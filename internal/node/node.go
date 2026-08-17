package node

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/hopscotch-go/hopscotch/internal/backend"
	"github.com/hopscotch-go/hopscotch/internal/endpoint"
	"github.com/hopscotch-go/hopscotch/internal/identity"
	"github.com/hopscotch-go/hopscotch/internal/netstack"
	"github.com/hopscotch-go/hopscotch/internal/peers"
	"github.com/hopscotch-go/hopscotch/internal/proto"
	"github.com/hopscotch-go/hopscotch/internal/tun"
)

type Config struct {
	Listen     string   // convenience: one bind; default network is udp
	Listens    []string // "udp:host:port" and/or "tcp:host:port" (repeatable)
	Network    string   // default for unprefixed Listen/Listens: udp or tcp
	Peers      []peers.Peer
	PeersFile  string
	Identity   string
	Cert       string // this node's CA-signed cert PEM
	CA         string // mesh CA cert PEM; trust any peer this CA signed
	Control    string // unix socket for local commands (ping, traceroute)
	Tun        bool   // kernel TUN
	Userspace  bool   // gVisor userspace IPv6 stack (no root); enables DialTCP
	Socks      string // local SOCKS5 listen addr (implies Userspace), e.g. 127.0.0.1:1080
	HTTPPort   int    // if >0, serve a tiny HTTP banner on this overlay TCP port (implies Userspace)
	Gateway    bool   // this TUN owns fd00::/8 and overlay DNS for the host
	NoListen   bool   // if true, do not bind (pure dial-only; cannot be dialed back)
	LogOverlay bool   // log every overlay nextHop forward
	Log        *log.Logger
}

type session struct {
	id      identity.NodeID
	names   []string
	addr    string
	conn    *quic.Conn
	stream  *quic.Stream
	uniQ    chan []byte // overlay packets that did not fit a datagram
	writeMu sync.Mutex
	pendMu  sync.Mutex
	pending map[uint64]chan proto.Message
}

type Node struct {
	cfg         Config
	log         *log.Logger
	priv        ed25519.PrivateKey
	pub         ed25519.PublicKey
	id          identity.NodeID
	tlsCert     tls.Certificate
	caPool      *x509.CertPool
	quicConf    *quic.Config
	peers       []peers.Peer
	pinByAddr   map[string]ed25519.PublicKey
	listenSpecs []endpoint.Endpoint
	advertise   []string
	names       []string
	controlPath string

	ctx    context.Context
	cancel context.CancelFunc
	rpcSeq atomic.Uint64

	tr        *quic.Transport
	ln        *quic.Listener
	control   net.Listener
	listeners []backend.Listener
	dialers   map[string]backend.Dialer
	mux       *backend.Mux
	tun       tun.Device
	stack     *netstack.Stack
	socksLn   net.Listener
	dnsPC     net.PacketConn

	mu       sync.Mutex
	sessions map[identity.NodeID]*session
	dialing  map[string]bool
	echoWait map[string]echoWait
	pktTap   chan []byte

	routeMu sync.Mutex
	routes  map[string]ribEntry // ULA string → next hop NodeID + metric
}

// New constructs a Node from cfg without starting listeners or dials.
func New(cfg Config) (*Node, error) {
	if cfg.Network == "" {
		cfg.Network = "udp"
	}
	if cfg.Network != "udp" && cfg.Network != "tcp" {
		return nil, fmt.Errorf("network %q: want udp or tcp", cfg.Network)
	}
	raw := append([]string(nil), cfg.Listens...)
	if len(raw) == 0 && cfg.Listen != "" {
		raw = []string{cfg.Listen}
	}
	var specs []endpoint.Endpoint
	for _, s := range raw {
		ep, err := endpoint.Parse(s, cfg.Network)
		if err != nil {
			return nil, fmt.Errorf("listen %q: %w", s, err)
		}
		specs = append(specs, ep)
	}
	// Every node binds an ephemeral UDP port unless NoListen is set, so
	// peers can dial back (bootstrapping and reconnection).
	if len(specs) == 0 && !cfg.NoListen {
		ep, err := endpoint.Parse("127.0.0.1:0", cfg.Network)
		if err != nil {
			return nil, fmt.Errorf("default listen: %w", err)
		}
		specs = append(specs, ep)
	}
	if cfg.Log == nil {
		cfg.Log = log.Default()
	}

	if cfg.Identity == "" || cfg.CA == "" || cfg.Cert == "" {
		return nil, errors.New("identity, ca, and cert are required")
	}

	priv, err := identity.LoadOrCreate(cfg.Identity)
	if err != nil {
		return nil, err
	}
	pub := priv.Public().(ed25519.PublicKey)
	id := identity.IDFromPublic(pub)

	caCert, err := identity.LoadCert(cfg.CA)
	if err != nil {
		return nil, err
	}
	if !caCert.IsCA {
		return nil, errors.New("ca file is not a CA certificate")
	}
	nodeCert, err := identity.LoadCert(cfg.Cert)
	if err != nil {
		return nil, err
	}
	cert, err := identity.TLSCertFromSigned(priv, nodeCert)
	if err != nil {
		return nil, err
	}
	if _, err := identity.VerifyChain([][]byte{nodeCert.Raw}, poolWith(caCert)); err != nil {
		return nil, fmt.Errorf("our cert is not signed by the given ca: %w", err)
	}
	caPool := poolWith(caCert)
	var ourNames []string
	if cert.Leaf != nil {
		ourNames = identity.NamesFromCert(cert.Leaf)
	}

	plist := append([]peers.Peer(nil), cfg.Peers...)
	if cfg.PeersFile != "" {
		extra, err := peers.Load(cfg.PeersFile)
		if err != nil {
			return nil, err
		}
		plist = append(plist, extra...)
	}
	for i, p := range plist {
		if p.Addr == "" {
			continue
		}
		ep, err := endpoint.Parse(p.Addr, "udp")
		if err != nil {
			return nil, fmt.Errorf("peer %q: %w", p.Addr, err)
		}
		plist[i].Addr = ep.String()
	}
	pin := make(map[string]ed25519.PublicKey)
	for _, p := range plist {
		if len(p.Pub) != 0 {
			pin[p.Addr] = p.Pub
		}
	}
	hasPeer := false
	for _, p := range plist {
		if p.Addr != "" {
			hasPeer = true
			break
		}
	}
	if len(specs) == 0 && !hasPeer {
		return nil, errors.New("listen or peers required")
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &Node{
		cfg:         cfg,
		log:         cfg.Log,
		priv:        priv,
		pub:         pub,
		id:          id,
		tlsCert:     cert,
		caPool:      caPool,
		peers:       plist,
		pinByAddr:   pin,
		listenSpecs: specs,
		names:       ourNames,
		controlPath: cfg.Control,
		ctx:         ctx,
		cancel:      cancel,
		sessions:    make(map[identity.NodeID]*session),
		dialing:     make(map[string]bool),
		echoWait:    make(map[string]echoWait),
		routes:      make(map[string]ribEntry),
		quicConf: &quic.Config{
			KeepAlivePeriod:       5 * time.Second,
			MaxIdleTimeout:        2 * time.Minute,
			EnableDatagrams:       true,
			MaxIncomingUniStreams: 4096,
			// Handshake stays at the QUIC minimum so small underlays work.
			// Overlay packets that do not fit a datagram go on a uni-stream
			// (reliable, no HOL vs other packets). PMTUD can grow datagrams.
			InitialPacketSize: 1200,
		},
	}, nil
}

// ID returns this node's mesh identity.
func (n *Node) ID() identity.NodeID { return n.id }

// AdvertiseAddr returns the primary underlay listen address advertised to peers.
func (n *Node) AdvertiseAddr() string {
	if len(n.advertise) == 0 {
		return ""
	}
	return n.advertise[0]
}

// AdvertiseAddrs returns all underlay addresses this node advertises.
func (n *Node) AdvertiseAddrs() []string {
	return append([]string(nil), n.advertise...)
}

// AdvertiseByNetwork returns an advertised underlay address for the given network, or the primary if none match.
func (n *Node) AdvertiseByNetwork(network string) string {
	for _, a := range n.advertise {
		ep, err := endpoint.Parse(a, "")
		if err == nil && ep.Network == network {
			return a
		}
	}
	return n.AdvertiseAddr()
}

// Names returns this node's overlay names from its CA cert.
func (n *Node) Names() []string {
	return append([]string(nil), n.names...)
}

// NamesOf returns overlay names learned for a peer session, if any.
func (n *Node) NamesOf(id identity.NodeID) []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	if s := n.sessions[id]; s != nil {
		return append([]string(nil), s.names...)
	}
	return nil
}

// peerNamesFromConn extracts overlay peer names from the peer TLS certificate.
func (n *Node) peerNamesFromConn(conn *quic.Conn) []string {
	certs := conn.ConnectionState().TLS.PeerCertificates
	if len(certs) == 0 {
		return nil
	}
	return identity.NamesFromCert(certs[0])
}

// peerLabel formats a peer as name(s) plus short id for logs.
func peerLabel(id identity.NodeID, names []string) string {
	if len(names) == 0 {
		return id.Short()
	}
	return strings.Join(names, ",") + " (" + id.Short() + ")"
}

// PeerCount returns the number of live peer sessions.
func (n *Node) PeerCount() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.sessions)
}

// Start binds underlay listeners, starts QUIC, and begins peer maintenance.
func (n *Node) Start() error {
	mux := backend.NewMux(backend.HopAddr{Net: "mux"})
	n.mux = mux
	n.dialers = make(map[string]backend.Dialer)
	n.tr = &quic.Transport{Conn: mux}

	for _, spec := range n.listenSpecs {
		ln, err := backend.NewListener(spec.Network, spec.Addr)
		if err != nil {
			n.Close()
			return err
		}
		ch, err := ln.Start(n.ctx)
		if err != nil {
			_ = ln.Close()
			n.Close()
			return err
		}
		n.listeners = append(n.listeners, ln)
		n.advertise = append(n.advertise, advertiseOf(spec, ln.Addr()))
		go n.attachInbound(ch)
	}
	for _, netw := range []string{"udp", "tcp"} {
		d, err := backend.NewDialer(netw)
		if err != nil {
			n.Close()
			return err
		}
		n.dialers[netw] = d
	}

	if len(n.listenSpecs) > 0 {
		qln, err := n.tr.Listen(n.serverTLS(), n.quicConf)
		if err != nil {
			n.Close()
			return err
		}
		n.ln = qln
	}

	n.log.Printf("pubkey    %s", identity.PublicHex(n.pub))
	n.log.Printf("identity  %s  (SHA-256 of pubkey)", n.id.Hex())
	n.log.Printf("short-id  %s", n.id.Short())
	if len(n.names) > 0 {
		n.log.Printf("names     %s  (from CA cert)", strings.Join(n.names, ", "))
	}
	n.log.Printf("ula       %s", n.id.ULA())
	if len(n.advertise) == 0 {
		n.log.Printf("listen    (dial-only)")
	}
	for _, a := range n.advertise {
		n.log.Printf("listen    %s", a)
	}
	if len(n.advertise) > 0 {
		n.log.Printf("advertise %s", strings.Join(n.advertise, " "))
	}
	n.log.Printf("peers     %d", len(n.peerAddrs()))
	n.log.Printf("auth      ca (any cert signed by the mesh CA)")
	if n.controlPath != "" {
		if err := n.listenControl(); err != nil {
			n.Close()
			return err
		}
		n.log.Printf("control   %s", n.controlPath)
	}

	go n.maintainLoop()
	if n.ln != nil {
		go n.acceptLoop()
	}

	if n.cfg.Tun {
		if err := n.startTun(); err != nil {
			n.Close()
			return err
		}
	}
	if n.cfg.Userspace || n.cfg.Socks != "" || n.cfg.HTTPPort > 0 {
		if err := n.startUserspace(); err != nil {
			n.Close()
			return err
		}
	}
	if n.cfg.Socks != "" {
		if err := n.startSocks(); err != nil {
			n.Close()
			return err
		}
	}
	if n.cfg.HTTPPort > 0 {
		if err := n.startHTTP(); err != nil {
			n.Close()
			return err
		}
	}

	if len(n.peerAddrs()) > 0 {
		go n.join()
	}
	return nil
}

// attachInbound feeds inbound underlay sessions into the QUIC mux.
func (n *Node) attachInbound(ch <-chan backend.Session) {
	for s := range ch {
		n.mux.Attach(s)
	}
}

// Close shuts down sessions, TUN, control socket, and listeners.
func (n *Node) Close() {
	n.cancel()
	n.mu.Lock()
	sessions := n.sessions
	n.sessions = make(map[identity.NodeID]*session)
	t := n.tun
	n.tun = nil
	st := n.stack
	n.stack = nil
	socksLn := n.socksLn
	n.socksLn = nil
	n.mu.Unlock()
	for _, s := range sessions {
		if s.conn != nil {
			_ = s.conn.CloseWithError(0, "bye")
		}
	}
	if socksLn != nil {
		_ = socksLn.Close()
	}
	if st != nil {
		st.Close()
	}
	if t != nil {
		_ = t.Close()
	}
	if n.dnsPC != nil {
		_ = n.dnsPC.Close()
	}
	if n.control != nil {
		_ = n.control.Close()
		n.control = nil
		if n.controlPath != "" {
			_ = os.Remove(n.controlPath)
		}
	}
	if n.ln != nil {
		_ = n.ln.Close()
	}
	if n.tr != nil {
		_ = n.tr.Close()
	}
	if n.mux != nil {
		_ = n.mux.Close()
	}
	for _, ln := range n.listeners {
		_ = ln.Close()
	}
}

// acceptLoop accepts inbound QUIC connections on the underlay listener.
func (n *Node) acceptLoop() {
	for {
		conn, err := n.ln.Accept(n.ctx)
		if err != nil {
			if n.ctx.Err() != nil {
				return
			}
			n.log.Printf("accept: %v", err)
			continue
		}
		go func(c *quic.Conn) {
			if _, err := n.establish(c, false, nil, ""); err != nil {
				n.log.Printf("inbound: %v", err)
				_ = c.CloseWithError(1, err.Error())
			}
		}(conn)
	}
}

// join dials configured peers with backoff until the node context ends.
func (n *Node) join() {
	addrs := n.peerAddrs()
	backoff := time.Second
	for n.ctx.Err() == nil {
		failed := 0
		for _, addr := range addrs {
			if n.sessionByAddr(addr) != nil {
				continue
			}
			if _, err := n.dial(addr); err != nil {
				n.log.Printf("peer %s: %v", addr, err)
				failed++
			}
		}
		if failed == 0 {
			backoff = time.Second
			if !n.sleep(time.Second) {
				return
			}
			continue
		}
		n.log.Printf("peers retry in %s", backoff)
		if !n.sleep(backoff) {
			return
		}
		if backoff < 15*time.Second {
			backoff *= 2
		}
	}
}

// sleep waits for d or returns false if the node context is canceled.
func (n *Node) sleep(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-n.ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// sessionByAddr returns the live session for an underlay advertise address.
func (n *Node) sessionByAddr(addr string) *session {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, s := range n.sessions {
		if s.addr == addr && s.conn != nil && s.conn.Context().Err() == nil {
			return s
		}
	}
	return nil
}

// peerAddrs lists configured peer underlay addresses excluding self.
func (n *Node) peerAddrs() []string {
	var out []string
	for _, p := range n.peers {
		if p.Addr == "" || n.isSelfAddr(p.Addr) {
			continue
		}
		out = append(out, p.Addr)
	}
	return out
}

// isSelfAddr reports whether s matches one of this node's advertised underlay addresses.
func (n *Node) isSelfAddr(s string) bool {
	ep, err := endpoint.Parse(s, "udp")
	if err != nil {
		return false
	}
	want := ep.String()
	for _, a := range n.advertise {
		if a == want {
			return true
		}
	}
	return false
}

// dial opens an underlay session and completes the QUIC hello handshake.
func (n *Node) dial(addr string) (*session, error) {
	if addr == "" || n.isSelfAddr(addr) {
		return nil, errors.New("refusing to dial self")
	}
	ep, err := endpoint.Parse(addr, "udp")
	if err != nil {
		return nil, err
	}
	addr = ep.String()
	n.mu.Lock()
	if n.dialing[addr] {
		n.mu.Unlock()
		return n.waitSessionByAddr(addr)
	}
	n.dialing[addr] = true
	n.mu.Unlock()
	defer func() {
		n.mu.Lock()
		delete(n.dialing, addr)
		n.mu.Unlock()
	}()

	dialer := n.dialers[ep.Network]
	if dialer == nil {
		return nil, fmt.Errorf("no dialer for %s", ep.Network)
	}
	ctx, cancel := context.WithTimeout(n.ctx, 8*time.Second)
	defer cancel()
	sess, err := dialer.Dial(ctx, ep.Addr)
	if err != nil {
		return nil, err
	}
	n.mux.Attach(sess)
	conn, err := n.tr.Dial(ctx, sess.RemoteAddr(), n.clientTLS(endpoint.Host(ep.Addr)), n.quicConf)
	if err != nil {
		_ = sess.Close()
		return nil, err
	}
	n.mu.Lock()
	expect := n.pinByAddr[addr]
	n.mu.Unlock()
	return n.establish(conn, true, expect, addr)
}

// waitSessionByAddr waits briefly for another dial to finish establishing addr.
func (n *Node) waitSessionByAddr(addr string) (*session, error) {
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		n.mu.Lock()
		for _, s := range n.sessions {
			if s.addr == addr {
				n.mu.Unlock()
				return s, nil
			}
		}
		n.mu.Unlock()
		select {
		case <-n.ctx.Done():
			return nil, n.ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	return nil, fmt.Errorf("timeout waiting for %s", addr)
}

// establish completes the control-stream hello and registers a peer session.
func (n *Node) establish(conn *quic.Conn, weDialed bool, expect ed25519.PublicKey, dialed string) (*session, error) {
	var stream *quic.Stream
	var err error
	if weDialed {
		stream, err = conn.OpenStreamSync(n.ctx)
	} else {
		stream, err = conn.AcceptStream(n.ctx)
	}
	if err != nil {
		return nil, err
	}

	pub, err := identity.PublicFromCerts(conn.ConnectionState().TLS.PeerCertificates)
	if err != nil {
		return nil, err
	}
	pid := identity.IDFromPublic(pub)
	if pid == n.id {
		_ = conn.CloseWithError(0, "self")
		return nil, errors.New("connected to self")
	}
	if len(expect) != 0 && !bytes.Equal(pub, expect) {
		_ = conn.CloseWithError(1, "key mismatch")
		return nil, fmt.Errorf("peer at %s: public key does not match peers file", conn.RemoteAddr())
	}

	if err := proto.Write(stream, proto.Message{
		Type:  "hello",
		Hello: &proto.Hello{Listen: n.advertise},
	}); err != nil {
		return nil, err
	}
	msg, err := proto.Read(stream)
	if err != nil {
		return nil, err
	}
	if msg.Type != "hello" || msg.Hello == nil {
		return nil, fmt.Errorf("expected hello, got %q", msg.Type)
	}
	adv := canonicalAddrs(msg.Hello.Listen)
	sessAddr := dialed
	if sessAddr == "" && len(adv) > 0 {
		sessAddr = adv[0]
	}
	if sessAddr == "" {
		sessAddr = conn.RemoteAddr().String()
	}

	peerNames := n.peerNamesFromConn(conn)
	sess := &session{
		id:      pid,
		names:   peerNames,
		addr:    sessAddr,
		conn:    conn,
		stream:  stream,
		uniQ:    make(chan []byte, 64),
		pending: make(map[uint64]chan proto.Message),
	}

	// Prefer the newest connection for a NodeID. A peer restart (or NAT remap)
	// often leaves the old QUIC conn looking alive until idle timeout; rejecting
	// as "duplicate" stranded redials for tens of seconds.
	var old *session
	n.mu.Lock()
	if existing := n.sessions[pid]; existing != nil {
		old = existing
		delete(n.sessions, pid)
	}
	n.sessions[pid] = sess
	n.mu.Unlock()
	if old != nil {
		if old.conn != nil {
			_ = old.conn.CloseWithError(0, "replaced")
		}
		n.log.Printf("replacing session %s", peerLabel(pid, peerNames))
	}

	role := "inbound"
	if weDialed {
		role = "dialed"
	}
	n.log.Printf("connected %s via %s advertise=%s underlay=%s",
		peerLabel(pid, peerNames), role, strings.Join(adv, ","), conn.RemoteAddr())

	go n.readLoop(sess)
	go n.readDatagramLoop(sess)
	go n.readUniStreamLoop(sess)
	go n.overlayStreamLoop(sess)
	n.onSessionUp(sess)
	return sess, nil
}

// readLoop reads control-plane messages on the session's bidirectional stream.
func (n *Node) readLoop(s *session) {
	defer func() {
		_ = s.conn.CloseWithError(0, "bye")
		n.mu.Lock()
		if cur := n.sessions[s.id]; cur == s {
			delete(n.sessions, s.id)
		}
		n.mu.Unlock()
		n.onSessionDown(s)
		n.log.Printf("disconnected %s", peerLabel(s.id, s.names))
	}()

	for {
		msg, err := proto.Read(s.stream)
		if err != nil {
			return
		}
		switch msg.Type {
		case "ping":
			_ = n.write(s, proto.Message{Type: "pong", RPC: msg.RPC})
		case "echo":
			n.handleEcho(s, msg)
		case "routes":
			n.handleRoutes(s, msg)
		case "pong", "echo_ok", "echo_err":
			if msg.Type == "echo_ok" || msg.Type == "echo_err" {
				n.completeEcho(msg)
				break
			}
			s.pendMu.Lock()
			ch := s.pending[msg.RPC]
			s.pendMu.Unlock()
			if ch != nil {
				select {
				case ch <- msg:
				default:
				}
			}
		default:
			n.log.Printf("from %s: unknown type %q", peerLabel(s.id, s.names), msg.Type)
		}
	}
}

// write sends a control-plane message on the session stream.
func (n *Node) write(s *session, m proto.Message) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return proto.Write(s.stream, m)
}

// maintainLoop periodically refreshes RIB advertisements and status logs.
func (n *Node) maintainLoop() {
	routes := time.NewTicker(routeRefresh)
	defer routes.Stop()
	status := time.NewTicker(10 * time.Second)
	defer status.Stop()
	for {
		select {
		case <-n.ctx.Done():
			return
		case <-routes.C:
			n.advertiseRoutes()
		case <-status.C:
			n.logStatus()
		}
	}
}

// logStatus logs connected sessions and current RIB routes.
func (n *Node) logStatus() {
	n.mu.Lock()
	nsess := len(n.sessions)
	sessions := make([]*session, 0, nsess)
	for _, s := range n.sessions {
		sessions = append(sessions, s)
	}
	n.mu.Unlock()
	n.routeMu.Lock()
	nroutes := len(n.routes)
	n.routeMu.Unlock()
	n.log.Printf("status connected=%d routes=%d", nsess, nroutes)
	for _, r := range n.Routes() {
		n.log.Printf("  route  %-8s via %-8s metric=%d", r.Dest, r.Next, r.Metric)
	}
	for _, s := range sessions {
		n.log.Printf("  %s  connected  %s", peerLabel(s.id, s.names), s.addr)
	}
}

// serverTLS returns TLS config for inbound QUIC.
func (n *Node) serverTLS() *tls.Config {
	return n.baseTLS("", false)
}

// clientTLS returns TLS config for outbound QUIC dials.
func (n *Node) clientTLS(serverName string) *tls.Config {
	if serverName == "" {
		serverName = "hopscotch"
	}
	return n.baseTLS(serverName, true)
}

// baseTLS builds shared TLS settings with mesh-CA peer verification.
func (n *Node) baseTLS(serverName string, client bool) *tls.Config {
	cfg := &tls.Config{
		Certificates:          []tls.Certificate{n.tlsCert},
		NextProtos:            []string{identity.ALPN},
		MinVersion:            tls.VersionTLS13,
		InsecureSkipVerify:    true, // no hostnames; mesh CA is checked in verifyPeer
		VerifyPeerCertificate: n.verifyPeer,
	}
	if client {
		cfg.ServerName = serverName
	} else {
		cfg.ClientAuth = tls.RequireAnyClientCert
	}
	return cfg
}

// verifyPeer checks the peer certificate chain against the mesh CA.
func (n *Node) verifyPeer(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	_, err := identity.VerifyChain(rawCerts, n.caPool)
	return err
}

// poolWith builds a CertPool containing only ca.
func poolWith(ca *x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca)
	return p
}

// advertiseOf builds the underlay address peers should dial, resolving ephemeral ports.
func advertiseOf(spec endpoint.Endpoint, bound net.Addr) string {
	host, port, err := net.SplitHostPort(spec.Addr)
	if err != nil {
		return spec.String()
	}
	if port == "0" {
		_, boundPort, berr := net.SplitHostPort(bound.String())
		if berr == nil {
			port = boundPort
		}
	}
	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" {
		host = "127.0.0.1"
	}
	return endpoint.Endpoint{Network: spec.Network, Addr: net.JoinHostPort(host, port)}.String()
}

// canonicalAddrs parses and deduplicates advertised underlay addresses.
func canonicalAddrs(in []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range in {
		ep, err := endpoint.Parse(s, "udp")
		if err != nil {
			continue
		}
		c := ep.String()
		if seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
	}
	return out
}
