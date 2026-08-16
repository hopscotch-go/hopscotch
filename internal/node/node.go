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
	"github.com/hopscotch-go/hopscotch/internal/kademlia"
	"github.com/hopscotch-go/hopscotch/internal/peers"
	"github.com/hopscotch-go/hopscotch/internal/proto"
	"github.com/hopscotch-go/hopscotch/internal/tun"
)

type Config struct {
	Listen    string   // convenience: one bind; default network is udp
	Listens   []string // "udp:host:port" and/or "tcp:host:port" (repeatable)
	Network   string   // default for unprefixed Listen/Listens: udp or tcp
	Peers     []peers.Peer
	PeersFile string
	Identity  string
	Cert      string // this node's CA-signed cert PEM
	CA        string // mesh CA cert PEM; trust any peer this CA signed
	Control   string // unix socket for local commands (ping)
	Tun       bool   // kernel TUN
	Gateway   bool   // this TUN owns fd00::/8 and overlay DNS for the host
	Log       *log.Logger
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
	table       *kademlia.Table
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
	dnsPC     net.PacketConn
	hosts     map[string]net.IP

	mu       sync.Mutex
	sessions map[identity.NodeID]*session
	dialing  map[string]bool
	echoWait map[string]echoWait
}

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
		table:       kademlia.NewTable(id),
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
		hosts:       make(map[string]net.IP),
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

func (n *Node) ID() identity.NodeID { return n.id }

func (n *Node) AdvertiseAddr() string {
	if len(n.advertise) == 0 {
		return ""
	}
	return n.advertise[0]
}

func (n *Node) AdvertiseAddrs() []string {
	return append([]string(nil), n.advertise...)
}

func (n *Node) AdvertiseByNetwork(network string) string {
	for _, a := range n.advertise {
		ep, err := endpoint.Parse(a, "")
		if err == nil && ep.Network == network {
			return a
		}
	}
	return n.AdvertiseAddr()
}

func (n *Node) Names() []string {
	return append([]string(nil), n.names...)
}

func (n *Node) NamesOf(id identity.NodeID) []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	if s := n.sessions[id]; s != nil {
		return append([]string(nil), s.names...)
	}
	return nil
}

func (n *Node) peerNamesFromConn(conn *quic.Conn) []string {
	certs := conn.ConnectionState().TLS.PeerCertificates
	if len(certs) == 0 {
		return nil
	}
	return identity.NamesFromCert(certs[0])
}

func peerLabel(id identity.NodeID, names []string) string {
	if len(names) == 0 {
		return id.Short()
	}
	return strings.Join(names, ",") + " (" + id.Short() + ")"
}

func (n *Node) label(id identity.NodeID) string {
	if id == n.id {
		return peerLabel(id, n.names)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if s := n.sessions[id]; s != nil {
		return peerLabel(id, s.names)
	}
	return id.Short()
}

func (n *Node) PeerCount() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.sessions)
}

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

	if len(n.peerAddrs()) > 0 {
		go n.join()
	}
	return nil
}

func (n *Node) attachInbound(ch <-chan backend.Session) {
	for s := range ch {
		n.mux.Attach(s)
	}
}

func (n *Node) Close() {
	n.cancel()
	n.mu.Lock()
	sessions := n.sessions
	n.sessions = make(map[identity.NodeID]*session)
	t := n.tun
	n.tun = nil
	n.mu.Unlock()
	for _, s := range sessions {
		if s.conn != nil {
			_ = s.conn.CloseWithError(0, "bye")
		}
	}
	if t != nil {
		_ = t.Close()
	}
	if n.dnsPC != nil {
		_ = n.dnsPC.Close()
	}
	if n.control != nil {
		_ = n.control.Close()
	}
	if n.controlPath != "" {
		_ = os.Remove(n.controlPath)
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

func (n *Node) join() {
	addrs := n.peerAddrs()
	backoff := time.Second
	var didLookup bool
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
			if !didLookup {
				n.lookup(n.id)
				didLookup = true
			}
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

	n.table.Insert(kademlia.Contact{ID: pid, Addrs: adv})
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
	return sess, nil
}

func (n *Node) readLoop(s *session) {
	defer func() {
		_ = s.conn.CloseWithError(0, "bye")
		n.mu.Lock()
		if cur := n.sessions[s.id]; cur == s {
			delete(n.sessions, s.id)
		}
		n.mu.Unlock()
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
		case "find_node":
			n.handleFindNode(s, msg)
		case "echo":
			n.handleEcho(s, msg)
		case "pong", "find_nodes", "echo_ok", "echo_err":
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

func (n *Node) handleFindNode(s *session, msg proto.Message) {
	target, err := identity.ParseHex(msg.Target)
	if err != nil {
		n.log.Printf("find_node from %s: bad target", peerLabel(s.id, s.names))
		return
	}
	contacts := n.replyContacts(target)
	n.log.Printf("FIND_NODE %s from %s → %d contacts", n.label(target), peerLabel(s.id, s.names), len(contacts))
	_ = n.write(s, proto.Message{Type: "find_nodes", RPC: msg.RPC, Contacts: contacts})
}

func (n *Node) replyContacts(target identity.NodeID) []proto.Contact {
	closest := n.table.Closest(target, kademlia.K)
	out := make([]proto.Contact, 0, len(closest)+1)
	out = append(out, proto.Contact{ID: n.id.Hex(), Addrs: n.advertise})
	for _, c := range closest {
		out = append(out, proto.Contact{ID: c.ID.Hex(), Addrs: c.Addrs})
	}
	return out
}

func (n *Node) lookup(target identity.NodeID) []kademlia.Contact {
	n.log.Printf("lookup %s", n.label(target))
	queried := make(map[identity.NodeID]bool)
	queried[n.id] = true

	shortlist := n.table.Closest(target, kademlia.K)
	changed := true
	for changed {
		changed = false
		batch := make([]kademlia.Contact, 0, kademlia.Alpha)
		for _, c := range shortlist {
			if queried[c.ID] {
				continue
			}
			batch = append(batch, c)
			if len(batch) == kademlia.Alpha {
				break
			}
		}
		if len(batch) == 0 {
			break
		}
		for _, c := range batch {
			queried[c.ID] = true
			got, err := n.queryFindNode(c, target)
			if err != nil {
				if errors.Is(err, errNoSession) {
					continue
				}
				n.log.Printf("FIND_NODE via %s: %v", n.label(c.ID), err)
				n.table.Remove(c.ID)
				continue
			}
			for _, next := range got {
				if next.ID == n.id || len(next.Addrs) == 0 || n.allSelfAddrs(next.Addrs) {
					continue
				}
				if _, ok := n.table.Get(next.ID); !ok {
					n.log.Printf("learned %s at %s (xor-closest path)", next.ID.Short(), strings.Join(next.Addrs, ","))
					changed = true
				}
				n.table.Insert(next)
			}
		}
		shortlist = n.table.Closest(target, kademlia.K)
	}

	return n.table.Closest(target, kademlia.K)
}

func (n *Node) queryFindNode(c kademlia.Contact, target identity.NodeID) ([]kademlia.Contact, error) {
	s := n.session(c.ID)
	if s == nil {
		return nil, errNoSession
	}
	rpc := n.rpcSeq.Add(1)
	ch := make(chan proto.Message, 1)
	s.pendMu.Lock()
	s.pending[rpc] = ch
	s.pendMu.Unlock()
	defer func() {
		s.pendMu.Lock()
		delete(s.pending, rpc)
		s.pendMu.Unlock()
	}()

	if err := n.write(s, proto.Message{Type: "find_node", RPC: rpc, Target: target.Hex()}); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(n.ctx, 5*time.Second)
	defer cancel()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case msg := <-ch:
		var out []kademlia.Contact
		for _, pc := range msg.Contacts {
			id, err := identity.ParseHex(pc.ID)
			if err != nil {
				continue
			}
			out = append(out, kademlia.Contact{ID: id, Addrs: canonicalAddrs(pc.Addrs)})
		}
		return out, nil
	}
}

func (n *Node) write(s *session, m proto.Message) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return proto.Write(s.stream, m)
}

func (n *Node) maintainLoop() {
	refresh := time.NewTicker(60 * time.Second)
	defer refresh.Stop()
	status := time.NewTicker(10 * time.Second)
	defer status.Stop()
	for {
		select {
		case <-n.ctx.Done():
			return
		case <-refresh.C:
			if n.table.Size() > 0 {
				n.lookup(n.id)
			}
		case <-status.C:
			n.logStatus()
		}
	}
}

func (n *Node) logStatus() {
	contacts := n.table.Contacts()
	n.mu.Lock()
	nsess := len(n.sessions)
	n.mu.Unlock()
	n.log.Printf("status table=%d connected=%d", len(contacts), nsess)
	for _, c := range contacts {
		n.mu.Lock()
		s := n.sessions[c.ID]
		n.mu.Unlock()
		state := "contact"
		label := c.ID.Short()
		if s != nil {
			state = "connected"
			label = peerLabel(c.ID, s.names)
		}
		n.log.Printf("  %s  %-11s  %s  bucket=%d",
			label, state, strings.Join(c.Addrs, ","), kademlia.BucketIndex(n.id, c.ID))
	}
}

func (n *Node) serverTLS() *tls.Config {
	return n.baseTLS("", false)
}

func (n *Node) clientTLS(serverName string) *tls.Config {
	if serverName == "" {
		serverName = "hopscotch"
	}
	return n.baseTLS(serverName, true)
}

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

func (n *Node) verifyPeer(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	_, err := identity.VerifyChain(rawCerts, n.caPool)
	return err
}

func poolWith(ca *x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca)
	return p
}

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

func (n *Node) allSelfAddrs(addrs []string) bool {
	if len(addrs) == 0 {
		return false
	}
	for _, a := range addrs {
		if !n.isSelfAddr(a) {
			return false
		}
	}
	return true
}
