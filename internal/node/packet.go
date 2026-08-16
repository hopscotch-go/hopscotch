package node

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/quic-go/quic-go"

	"github.com/hopscotch-go/hopscotch/internal/dns"
	"github.com/hopscotch-go/hopscotch/internal/identity"
	"github.com/hopscotch-go/hopscotch/internal/tun"
)

const (
	ipv6HeaderLen      = 40
	nextHeaderTCP      = 6
	nextHeaderUDP      = 17
	nextHeaderICMPv6   = 58
	icmpv6DestUnreach  = 1
	icmpv6PacketTooBig = 2
	icmpv6TimeExceeded = 3
	icmpv6EchoRequest  = 128
	icmpv6EchoReply    = 129
	icmpCodeNoRoute    = 0 // Destination Unreachable: no route to destination
	tcpFlagSYN         = 0x02
	tcpOptMSS          = 2
	tcpHeaderMin       = 20
	dnsPort            = 53
	tcpMSS             = tun.MTU - ipv6HeaderLen - tcpHeaderMin // 1220
)

// loadHostsFile loads local name→ULA mappings from the identity-adjacent hosts file.
func (n *Node) loadHostsFile() {
	if n.cfg.Identity == "" {
		return
	}
	hostsPath := filepath.Join(filepath.Dir(n.cfg.Identity), "hosts")
	hs, err := tun.ParseHostsFile(hostsPath)
	if err != nil {
		return
	}
	n.mu.Lock()
	for _, h := range hs {
		n.hosts[h.Name] = h.IP
	}
	n.mu.Unlock()
}

// startTun opens a gateway TUN and optional local DNS for host overlay traffic.
func (n *Node) startTun() error {
	if !n.cfg.Gateway {
		// Extra hopscotch on this host must not ifconfig its ULA: ping6
		// would then be a local loop (src == dst) and never enter the overlay.
		n.log.Printf("gateway=false: %s is not a host address; ICMP echo answered here", n.id.ULA())
		return nil
	}
	n.loadHostsFile()
	var dnsPort int
	if runtime.GOOS == "darwin" {
		port, err := n.listenLocalDNS()
		if err != nil {
			return fmt.Errorf("tun: %w", err)
		}
		dnsPort = port
	}
	d, err := tun.Setup(tun.Opts{
		IP:      n.id.ULA(),
		Gateway: true,
		DNSPort: dnsPort,
	})
	if err != nil {
		if n.dnsPC != nil {
			_ = n.dnsPC.Close()
			n.dnsPC = nil
		}
		return fmt.Errorf("tun: %w", err)
	}
	n.attachTunLocked(d)
	n.log.Printf("tun       %s  %s/128  host overlay (fd00::/8, DNS %s search %s)",
		d.Name(), n.id.ULA(), identity.ResolverULA(), identity.NameURIScheme)
	if n.dnsPC != nil {
		n.log.Printf("dns       %s  (/etc/resolver)", n.dnsPC.LocalAddr())
	}
	return nil
}

// AttachTun uses an already-open device (tests). Kernel configure is skipped.
func (n *Node) AttachTun(d tun.Device) {
	n.attachTunLocked(d)
}

// attachTunLocked installs d as the TUN device and starts the read loop.
func (n *Node) attachTunLocked(d tun.Device) {
	n.mu.Lock()
	if n.tun != nil {
		_ = n.tun.Close()
	}
	n.tun = d
	n.mu.Unlock()
	go n.tunLoop()
}

// tunLoop reads packets from the kernel TUN into the overlay forward path.
func (n *Node) tunLoop() {
	for {
		n.mu.Lock()
		d := n.tun
		n.mu.Unlock()
		if d == nil {
			return
		}
		pkt, err := d.ReadPacket()
		if err != nil {
			return
		}
		n.handlePacket(nil, pkt)
	}
}

// deliverTun taps then writes an IPv6 packet to the local TUN and userspace stack.
func (n *Node) deliverTun(pkt []byte) {
	n.tapPacket(pkt)
	n.deliverStack(pkt)
	n.mu.Lock()
	d := n.tun
	n.mu.Unlock()
	if d == nil {
		return
	}
	_ = d.WritePacket(pkt)
}

// handlePacket accepts an overlay IPv6 packet from TUN or a peer session.
func (n *Node) handlePacket(from *session, pkt []byte) {
	if len(pkt) == 0 || pkt[0]>>4 != 6 {
		return
	}
	n.handleIPv6(from, pkt)
}

// handleIPv6 routes overlay IPv6: local delivery, DNS, or RIB next-hop forward.
func (n *Node) handleIPv6(from *session, pkt []byte) {
	dst, hop, ok := parseIPv6(pkt)
	if !ok || !identity.IsMeshULA(dst) {
		return
	}
	if identity.IsResolverULA(dst) {
		if from != nil {
			return
		}
		if reply := n.dnsReply(pkt); len(reply) > 0 {
			n.deliverTun(reply)
		}
		return
	}
	if dst.Equal(n.id.ULA()) {
		if from == nil {
			return
		}
		n.tapPacket(pkt)
		n.mu.Lock()
		d := n.tun
		st := n.stack
		n.mu.Unlock()
		if st != nil {
			st.Inject(pkt)
		}
		if d != nil {
			_ = d.WritePacket(pkt)
			return
		}
		if st != nil {
			return
		}
		if reply, ok := icmpEchoReply(pkt); ok {
			_ = from.writePacket(reply)
		}
		return
	}
	hopAfter := hop
	if from != nil {
		if hop <= 1 {
			n.sendICMPError(from, pkt, icmpv6TimeExceeded, 0, 0)
			return
		}
		pkt[7]--
		hopAfter = hop - 1
	}
	pkt = clampTCPMSS(pkt, tcpMSS)
	next := n.nextHop(dst, from)
	if next == nil {
		n.sendICMPError(from, pkt, icmpv6DestUnreach, icmpCodeNoRoute, 0)
		if n.cfg.LogOverlay {
			n.log.Printf("overlay no route dst=%s", dst)
		}
		return
	}
	if n.cfg.LogOverlay {
		fromLabel := "tun"
		if from != nil {
			fromLabel = peerLabel(from.id, from.names)
		}
		n.log.Printf("overlay fwd dst=%s from=%s to=%s hlim=%d",
			dst, fromLabel, peerLabel(next.id, next.names), hopAfter)
	}
	if err := next.writePacket(pkt); err != nil {
		n.sendPacketTooBig(from, pkt, err)
		var tooBig *quic.DatagramTooLargeError
		if !errors.As(err, &tooBig) {
			n.log.Printf("overlay send %s: %v", dst, err)
		}
	}
}

// listenLocalDNS binds a localhost UDP DNS socket for macOS /etc/resolver.
func (n *Node) listenLocalDNS() (int, error) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("dns: %w", err)
	}
	addr, ok := pc.LocalAddr().(*net.UDPAddr)
	if !ok || addr.Port == 0 {
		_ = pc.Close()
		return 0, fmt.Errorf("dns: no local port")
	}
	n.dnsPC = pc
	go n.localDNSLoop(pc)
	return addr.Port, nil
}

// localDNSLoop answers local DNS queries via overlay name lookup.
func (n *Node) localDNSLoop(pc net.PacketConn) {
	buf := make([]byte, 2048)
	for {
		nr, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		body := dns.Reply(buf[:nr], n.overlayLookup)
		if len(body) == 0 {
			continue
		}
		_, _ = pc.WriteTo(body, addr)
	}
}

// overlayLookup resolves an overlay DNS name to an AAAA record.
func (n *Node) overlayLookup(name string) dns.Record {
	return dns.Record{AAAA: n.overlayIP(name)}
}

// overlayIP maps an overlay name to a mesh ULA from self, sessions, or hosts.
func (n *Node) overlayIP(name string) net.IP {
	name = strings.ToLower(name)
	if name == "dns" {
		return identity.ResolverULA()
	}
	for _, nm := range n.names {
		if nm == name {
			return n.id.ULA()
		}
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, s := range n.sessions {
		for _, nm := range s.names {
			if nm == name {
				return s.id.ULA()
			}
		}
	}
	if ip, ok := n.hosts[name]; ok {
		return append(net.IP(nil), ip...)
	}
	return nil
}

// dnsReply builds an overlay DNS response packet for resolver-ULA queries.
func (n *Node) dnsReply(pkt []byte) []byte {
	src, dst, sport, dport, payload, ok := parseUDP6(pkt)
	if !ok || dport != dnsPort {
		return nil
	}
	body := dns.Reply(payload, n.overlayLookup)
	if len(body) == 0 {
		return nil
	}
	return udp6(dst, src, dport, sport, body)
}

// nextHop picks an overlay forward target from the distance-vector RIB
// (hop count over live sessions). Falls back to an exact ULA session match
// if the table has not converged yet. Never forwards back to ingress.
func (n *Node) nextHop(dst net.IP, from *session) *session {
	if s := n.routeNextHop(dst); s != nil && s != from {
		return s
	}
	for _, s := range n.sessionList() {
		if s == from {
			continue
		}
		if s.id.ULA().Equal(dst) {
			return s
		}
	}
	return nil
}

// writePacket sends an overlay IPv6 packet as a QUIC datagram, falling back to uni-stream.
func (s *session) writePacket(pkt []byte) error {
	if s.conn == nil {
		return fmt.Errorf("no connection")
	}
	if len(pkt) == 0 {
		return fmt.Errorf("overlay packet length 0")
	}
	if len(pkt) > tun.MTU {
		return &quic.DatagramTooLargeError{MaxDatagramPayloadSize: int64(tun.MTU)}
	}
	err := s.conn.SendDatagram(pkt)
	if err == nil {
		return nil
	}
	if !datagramFallback(err) {
		return err
	}
	if s.uniQ == nil {
		return err
	}
	buf := append([]byte(nil), pkt...)
	select {
	case s.uniQ <- buf:
		return nil
	default:
		return err
	}
}

// datagramFallback reports whether err should fall back from datagram to stream.
func datagramFallback(err error) bool {
	var tooBig *quic.DatagramTooLargeError
	if errors.As(err, &tooBig) {
		return true
	}
	return err != nil && strings.Contains(err.Error(), "datagram support disabled")
}

// overlayStreamLoop drains uniQ and sends oversized overlay packets on uni-streams.
func (n *Node) overlayStreamLoop(s *session) {
	for {
		select {
		case <-n.ctx.Done():
			return
		case <-s.conn.Context().Done():
			return
		case pkt := <-s.uniQ:
			if err := s.writePacketStream(pkt); err != nil {
				n.log.Printf("overlay stream %s: %v", peerLabel(s.id, s.names), err)
			}
		}
	}
}

// writePacketStream sends one overlay packet on a new unidirectional QUIC stream.
func (s *session) writePacketStream(pkt []byte) error {
	st, err := s.conn.OpenUniStreamSync(s.conn.Context())
	if err != nil {
		return err
	}
	defer st.Close()
	_, err = st.Write(pkt)
	return err
}

// readUniStreamLoop accepts unidirectional streams carrying overlay packets.
func (n *Node) readUniStreamLoop(s *session) {
	for {
		st, err := s.conn.AcceptUniStream(n.ctx)
		if err != nil {
			return
		}
		go n.readUniPacket(s, st)
	}
}

// readUniPacket reads one overlay packet from a uni-stream and handles it.
func (n *Node) readUniPacket(s *session, st *quic.ReceiveStream) {
	pkt, err := io.ReadAll(io.LimitReader(st, int64(tun.MTU)+1))
	if err != nil || len(pkt) < ipv6HeaderLen || len(pkt) > tun.MTU {
		return
	}
	n.handlePacket(s, pkt)
}

// sendPacketTooBig emits ICMPv6 Packet Too Big when a datagram exceeds underlay limits.
func (n *Node) sendPacketTooBig(from *session, pkt []byte, err error) {
	var tooBig *quic.DatagramTooLargeError
	if !errors.As(err, &tooBig) {
		return
	}
	mtu := tun.MTU
	if tooBig.MaxDatagramPayloadSize > 0 && int(tooBig.MaxDatagramPayloadSize) < mtu {
		mtu = int(tooBig.MaxDatagramPayloadSize)
	}
	n.sendICMPError(from, pkt, icmpv6PacketTooBig, 0, uint32(mtu))
}

// sendICMPError sends an ICMPv6 error toward from or the local TUN.
func (n *Node) sendICMPError(from *session, pkt []byte, typ, code uint8, param uint32) {
	reply := icmpv6Error(pkt, n.id.ULA(), typ, code, param)
	if reply == nil {
		return
	}
	if from == nil {
		n.deliverTun(reply)
		return
	}
	_ = from.writePacket(reply)
}

// icmpv6Error builds an ICMPv6 error packet quoting as much of pkt as fits.
func icmpv6Error(pkt []byte, src net.IP, typ, code uint8, param uint32) []byte {
	src = src.To16()
	if src == nil || len(pkt) < ipv6HeaderLen || pkt[0]>>4 != 6 {
		return nil
	}
	if pkt[6] == nextHeaderICMPv6 && len(pkt) > ipv6HeaderLen && pkt[ipv6HeaderLen] < 128 {
		return nil
	}
	origSrc := net.IP(pkt[8:24])
	if origSrc.IsUnspecified() || origSrc.IsMulticast() {
		return nil
	}
	maxAsMuch := tun.MTU - ipv6HeaderLen - 8
	if maxAsMuch < ipv6HeaderLen {
		return nil
	}
	asMuch := len(pkt)
	if asMuch > maxAsMuch {
		asMuch = maxAsMuch
	}
	out := make([]byte, ipv6HeaderLen+8+asMuch)
	out[0] = 0x60
	plen := 8 + asMuch
	out[4] = byte(plen >> 8)
	out[5] = byte(plen)
	out[6] = nextHeaderICMPv6
	out[7] = 64
	copy(out[8:24], src)
	copy(out[24:40], origSrc)
	out[40] = typ
	out[41] = code
	binary.BigEndian.PutUint32(out[44:48], param)
	copy(out[48:], pkt[:asMuch])
	sum := icmpv6Checksum(out)
	out[42] = byte(sum >> 8)
	out[43] = byte(sum)
	return out
}

// clampTCPMSS caps TCP MSS options on SYN so segments fit overlay MTU.
func clampTCPMSS(pkt []byte, mss uint16) []byte {
	if len(pkt) < ipv6HeaderLen+tcpHeaderMin || pkt[6] != nextHeaderTCP {
		return pkt
	}
	doff := int(pkt[ipv6HeaderLen+12]>>4) * 4
	if doff < tcpHeaderMin || ipv6HeaderLen+doff > len(pkt) {
		return pkt
	}
	if pkt[ipv6HeaderLen+13]&tcpFlagSYN == 0 {
		return pkt
	}
	changed := false
	i := ipv6HeaderLen + tcpHeaderMin
	end := ipv6HeaderLen + doff
	for i < end {
		kind := pkt[i]
		if kind == 0 {
			break
		}
		if kind == 1 {
			i++
			continue
		}
		if i+1 >= end {
			break
		}
		l := int(pkt[i+1])
		if l < 2 || i+l > end {
			break
		}
		if kind == tcpOptMSS && l == 4 {
			old := binary.BigEndian.Uint16(pkt[i+2 : i+4])
			if old > mss {
				if !changed {
					pkt = append([]byte(nil), pkt...)
					changed = true
				}
				binary.BigEndian.PutUint16(pkt[i+2:i+4], mss)
			}
		}
		i += l
	}
	if changed {
		pkt[ipv6HeaderLen+16], pkt[ipv6HeaderLen+17] = 0, 0
		sum := tcp6Checksum(pkt)
		pkt[ipv6HeaderLen+16] = byte(sum >> 8)
		pkt[ipv6HeaderLen+17] = byte(sum)
	}
	return pkt
}

// tcp6Checksum computes the IPv6 TCP checksum for pkt.
func tcp6Checksum(pkt []byte) uint16 {
	return transportChecksum(pkt, nextHeaderTCP)
}

// transportChecksum computes an IPv6 pseudo-header transport checksum.
func transportChecksum(pkt []byte, proto uint8) uint16 {
	var sum uint32
	plen := uint32(len(pkt) - ipv6HeaderLen)
	for i := 8; i < ipv6HeaderLen; i += 2 {
		sum += uint32(pkt[i])<<8 | uint32(pkt[i+1])
	}
	sum += plen >> 16
	sum += plen & 0xffff
	sum += uint32(proto)
	for i := ipv6HeaderLen; i+1 < len(pkt); i += 2 {
		sum += uint32(pkt[i])<<8 | uint32(pkt[i+1])
	}
	if (len(pkt)-ipv6HeaderLen)%2 == 1 {
		sum += uint32(pkt[len(pkt)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	c := ^uint16(sum)
	if proto == nextHeaderUDP && c == 0 {
		return 0xffff
	}
	return c
}

// readDatagramLoop receives overlay packets from QUIC datagrams.
func (n *Node) readDatagramLoop(s *session) {
	for {
		pkt, err := s.conn.ReceiveDatagram(n.ctx)
		if err != nil {
			return
		}
		n.handlePacket(s, pkt)
	}
}

// parseIPv6 extracts destination and hop limit from an IPv6 header.
func parseIPv6(pkt []byte) (dst net.IP, hopLimit int, ok bool) {
	if len(pkt) < ipv6HeaderLen || pkt[0]>>4 != 6 {
		return nil, 0, false
	}
	return net.IP(pkt[24:40]), int(pkt[7]), true
}

// parseUDP6 parses an IPv6 UDP packet into endpoints and payload.
func parseUDP6(pkt []byte) (src, dst net.IP, sport, dport uint16, payload []byte, ok bool) {
	if len(pkt) < ipv6HeaderLen+8 || pkt[0]>>4 != 6 || pkt[6] != nextHeaderUDP {
		return
	}
	udpLen := int(pkt[44])<<8 | int(pkt[45])
	if udpLen < 8 || ipv6HeaderLen+udpLen > len(pkt) {
		return
	}
	src = net.IP(pkt[8:24])
	dst = net.IP(pkt[24:40])
	sport = uint16(pkt[40])<<8 | uint16(pkt[41])
	dport = uint16(pkt[42])<<8 | uint16(pkt[43])
	payload = pkt[ipv6HeaderLen+8 : ipv6HeaderLen+udpLen]
	ok = true
	return
}

// udp6 builds an IPv6 UDP packet with checksum.
func udp6(src, dst net.IP, sport, dport uint16, payload []byte) []byte {
	src, dst = src.To16(), dst.To16()
	if src == nil || dst == nil {
		return nil
	}
	udpLen := 8 + len(payload)
	pkt := make([]byte, ipv6HeaderLen+udpLen)
	pkt[0] = 0x60
	pkt[4] = byte(udpLen >> 8)
	pkt[5] = byte(udpLen)
	pkt[6] = nextHeaderUDP
	pkt[7] = 64
	copy(pkt[8:24], src)
	copy(pkt[24:40], dst)
	pkt[40] = byte(sport >> 8)
	pkt[41] = byte(sport)
	pkt[42] = byte(dport >> 8)
	pkt[43] = byte(dport)
	pkt[44] = byte(udpLen >> 8)
	pkt[45] = byte(udpLen)
	copy(pkt[48:], payload)
	sum := udp6Checksum(pkt)
	pkt[46] = byte(sum >> 8)
	pkt[47] = byte(sum)
	return pkt
}

// udp6Checksum computes the IPv6 UDP checksum for pkt.
func udp6Checksum(pkt []byte) uint16 {
	return transportChecksum(pkt, nextHeaderUDP)
}

// icmpEchoReply turns an ICMPv6 echo request into a reply, if applicable.
func icmpEchoReply(pkt []byte) ([]byte, bool) {
	if len(pkt) < ipv6HeaderLen+8 || pkt[6] != nextHeaderICMPv6 || pkt[40] != icmpv6EchoRequest {
		return nil, false
	}
	out := append([]byte(nil), pkt...)
	copy(out[8:24], pkt[24:40])
	copy(out[24:40], pkt[8:24])
	out[7] = 64
	out[40] = icmpv6EchoReply
	out[42], out[43] = 0, 0
	sum := icmpv6Checksum(out)
	out[42] = byte(sum >> 8)
	out[43] = byte(sum)
	return out, true
}

// icmpv6Checksum computes the ICMPv6 checksum for pkt.
func icmpv6Checksum(pkt []byte) uint16 {
	return transportChecksum(pkt, nextHeaderICMPv6)
}
