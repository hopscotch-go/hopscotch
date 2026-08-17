package node

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"golang.org/x/net/dns/dnsmessage"

	"github.com/hopscotch-go/hopscotch/internal/identity"
	"github.com/hopscotch-go/hopscotch/internal/peers"
	"github.com/hopscotch-go/hopscotch/internal/tun"
)

func TestHubStarNextHop(t *testing.T) {
	foo, bar, baz := startHub(t)
	defer foo.Close()
	defer bar.Close()
	defer baz.Close()

	dest := baz.ID().ULA()
	if !foo.waitRoute(dest, 3*time.Second) {
		t.Fatal("foo has no route to baz")
	}
	hop := foo.nextHop(dest, nil)
	if hop == nil || hop.id != bar.ID() {
		t.Fatalf("foo next hop %v", hop)
	}
	fromFoo := bar.session(foo.ID())
	if fromFoo == nil {
		t.Fatal("bar missing foo session")
	}
	if !bar.waitRoute(dest, 3*time.Second) {
		t.Fatal("bar has no route to baz")
	}
	hop = bar.nextHop(dest, fromFoo)
	if hop == nil || hop.id != baz.ID() {
		t.Fatalf("bar next hop %v want baz", hop)
	}
}

func TestHubStarPacket(t *testing.T) {
	foo, bar, baz := startHub(t)
	defer foo.Close()
	defer bar.Close()
	defer baz.Close()

	fooDev := tun.NewMem()
	bazDev := tun.NewMem()
	defer fooDev.Close()
	defer bazDev.Close()
	foo.AttachTun(fooDev)
	baz.AttachTun(bazDev)

	pkt := ipv6Empty(foo.ID().ULA(), baz.ID().ULA(), 64)
	if err := fooDev.Inject(pkt); err != nil {
		t.Fatal(err)
	}
	got := recvMem(t, bazDev, 3*time.Second)
	if !net.IP(got[24:40]).Equal(baz.ID().ULA()) {
		t.Fatalf("dst %s", net.IP(got[24:40]))
	}
	if !net.IP(got[8:24]).Equal(foo.ID().ULA()) {
		t.Fatalf("src %s", net.IP(got[8:24]))
	}
	if got[7] != 63 {
		t.Fatalf("hop limit %d after one forward", got[7])
	}
}

func TestHubStarLargePacket(t *testing.T) {
	foo, bar, baz := startHub(t)
	defer foo.Close()
	defer bar.Close()
	defer baz.Close()

	fooDev := tun.NewMem()
	bazDev := tun.NewMem()
	defer fooDev.Close()
	defer bazDev.Close()
	foo.AttachTun(fooDev)
	baz.AttachTun(bazDev)

	pkt := make([]byte, tun.MTU)
	pkt[0] = 0x60
	plen := tun.MTU - ipv6HeaderLen
	pkt[4] = byte(plen >> 8)
	pkt[5] = byte(plen)
	pkt[6] = 59
	pkt[7] = 64
	copy(pkt[8:24], foo.ID().ULA().To16())
	copy(pkt[24:40], baz.ID().ULA().To16())
	for i := ipv6HeaderLen; i < len(pkt); i++ {
		pkt[i] = byte(i)
	}
	if err := fooDev.Inject(pkt); err != nil {
		t.Fatal(err)
	}
	got := recvMem(t, bazDev, 5*time.Second)
	if len(got) != tun.MTU {
		t.Fatalf("len %d", len(got))
	}
	if !bytes.Equal(got[ipv6HeaderLen:], pkt[ipv6HeaderLen:]) {
		t.Fatal("payload")
	}
	if got[7] != 63 {
		t.Fatalf("hop limit %d", got[7])
	}
}

func TestClampTCPMSS(t *testing.T) {
	src := identity.NodeID{1}.ULA()
	dst := identity.NodeID{2}.ULA()
	orig := tcpSYN(src, dst, 1440)
	got := clampTCPMSS(orig, 1220)
	mss := binary.BigEndian.Uint16(got[ipv6HeaderLen+22 : ipv6HeaderLen+24])
	if mss != 1220 {
		t.Fatalf("mss %d", mss)
	}
	if binary.BigEndian.Uint16(orig[ipv6HeaderLen+22:ipv6HeaderLen+24]) != 1440 {
		t.Fatal("mutated original")
	}
	sum := binary.BigEndian.Uint16(got[ipv6HeaderLen+16 : ipv6HeaderLen+18])
	check := append([]byte(nil), got...)
	check[ipv6HeaderLen+16], check[ipv6HeaderLen+17] = 0, 0
	if tcp6Checksum(check) != sum {
		t.Fatal("checksum")
	}
	same := clampTCPMSS(tcpSYN(src, dst, 1000), 1220)
	if binary.BigEndian.Uint16(same[ipv6HeaderLen+22:ipv6HeaderLen+24]) != 1000 {
		t.Fatal("should leave smaller mss")
	}
}

func tcpSYN(src, dst net.IP, mss uint16) []byte {
	p := make([]byte, ipv6HeaderLen+24)
	p[0] = 0x60
	p[4], p[5] = 0, 24
	p[6] = nextHeaderTCP
	p[7] = 64
	copy(p[8:24], src.To16())
	copy(p[24:40], dst.To16())
	p[40], p[41] = 0x04, 0xd2
	p[42], p[43] = 0x00, 0x16
	p[ipv6HeaderLen+12] = 6 << 4
	p[ipv6HeaderLen+13] = tcpFlagSYN
	p[ipv6HeaderLen+14], p[ipv6HeaderLen+15] = 0xff, 0xff
	p[ipv6HeaderLen+20] = tcpOptMSS
	p[ipv6HeaderLen+21] = 4
	binary.BigEndian.PutUint16(p[ipv6HeaderLen+22:ipv6HeaderLen+24], mss)
	sum := tcp6Checksum(p)
	p[ipv6HeaderLen+16] = byte(sum >> 8)
	p[ipv6HeaderLen+17] = byte(sum)
	return p
}

func TestOverlayHopLimit(t *testing.T) {
	foo, bar, baz := startHub(t)
	defer foo.Close()
	defer bar.Close()
	defer baz.Close()

	fooDev := tun.NewMem()
	bazDev := tun.NewMem()
	defer fooDev.Close()
	defer bazDev.Close()
	foo.AttachTun(fooDev)
	baz.AttachTun(bazDev)

	if err := fooDev.Inject(ipv6Empty(foo.ID().ULA(), baz.ID().ULA(), 1)); err != nil {
		t.Fatal(err)
	}
	got := recvMem(t, fooDev, 3*time.Second)
	if got[40] != icmpv6TimeExceeded {
		t.Fatalf("icmp type %d", got[40])
	}
	if !net.IP(got[8:24]).Equal(bar.ID().ULA()) {
		t.Fatalf("src %s want bar", net.IP(got[8:24]))
	}
	if !net.IP(got[24:40]).Equal(foo.ID().ULA()) {
		t.Fatalf("dst %s", net.IP(got[24:40]))
	}
	select {
	case <-bazDev.Recv():
		t.Fatal("packet with hop limit 1 should die at bar")
	case <-time.After(200 * time.Millisecond):
	}
}

func startHub(t *testing.T) (*Node, *Node, *Node) {
	t.Helper()
	dir := t.TempDir()
	caPath, caCert, caKey := writeCA(t, dir)
	bar := startNode(t, dir, "bar", caPath, caCert, caKey, Config{
		Listen:  "127.0.0.1:0",
		Network: "udp",
	})
	foo := startNode(t, dir, "foo", caPath, caCert, caKey, Config{
		Peers:   []peers.Peer{{Addr: bar.AdvertiseAddr()}},
		Control: filepath.Join(dir, "foo.sock"),
	})
	baz := startNode(t, dir, "baz", caPath, caCert, caKey, Config{
		Peers: []peers.Peer{{Addr: bar.AdvertiseAddr()}},
	})
	waitPeers(t, foo, 1)
	waitPeers(t, baz, 1)
	waitPeers(t, bar, 2)
	return foo, bar, baz
}

func ipv6Empty(src, dst net.IP, hop uint8) []byte {
	p := make([]byte, 40)
	p[0] = 0x60
	p[6] = 59
	p[7] = hop
	copy(p[8:24], src.To16())
	copy(p[24:40], dst.To16())
	return p
}

func ipv6ICMPEcho(src, dst net.IP, hop uint8) []byte {
	p := make([]byte, 56)
	p[0] = 0x60
	p[4], p[5] = 0, 16
	p[6] = nextHeaderICMPv6
	p[7] = hop
	copy(p[8:24], src.To16())
	copy(p[24:40], dst.To16())
	p[40] = icmpv6EchoRequest
	p[44], p[45] = 0x12, 0x34
	p[46], p[47] = 0, 1
	sum := icmpv6Checksum(p)
	p[42] = byte(sum >> 8)
	p[43] = byte(sum)
	return p
}

func recvMem(t *testing.T, d *tun.Mem, wait time.Duration) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	select {
	case <-ctx.Done():
		t.Fatal("timeout waiting for overlay packet")
		return nil
	case p := <-d.Recv():
		if len(p) < 20 {
			t.Fatalf("short packet %d", len(p))
		}
		return p
	}
}

func TestHubStarICMPEcho(t *testing.T) {
	foo, bar, baz := startHub(t)
	defer foo.Close()
	defer bar.Close()
	defer baz.Close()

	fooDev := tun.NewMem()
	defer fooDev.Close()
	foo.AttachTun(fooDev)

	req := ipv6ICMPEcho(foo.ID().ULA(), baz.ID().ULA(), 64)
	if err := fooDev.Inject(req); err != nil {
		t.Fatal(err)
	}
	got := recvMem(t, fooDev, 3*time.Second)
	if got[40] != icmpv6EchoReply {
		t.Fatalf("icmp type %d", got[40])
	}
	if !net.IP(got[8:24]).Equal(baz.ID().ULA()) {
		t.Fatalf("src %s", net.IP(got[8:24]))
	}
	if !net.IP(got[24:40]).Equal(foo.ID().ULA()) {
		t.Fatalf("dst %s", net.IP(got[24:40]))
	}
}

func TestICMPEchoReply(t *testing.T) {
	src := identity.NodeID{1}.ULA()
	dst := identity.NodeID{2}.ULA()
	req := ipv6ICMPEcho(src, dst, 64)
	reply, ok := icmpEchoReply(req)
	if !ok {
		t.Fatal("ok")
	}
	if reply[40] != icmpv6EchoReply {
		t.Fatalf("type %d", reply[40])
	}
	if !net.IP(reply[8:24]).Equal(dst) || !net.IP(reply[24:40]).Equal(src) {
		t.Fatal("addrs")
	}
	got := uint16(reply[42])<<8 | uint16(reply[43])
	reply[42], reply[43] = 0, 0
	if icmpv6Checksum(reply) != got {
		t.Fatalf("checksum got %04x want %04x", got, icmpv6Checksum(reply))
	}
}

func TestICMPPacketTooBig(t *testing.T) {
	src := identity.NodeID{1}.ULA()
	dst := identity.NodeID{2}.ULA()
	router := identity.NodeID{3}.ULA()
	orig := ipv6Empty(src, dst, 64)
	orig = append(orig, bytes.Repeat([]byte{0xab}, tun.MTU)...)
	plen := len(orig) - ipv6HeaderLen
	orig[4] = byte(plen >> 8)
	orig[5] = byte(plen)

	got := icmpPacketTooBig(orig, router, 1100)
	if got == nil {
		t.Fatal("nil")
	}
	if got[6] != nextHeaderICMPv6 || got[40] != icmpv6PacketTooBig {
		t.Fatalf("icmp %d %d", got[6], got[40])
	}
	if !net.IP(got[8:24]).Equal(router) || !net.IP(got[24:40]).Equal(src) {
		t.Fatal("addrs")
	}
	if binary.BigEndian.Uint32(got[44:48]) != 1100 {
		t.Fatalf("mtu %d", binary.BigEndian.Uint32(got[44:48]))
	}
	if len(got) > tun.MTU {
		t.Fatalf("ptb length %d > MTU", len(got))
	}
	sum := uint16(got[42])<<8 | uint16(got[43])
	got[42], got[43] = 0, 0
	if icmpv6Checksum(got) != sum {
		t.Fatal("checksum")
	}
}

func TestICMPPacketTooBigSkipsICMPError(t *testing.T) {
	src := identity.NodeID{1}.ULA()
	dst := identity.NodeID{2}.ULA()
	errPkt := icmpPacketTooBig(ipv6Empty(src, dst, 64), dst, tun.MTU)
	if icmpPacketTooBig(errPkt, dst, tun.MTU) != nil {
		t.Fatal("ptb of ptb")
	}
}

func icmpPacketTooBig(pkt []byte, src net.IP, mtu int) []byte {
	return icmpv6Error(pkt, src, icmpv6PacketTooBig, 0, uint32(mtu))
}

func TestPacketTooBigToTun(t *testing.T) {
	foo, bar, baz := startHub(t)
	defer foo.Close()
	defer bar.Close()
	defer baz.Close()

	fooDev := tun.NewMem()
	defer fooDev.Close()
	foo.AttachTun(fooDev)

	orig := ipv6Empty(foo.ID().ULA(), baz.ID().ULA(), 64)
	orig = append(orig, make([]byte, tun.MTU)...)
	plen := len(orig) - ipv6HeaderLen
	orig[4] = byte(plen >> 8)
	orig[5] = byte(plen)
	foo.sendPacketTooBig(nil, orig, &quic.DatagramTooLargeError{MaxDatagramPayloadSize: int64(tun.MTU)})
	got := recvMem(t, fooDev, time.Second)
	if got[40] != icmpv6PacketTooBig {
		t.Fatalf("type %d", got[40])
	}
	if !net.IP(got[24:40]).Equal(foo.ID().ULA()) {
		t.Fatalf("dst %s", net.IP(got[24:40]))
	}
}

func TestParseIPv6(t *testing.T) {
	src := identity.NodeID{1, 2, 3}.ULA()
	dst := identity.NodeID{4, 5, 6}.ULA()
	p := ipv6Empty(src, dst, 9)
	got, hop, ok := parseIPv6(p)
	if !ok || hop != 9 || !got.Equal(dst) {
		t.Fatalf("%v hop=%d ok=%v", got, hop, ok)
	}
	if parse, _, ok := parseIPv6([]byte{0x45, 0, 0, 0}); ok || parse != nil {
		t.Fatal("v4")
	}
}

func TestOverlayDNS(t *testing.T) {
	foo, bar, baz := startHub(t)
	defer foo.Close()
	defer bar.Close()
	defer baz.Close()

	fooDev := tun.NewMem()
	defer fooDev.Close()
	foo.AttachTun(fooDev)

	q := dnsQueryPkt(t, foo.ID().ULA(), identity.ResolverULA(), "bar.hopscotch.", dnsmessage.TypeAAAA)
	if err := fooDev.Inject(q); err != nil {
		t.Fatal(err)
	}
	got := recvMem(t, fooDev, 3*time.Second)
	src, dst, sport, dport, payload, ok := parseUDP6(got)
	if !ok {
		t.Fatal("not udp")
	}
	if !src.Equal(identity.ResolverULA()) || !dst.Equal(foo.ID().ULA()) {
		t.Fatalf("addrs %s → %s", src, dst)
	}
	if sport != dnsPort || dport != 12345 {
		t.Fatalf("ports %d → %d", sport, dport)
	}
	var p dnsmessage.Parser
	if _, err := p.Start(payload); err != nil {
		t.Fatal(err)
	}
	if err := p.SkipAllQuestions(); err != nil {
		t.Fatal(err)
	}
	h, err := p.AnswerHeader()
	if err != nil {
		t.Fatal(err)
	}
	rr, err := p.AAAAResource()
	if err != nil {
		t.Fatal(err)
	}
	if h.Type != dnsmessage.TypeAAAA || !net.IP(rr.AAAA[:]).Equal(bar.ID().ULA()) {
		t.Fatalf("aaaa %s", net.IP(rr.AAAA[:]))
	}
}

func TestResolverULANotForwarded(t *testing.T) {
	foo, bar, baz := startHub(t)
	defer foo.Close()
	defer bar.Close()
	defer baz.Close()

	fooDev := tun.NewMem()
	bazDev := tun.NewMem()
	defer fooDev.Close()
	defer bazDev.Close()
	foo.AttachTun(fooDev)
	baz.AttachTun(bazDev)

	q := dnsQueryPkt(t, foo.ID().ULA(), identity.ResolverULA(), "example.com.", dnsmessage.TypeAAAA)
	if err := fooDev.Inject(q); err != nil {
		t.Fatal(err)
	}
	got := recvMem(t, fooDev, 3*time.Second)
	_, _, _, _, payload, ok := parseUDP6(got)
	if !ok {
		t.Fatal("not udp")
	}
	var p dnsmessage.Parser
	hdr, err := p.Start(payload)
	if err != nil {
		t.Fatal(err)
	}
	if hdr.RCode != dnsmessage.RCodeRefused {
		t.Fatalf("rcode %v", hdr.RCode)
	}
	select {
	case <-bazDev.Recv():
		t.Fatal("DNS query was forwarded into the mesh")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestSessionNameDNS(t *testing.T) {
	foo, bar, baz := startHub(t)
	defer foo.Close()
	defer bar.Close()
	defer baz.Close()

	fooDev := tun.NewMem()
	defer fooDev.Close()
	foo.AttachTun(fooDev)

	q := dnsQueryPkt(t, foo.ID().ULA(), identity.ResolverULA(), "bar.hopscotch.", dnsmessage.TypeAAAA)
	if err := fooDev.Inject(q); err != nil {
		t.Fatal(err)
	}
	got := recvMem(t, fooDev, 3*time.Second)
	_, _, _, _, payload, ok := parseUDP6(got)
	if !ok {
		t.Fatal("not udp")
	}
	var p dnsmessage.Parser
	if _, err := p.Start(payload); err != nil {
		t.Fatal(err)
	}
	if err := p.SkipAllQuestions(); err != nil {
		t.Fatal(err)
	}
	if _, err := p.AnswerHeader(); err != nil {
		t.Fatal(err)
	}
	rr, err := p.AAAAResource()
	if err != nil {
		t.Fatal(err)
	}
	if !net.IP(rr.AAAA[:]).Equal(bar.ID().ULA()) {
		t.Fatalf("aaaa %s want bar", net.IP(rr.AAAA[:]))
	}
}

func dnsQueryPkt(t *testing.T, src, dst net.IP, name string, typ dnsmessage.Type) []byte {
	t.Helper()
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{ID: 1, RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name:  dnsmessage.MustNewName(name),
			Type:  typ,
			Class: dnsmessage.ClassINET,
		}},
	}
	body, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return udp6(src, dst, 12345, dnsPort, body)
}
