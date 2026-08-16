package node

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hopscotch-go/hopscotch/internal/identity"
	"github.com/hopscotch-go/hopscotch/internal/peers"
	"github.com/hopscotch-go/hopscotch/internal/tun"
)

// Former XOR loop-risk topology. With hop-count DV, the spur is the short
// path and OverlayLoopCount stays 0.
func TestOverlayProgressNoCycle(t *testing.T) {
	var (
		foo, bar, baz, buzz, bizz, blaz *Node
		loopRisk                        bool
	)
	for attempt := 1; attempt <= 80; attempt++ {
		dir := t.TempDir()
		caPath, caCert, caKey := writeCA(t, dir)
		bar = startNode(t, dir, "bar", caPath, caCert, caKey, Config{Listen: "127.0.0.1:0", Network: "udp"})
		foo = startNode(t, dir, "foo", caPath, caCert, caKey, Config{
			Peers:   []peers.Peer{{Addr: bar.AdvertiseAddr()}},
			Control: filepath.Join(dir, "foo.sock"),
		})
		waitPeers(t, foo, 1)
		waitPeers(t, bar, 1)
		baz = startNode(t, dir, "baz", caPath, caCert, caKey, Config{
			Listen:  "127.0.0.1:0",
			Network: "udp",
			Peers:   []peers.Peer{{Addr: bar.AdvertiseAddr()}},
		})
		waitPeers(t, baz, 1)
		waitPeers(t, bar, 2)
		buzz = startNode(t, dir, "buzz", caPath, caCert, caKey, Config{
			Listen:  "127.0.0.1:0",
			Network: "udp",
			Peers:   []peers.Peer{{Addr: baz.AdvertiseAddr()}, {Addr: bar.AdvertiseAddr()}},
		})
		waitPeers(t, buzz, 2)
		waitPeers(t, bar, 3)
		bizz = startNode(t, dir, "bizz", caPath, caCert, caKey, Config{
			Listen:  "127.0.0.1:0",
			Network: "udp",
			Peers:   []peers.Peer{{Addr: buzz.AdvertiseAddr()}},
		})
		waitPeers(t, bizz, 1)
		waitPeers(t, buzz, 3)
		blaz = startNode(t, dir, "blaz", caPath, caCert, caKey, Config{
			Peers: []peers.Peer{{Addr: bizz.AdvertiseAddr()}},
		})
		waitPeers(t, blaz, 1)
		waitPeers(t, bizz, 2)

		loopRisk = identity.CloserULA(blaz.ID().ULA(), baz.ID().ULA(), buzz.ID().ULA()) &&
			!identity.CloserULA(blaz.ID().ULA(), bizz.ID().ULA(), bar.ID().ULA())
		if loopRisk {
			t.Logf("naive-loop-risk topology on attempt %d", attempt)
			break
		}
		foo.Close()
		bar.Close()
		baz.Close()
		buzz.Close()
		bizz.Close()
		blaz.Close()
		foo, bar, baz, buzz, bizz, blaz = nil, nil, nil, nil, nil, nil
	}
	if foo == nil || !loopRisk {
		t.Skip("could not key a naive-loop-risk ULA set in time")
	}
	defer foo.Close()
	defer bar.Close()
	defer baz.Close()
	defer buzz.Close()
	defer bizz.Close()
	defer blaz.Close()

	if !foo.waitRoute(blaz.ID().ULA(), 5*time.Second) {
		t.Fatal("foo has no route to blaz")
	}

	writeTestHosts(t, filepath.Dir(foo.cfg.Identity), foo, bar, baz, buzz, bizz, blaz)
	foo.loadHostsFile()

	dev := tun.NewMem()
	defer dev.Close()
	foo.AttachTun(dev)
	req := ipv6ICMPEcho(foo.ID().ULA(), blaz.ID().ULA(), 32)
	if err := dev.Inject(req); err != nil {
		t.Fatal(err)
	}
	select {
	case <-time.After(3 * time.Second):
	case pkt := <-dev.Recv():
		switch pkt[40] {
		case icmpv6EchoReply, icmpv6DestUnreach, icmpv6TimeExceeded:
		default:
			t.Logf("unexpected icmp type %d", pkt[40])
		}
	}
	total := buzz.OverlayLoopCount() + bar.OverlayLoopCount() + baz.OverlayLoopCount()
	if total != 0 {
		t.Fatalf("DV must not cycle; overlay_loops=%d", total)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	tr, err := foo.TraceRoute(ctx, "blaz", 16)
	if err != nil {
		t.Fatal(err)
	}
	total = buzz.OverlayLoopCount() + bar.OverlayLoopCount() + baz.OverlayLoopCount()
	if total != 0 {
		t.Fatalf("traceroute must not induce cycles; overlay_loops=%d", total)
	}
	if !tr.Reach {
		t.Fatalf("expected reach blaz via DV, hops=%v", tr.Hops)
	}
	teNames := map[string]int{}
	for _, h := range tr.Hops {
		if h.Reply == "time_exceeded" && h.Name != "" {
			teNames[h.Name]++
		}
	}
	for name, c := range teNames {
		if c > 2 {
			t.Fatalf("time_exceeded from %q %d times — forward cycle?: %v", name, c, tr.Hops)
		}
	}
}

func TestTraceRouteHub(t *testing.T) {
	foo, bar, baz := startHub(t)
	defer foo.Close()
	defer bar.Close()
	defer baz.Close()

	writeTestHosts(t, filepath.Dir(foo.cfg.Identity), foo, bar, baz)
	foo.loadHostsFile()
	if !foo.waitRoute(baz.ID().ULA(), 3*time.Second) {
		t.Fatal("no route to baz")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tr, err := foo.TraceRoute(ctx, "baz", 8)
	if err != nil {
		t.Fatal(err)
	}
	if !tr.Reach {
		t.Fatalf("expected reach baz, hops=%v", tr.Hops)
	}
	if len(tr.Hops) < 2 {
		t.Fatalf("short trace %#v", tr.Hops)
	}
}

func TestOverlayReachesBlaz(t *testing.T) {
	dir := t.TempDir()
	caPath, caCert, caKey := writeCA(t, dir)
	bar := startNode(t, dir, "bar", caPath, caCert, caKey, Config{Listen: "127.0.0.1:0", Network: "udp"})
	defer bar.Close()
	foo := startNode(t, dir, "foo", caPath, caCert, caKey, Config{
		Peers:   []peers.Peer{{Addr: bar.AdvertiseAddr()}},
		Control: filepath.Join(dir, "foo.sock"),
	})
	defer foo.Close()
	waitPeers(t, foo, 1)
	waitPeers(t, bar, 1)
	baz := startNode(t, dir, "baz", caPath, caCert, caKey, Config{
		Listen:  "127.0.0.1:0",
		Network: "udp",
		Peers:   []peers.Peer{{Addr: bar.AdvertiseAddr()}},
	})
	defer baz.Close()
	waitPeers(t, baz, 1)
	waitPeers(t, bar, 2)
	buzz := startNode(t, dir, "buzz", caPath, caCert, caKey, Config{
		Listen:  "127.0.0.1:0",
		Network: "udp",
		Peers:   []peers.Peer{{Addr: baz.AdvertiseAddr()}, {Addr: bar.AdvertiseAddr()}},
	})
	defer buzz.Close()
	waitPeers(t, buzz, 2)
	waitPeers(t, bar, 3)
	bizz := startNode(t, dir, "bizz", caPath, caCert, caKey, Config{
		Listen:  "127.0.0.1:0",
		Network: "udp",
		Peers:   []peers.Peer{{Addr: buzz.AdvertiseAddr()}},
	})
	defer bizz.Close()
	waitPeers(t, bizz, 1)
	waitPeers(t, buzz, 3)
	blaz := startNode(t, dir, "blaz", caPath, caCert, caKey, Config{
		Peers: []peers.Peer{{Addr: bizz.AdvertiseAddr()}},
	})
	defer blaz.Close()
	waitPeers(t, blaz, 1)
	waitPeers(t, bizz, 2)

	if !foo.waitRoute(blaz.ID().ULA(), 5*time.Second) {
		t.Fatalf("no DV route to blaz metric=%d", foo.RouteMetric(blaz.ID().ULA()))
	}
	if foo.PeerCount() != 1 {
		t.Fatalf("foo should stay degree-1; peers=%d", foo.PeerCount())
	}

	writeTestHosts(t, dir, foo, bar, baz, buzz, bizz, blaz)
	foo.loadHostsFile()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tr, err := foo.TraceRoute(ctx, "blaz", 16)
	if err != nil {
		t.Fatal(err)
	}
	total := buzz.OverlayLoopCount() + bar.OverlayLoopCount() + baz.OverlayLoopCount()
	if total != 0 {
		t.Fatalf("overlay_loops=%d", total)
	}
	if !tr.Reach {
		t.Fatalf("expected to reach blaz, hops=%v", tr.Hops)
	}
}

func TestNextHopUsesRouteTable(t *testing.T) {
	foo, bar, baz := startHub(t)
	defer foo.Close()
	defer bar.Close()
	defer baz.Close()

	if !foo.waitRoute(baz.ID().ULA(), 3*time.Second) {
		t.Fatal("foo missing route to baz")
	}
	hop := foo.nextHop(baz.ID().ULA(), nil)
	if hop == nil || hop.id != bar.ID() {
		t.Fatalf("origin next hop %v want bar", hop)
	}
	fromFoo := bar.session(foo.ID())
	if fromFoo == nil {
		t.Fatal("bar missing foo")
	}
	if !bar.waitRoute(baz.ID().ULA(), 3*time.Second) {
		t.Fatal("bar missing route to baz")
	}
	hop = bar.nextHop(baz.ID().ULA(), fromFoo)
	if hop == nil || hop.id != baz.ID() {
		t.Fatalf("bar next hop %v want baz", hop)
	}
	if m := foo.RouteMetric(baz.ID().ULA()); m != 2 {
		t.Fatalf("foo metric to baz %d want 2", m)
	}
}

func writeTestHosts(t *testing.T, dir string, nodes ...*Node) {
	t.Helper()
	var b strings.Builder
	b.WriteString("# hopscotch overlay names → ULA\n")
	for _, n := range nodes {
		name := n.hopName()
		fmt.Fprintf(&b, "%s %s\n", n.ID().ULA(), name)
	}
	if err := os.WriteFile(filepath.Join(dir, "hosts"), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}
