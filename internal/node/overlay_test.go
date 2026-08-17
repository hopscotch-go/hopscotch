package node

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/hopscotch-go/hopscotch/internal/peers"
)

func TestTraceRouteHub(t *testing.T) {
	foo, bar, baz := startHub(t)
	defer foo.Close()
	defer bar.Close()
	defer baz.Close()

	if !foo.waitRoute(baz.ID().ULA(), 3*time.Second) {
		t.Fatal("no route to baz")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tr, err := foo.TraceRoute(ctx, baz.ID().ULA().String(), 8)
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

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tr, err := foo.TraceRoute(ctx, blaz.ID().ULA().String(), 16)
	if err != nil {
		t.Fatal(err)
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
