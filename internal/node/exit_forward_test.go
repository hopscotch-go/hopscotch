package node

import (
	"testing"
	"time"

	"github.com/hopscotch-go/hopscotch/internal/tun"
)

func TestExitEncapsulateForward(t *testing.T) {
	foo, bar, baz := startHub(t)
	defer foo.Close()
	defer bar.Close()
	defer baz.Close()

	baz.cfg.Exit = true
	foo.cfg.ExitNode = "baz"
	foo.exitMu.Lock()
	foo.exitULA = baz.ID().ULA()
	foo.exitMu.Unlock()

	if !foo.waitRoute(baz.ID().ULA(), 3*time.Second) {
		t.Fatal("no route")
	}

	inner := make([]byte, 20)
	inner[0] = 0x45
	inner[3] = 20
	inner[8] = 64
	inner[9] = 1
	pl := PlumbingIPv4(foo.ID().ULA()).To4()
	copy(inner[12:16], pl)
	copy(inner[16:20], []byte{8, 8, 8, 8})

	mem := tun.NewMem()
	defer mem.Close()
	baz.mu.Lock()
	baz.tun = mem
	baz.mu.Unlock()

	foo.handleExitFromTUN(nil, inner)

	select {
	case got := <-mem.Recv():
		if got[0]>>4 != 4 {
			t.Fatalf("want ipv4 on exit tun, got ver=%d", got[0]>>4)
		}
		if !netIPEqual(got[12:16], pl) {
			t.Fatalf("src %v want %v", got[12:16], pl)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for exit egress")
	}
}

func TestExitAdvertiseDefaults(t *testing.T) {
	foo, bar, baz := startHub(t)
	defer foo.Close()
	defer bar.Close()
	defer baz.Close()

	baz.cfg.Exit = true
	baz.advertiseRoutes()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		foo.routeMu.Lock()
		_, ok4 := foo.routes[defaultRouteV4]
		_, ok6 := foo.routes[defaultRouteV6]
		foo.routeMu.Unlock()
		if ok4 && ok6 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("foo did not learn default routes from exit")
}

func netIPEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
