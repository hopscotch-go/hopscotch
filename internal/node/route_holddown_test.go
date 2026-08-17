package node

import (
	"testing"
	"time"

	"github.com/hopscotch-go/hopscotch/internal/proto"
)

func TestRIBHolddown(t *testing.T) {
	foo, bar, baz := startHub(t)
	defer foo.Close()
	defer bar.Close()
	defer baz.Close()

	baz.cfg.Exit = true
	baz.advertiseRoutes()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		foo.routeMu.Lock()
		_, ok := foo.routes[defaultRouteV6]
		foo.routeMu.Unlock()
		if ok {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	foo.routeMu.Lock()
	_, ok := foo.routes[defaultRouteV6]
	foo.routeMu.Unlock()
	if !ok {
		t.Fatal("foo never learned ::/0")
	}

	barSess := foo.session(bar.ID())
	if barSess == nil {
		t.Fatal("no session to bar")
	}
	// Sparse ad: only bar's ULA (as if bar briefly lost the exit).
	foo.handleRoutes(barSess, proto.Message{
		Type:   "routes",
		Routes: []proto.Route{{Dest: bar.ID().ULA().String(), Metric: 0}},
	})

	foo.routeMu.Lock()
	_, still := foo.routes[defaultRouteV6]
	stale := foo.routes[defaultRouteV6].stale
	foo.routeMu.Unlock()
	if !still {
		t.Fatal("sparse ad withdrew ::/0 immediately; want holddown")
	}
	if stale.IsZero() {
		t.Fatal("expected ::/0 marked stale after sparse ad")
	}

	// Full ad again within holddown restores the route.
	foo.handleRoutes(barSess, proto.Message{
		Type: "routes",
		Routes: []proto.Route{
			{Dest: bar.ID().ULA().String(), Metric: 0},
			{Dest: defaultRouteV6, Metric: 1},
			{Dest: defaultRouteV4, Metric: 1},
			{Dest: baz.ID().ULA().String(), Metric: 1},
		},
	})
	foo.routeMu.Lock()
	e := foo.routes[defaultRouteV6]
	foo.routeMu.Unlock()
	if e.stale.IsZero() == false {
		t.Fatal("full ad should clear stale")
	}
}
