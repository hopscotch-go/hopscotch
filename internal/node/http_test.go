package node

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/hopscotch-go/hopscotch/internal/tun"
)

func TestUserspaceHTTPOverlay(t *testing.T) {
	foo, bar, baz := startHub(t)
	defer foo.Close()
	defer bar.Close()
	defer baz.Close()

	foo.cfg.HTTPPort = 80
	if err := foo.startUserspace(); err != nil {
		t.Fatal(err)
	}
	if err := foo.startHTTP(); err != nil {
		t.Fatal(err)
	}
	// Client side looks like remote baz: TUN + userspace (SOCKS path).
	if err := baz.startUserspace(); err != nil {
		t.Fatal(err)
	}
	baz.AttachTun(tun.NewMem())
	if !baz.waitRoute(foo.ID().ULA(), 3*time.Second) {
		t.Fatal("no route")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := baz.DialTCP(ctx, foo.ID().ULA(), 80)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	req, err := http.NewRequest(http.MethodGet, "http://foo/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := req.Write(conn); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(body); got != "hopscotch foo\n" {
		t.Fatalf("body %q", got)
	}
}
