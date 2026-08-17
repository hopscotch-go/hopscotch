package node

import (
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestSocksOverlayConnect(t *testing.T) {
	foo, bar, baz := startHub(t)
	defer foo.Close()
	defer bar.Close()
	defer baz.Close()

	for _, n := range []*Node{foo, baz} {
		if err := n.startUserspace(); err != nil {
			t.Fatal(err)
		}
	}
	writeTestHosts(t, filepath.Dir(foo.cfg.Identity), foo, bar, baz)
	foo.loadHostsFile()
	if !foo.waitRoute(baz.ID().ULA(), 3*time.Second) {
		t.Fatal("no route")
	}

	ln, err := baz.ListenTCP(80)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 4)
		_, _ = io.ReadFull(c, buf)
		_, _ = c.Write([]byte("HTTP"))
	}()

	foo.cfg.Socks = "127.0.0.1:0"
	if err := foo.startSocks(); err != nil {
		t.Fatal(err)
	}
	foo.mu.Lock()
	socksAddr := foo.socksLn.Addr().String()
	foo.mu.Unlock()

	c, err := net.DialTimeout("tcp", socksAddr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))

	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	var greq [2]byte
	if _, err := io.ReadFull(c, greq[:]); err != nil {
		t.Fatal(err)
	}
	host := "baz"
	req := []byte{5, 1, 0, 3, byte(len(host))}
	req = append(req, host...)
	req = append(req, 0, 80)
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	rep := make([]byte, 10)
	if _, err := io.ReadFull(c, rep); err != nil {
		t.Fatal(err)
	}
	if rep[1] != 0 {
		t.Fatalf("socks reply %v", rep)
	}
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "HTTP" {
		t.Fatalf("got %q", buf)
	}
}
