package node

import (
	"context"
	"io"
	"testing"
	"time"
)

func TestUserspaceTCPOverlay(t *testing.T) {
	foo, bar, baz := startHub(t)
	defer foo.Close()
	defer bar.Close()
	defer baz.Close()

	for _, n := range []*Node{foo, baz} {
		if err := n.startUserspace(); err != nil {
			t.Fatal(err)
		}
	}
	if !foo.waitRoute(baz.ID().ULA(), 3*time.Second) {
		t.Fatal("no route to baz")
	}

	ln, err := baz.ListenTCP(7)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	errc := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		defer c.Close()
		buf := make([]byte, 4)
		if _, err := io.ReadFull(c, buf); err != nil {
			errc <- err
			return
		}
		_, err = c.Write([]byte("pong"))
		errc <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := foo.DialTCP(ctx, baz.ID().ULA(), 7)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "pong" {
		t.Fatalf("got %q", buf)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}
