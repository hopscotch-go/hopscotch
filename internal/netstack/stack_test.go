package netstack

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestDialListenLoopback(t *testing.T) {
	ip := net.ParseIP("fd00::1")
	var peer *Stack
	a, err := New(ip, 1280, func(pkt []byte) {
		if peer != nil {
			peer.Inject(pkt)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	peer = a

	ln, err := a.ListenTCP(9)
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
		buf := make([]byte, 5)
		if _, err := io.ReadFull(c, buf); err != nil {
			errc <- err
			return
		}
		_, err = c.Write([]byte("world"))
		errc <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := a.DialTCP(ctx, ip, 9)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "world" {
		t.Fatalf("got %q", buf)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}
