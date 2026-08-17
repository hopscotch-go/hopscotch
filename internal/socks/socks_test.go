package socks

import (
	"context"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

func TestSOCKSConnect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	_, bportStr, err := net.SplitHostPort(backend.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	bport64, err := strconv.ParseUint(bportStr, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	bport := uint16(bport64)

	go func() {
		c, err := backend.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 4)
		_, _ = io.ReadFull(c, buf)
		_, _ = c.Write([]byte("pong"))
	}()

	s := &Server{
		Dial: func(ctx context.Context, host string, port uint16) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
		},
	}
	go s.ListenAndServe(ln)

	c, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	var greq [2]byte
	if _, err := io.ReadFull(c, greq[:]); err != nil {
		t.Fatal(err)
	}
	if greq[0] != 5 || greq[1] != 0 {
		t.Fatalf("greet %v", greq)
	}

	host := "127.0.0.1"
	req := []byte{5, 1, 0, 3, byte(len(host))}
	req = append(req, host...)
	req = append(req, byte(bport>>8), byte(bport))
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	rep := make([]byte, 10)
	if _, err := io.ReadFull(c, rep); err != nil {
		t.Fatal(err)
	}
	if rep[1] != 0 {
		t.Fatalf("reply %v", rep)
	}
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
}
