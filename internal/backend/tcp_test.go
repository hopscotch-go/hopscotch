package backend

import (
	"net"
	"testing"
	"time"
)

func TestTCPSessionRoundTrip(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	sa := newTCPSession(a)
	sb := newTCPSession(b)

	gotPing := make(chan []byte, 1)
	go func() {
		got, err := sb.Recv(2 * time.Second)
		if err != nil {
			t.Errorf("recv ping: %v", err)
			close(gotPing)
			return
		}
		gotPing <- got
		if err := sb.Send([]byte("pong")); err != nil {
			t.Errorf("send pong: %v", err)
		}
	}()

	if err := sa.Send([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	select {
	case got, ok := <-gotPing:
		if !ok {
			t.Fatal("recv ping failed")
		}
		if string(got) != "ping" {
			t.Fatalf("got %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for ping")
	}

	got, err := sa.Recv(2 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "pong" {
		t.Fatalf("got %q", got)
	}
}

func TestTCPSessionSplitReads(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	recvDone := make(chan []byte, 1)
	go func() {
		s := newTCPSession(server)
		b, err := s.Recv(2 * time.Second)
		if err != nil {
			t.Errorf("recv: %v", err)
			close(recvDone)
			return
		}
		recvDone <- b
	}()

	raw, err := EncodeFrame([]byte("abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write(raw[:3]); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	if _, err := client.Write(raw[3:]); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-recvDone:
		if string(got) != "abcdef" {
			t.Fatalf("got %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
}

func TestMuxOverFramedPipe(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	sa := newTCPSession(a)
	sb := newTCPSession(b)
	ma := NewMux(pipeAddr("a"))
	mb := NewMux(pipeAddr("b"))
	defer ma.Close()
	defer mb.Close()
	ma.Attach(sa)
	mb.Attach(sb)

	msg := []byte("quic-looking-payload")
	if _, err := ma.WriteTo(msg, sa.RemoteAddr()); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, addr, err := mb.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != string(msg) {
		t.Fatalf("got %q", buf[:n])
	}
	if addr.String() != sb.RemoteAddr().String() {
		t.Fatalf("addr %s", addr)
	}
}

type pipeAddr string

func (a pipeAddr) Network() string { return "pipe" }
func (a pipeAddr) String() string  { return string(a) }
