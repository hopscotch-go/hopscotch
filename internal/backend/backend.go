package backend

import (
	"context"
	"errors"
	"net"
	"time"
)

var ErrTimeout = errors.New("backend recv timeout")

// Session is one hop to a neighbor. It carries datagrams, not QUIC.
// TCP implementations length-prefix; UDP sends raw packets.
type Session interface {
	Send([]byte) error
	Recv(timeout time.Duration) ([]byte, error)
	Close() error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
}

// Listener accepts inbound backend sessions.
type Listener interface {
	Start(ctx context.Context) (<-chan Session, error)
	Addr() net.Addr
	Close() error
}

// Dialer opens an outbound backend session.
type Dialer interface {
	Dial(ctx context.Context, address string) (Session, error)
}

func NewListener(network, address string) (Listener, error) {
	switch network {
	case "tcp":
		return NewTCPListener(address)
	case "udp":
		return NewUDPListener(address)
	default:
		return nil, errors.New("unknown backend " + network)
	}
}

func NewDialer(network string) (Dialer, error) {
	switch network {
	case "tcp":
		return TCPDialer{}, nil
	case "udp":
		return UDPDialer{}, nil
	default:
		return nil, errors.New("unknown backend " + network)
	}
}
