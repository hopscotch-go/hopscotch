package tun

import (
	"io"
	"sync"
)

// Mem is an in-process TUN for tests. Inject feeds ReadPacket;
// packets written by the node are received with Recv.
type Mem struct {
	in     chan []byte
	out    chan []byte
	mu     sync.Mutex
	closed bool
}

// NewMem returns a buffered in-memory Device for unit tests.
func NewMem() *Mem {
	return &Mem{
		in:  make(chan []byte, 16),
		out: make(chan []byte, 256),
	}
}

// Name returns the fixed interface name "mem".
func (m *Mem) Name() string { return "mem" }

// Inject delivers a packet that the next ReadPacket call will return.
func (m *Mem) Inject(pkt []byte) error {
	m.mu.Lock()
	closed := m.closed
	m.mu.Unlock()
	if closed {
		return io.EOF
	}
	m.in <- append([]byte(nil), pkt...)
	return nil
}

// ReadPacket blocks until Inject provides a packet or Close shuts the channel.
func (m *Mem) ReadPacket() ([]byte, error) {
	p, ok := <-m.in
	if !ok {
		return nil, io.EOF
	}
	return p, nil
}

// WritePacket copies a packet into the outbound channel for Recv consumers.
func (m *Mem) WritePacket(pkt []byte) error {
	select {
	case m.out <- append([]byte(nil), pkt...):
		return nil
	default:
		return nil
	}
}

// Recv returns the channel of packets previously written with WritePacket.
func (m *Mem) Recv() <-chan []byte { return m.out }

// Close marks the device closed and unblocks pending ReadPacket callers.
func (m *Mem) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	m.closed = true
	close(m.in)
	return nil
}
