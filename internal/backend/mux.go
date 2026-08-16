package backend

import (
	"errors"
	"net"
	"sync"
	"time"
)

type datagram struct {
	b    []byte
	addr net.Addr
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

// Mux is a net.PacketConn over a set of backend Sessions.
// quic.Transport sits on this, not on a raw TCP or UDP socket.
type Mux struct {
	local     net.Addr
	mu        sync.Mutex
	sessions  map[string]Session
	in        chan datagram
	closed    chan struct{}
	closeOnce sync.Once

	deadlineMu   sync.Mutex
	readDeadline time.Time
	deadlineWake chan struct{}
}

func NewMux(local net.Addr) *Mux {
	return &Mux{
		local:        local,
		sessions:     make(map[string]Session),
		in:           make(chan datagram, 64),
		closed:       make(chan struct{}),
		deadlineWake: make(chan struct{}, 1),
	}
}

func (m *Mux) Attach(s Session) {
	key := s.RemoteAddr().String()
	m.mu.Lock()
	if old, ok := m.sessions[key]; ok {
		if old == s {
			m.mu.Unlock()
			return
		}
		_ = old.Close()
	}
	m.sessions[key] = s
	m.mu.Unlock()
	go m.readLoop(s, key)
}

func (m *Mux) readLoop(s Session, key string) {
	defer func() {
		m.mu.Lock()
		if cur := m.sessions[key]; cur == s {
			delete(m.sessions, key)
		}
		m.mu.Unlock()
	}()
	for {
		select {
		case <-m.closed:
			return
		default:
		}
		b, err := s.Recv(time.Second)
		if errors.Is(err, ErrTimeout) {
			continue
		}
		if err != nil {
			return
		}
		select {
		case m.in <- datagram{b: b, addr: s.RemoteAddr()}:
		case <-m.closed:
			return
		}
	}
}

func (m *Mux) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		m.deadlineMu.Lock()
		dl := m.readDeadline
		m.deadlineMu.Unlock()

		if !dl.IsZero() && !time.Now().Before(dl) {
			return 0, nil, timeoutErr{}
		}

		var timer <-chan time.Time
		if !dl.IsZero() {
			tmr := time.NewTimer(time.Until(dl))
			timer = tmr.C
			select {
			case <-m.closed:
				tmr.Stop()
				return 0, nil, net.ErrClosed
			case d := <-m.in:
				tmr.Stop()
				return copy(p, d.b), d.addr, nil
			case <-timer:
				return 0, nil, timeoutErr{}
			case <-m.deadlineWake:
				tmr.Stop()
			}
			continue
		}

		select {
		case <-m.closed:
			return 0, nil, net.ErrClosed
		case d := <-m.in:
			return copy(p, d.b), d.addr, nil
		case <-m.deadlineWake:
		}
	}
}

func (m *Mux) WriteTo(p []byte, addr net.Addr) (int, error) {
	if addr == nil {
		return 0, errors.New("nil addr")
	}
	m.mu.Lock()
	s := m.sessions[addr.String()]
	m.mu.Unlock()
	if s == nil {
		return 0, errors.New("no backend session for " + addr.String())
	}
	if err := s.Send(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (m *Mux) LocalAddr() net.Addr { return m.local }

func (m *Mux) Close() error {
	m.closeOnce.Do(func() {
		close(m.closed)
		m.mu.Lock()
		defer m.mu.Unlock()
		for _, s := range m.sessions {
			_ = s.Close()
		}
		m.sessions = map[string]Session{}
	})
	return nil
}

func (m *Mux) SetDeadline(t time.Time) error {
	if err := m.SetReadDeadline(t); err != nil {
		return err
	}
	return m.SetWriteDeadline(t)
}

func (m *Mux) SetReadDeadline(t time.Time) error {
	m.deadlineMu.Lock()
	m.readDeadline = t
	m.deadlineMu.Unlock()
	select {
	case m.deadlineWake <- struct{}{}:
	default:
	}
	return nil
}

func (m *Mux) SetWriteDeadline(time.Time) error { return nil }

// Avoid quic-go's "not a UDPConn" buffer-size warning; this is not a socket.
func (m *Mux) SetReadBuffer(int) error  { return nil }
func (m *Mux) SetWriteBuffer(int) error { return nil }

var _ net.PacketConn = (*Mux)(nil)
