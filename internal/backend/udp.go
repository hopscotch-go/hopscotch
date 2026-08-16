package backend

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

const udpMax = 65507

// UDPDialer opens a connected UDP socket from an ephemeral local port.
type UDPDialer struct{}

// Dial opens a connected UDP session to address.
func (UDPDialer) Dial(ctx context.Context, address string) (Session, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp", address)
	if err != nil {
		return nil, err
	}
	uc, ok := c.(*net.UDPConn)
	if !ok {
		_ = c.Close()
		return nil, fmt.Errorf("udp dial did not return UDPConn")
	}
	return &udpDialSession{c: uc}, nil
}

type udpDialSession struct {
	c *net.UDPConn
}

// LocalAddr returns the local address of the dialed UDP session.
func (s *udpDialSession) LocalAddr() net.Addr { return wrapAddr("udp", s.c.LocalAddr()) }

// RemoteAddr returns the remote address of the dialed UDP session.
func (s *udpDialSession) RemoteAddr() net.Addr { return wrapAddr("udp", s.c.RemoteAddr()) }

// Send writes one datagram on the connected UDP socket.
func (s *udpDialSession) Send(data []byte) error {
	if len(data) > udpMax {
		return fmt.Errorf("udp payload too large")
	}
	n, err := s.c.Write(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return fmt.Errorf("partial udp write")
	}
	return nil
}

// Recv reads one datagram, or ErrTimeout if none arrives in time.
func (s *udpDialSession) Recv(timeout time.Duration) ([]byte, error) {
	if err := s.c.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	buf := make([]byte, udpMax)
	n, err := s.c.Read(buf)
	if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
		return nil, ErrTimeout
	}
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), buf[:n]...), nil
}

// Close closes the connected UDP socket.
func (s *udpDialSession) Close() error { return s.c.Close() }

type UDPListener struct {
	c      *net.UDPConn
	mu     sync.Mutex
	byAddr map[string]*udpListenSession
}

// NewUDPListener binds a UDP socket and tracks per-peer sessions.
func NewUDPListener(address string) (*UDPListener, error) {
	addr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, err
	}
	c, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}
	return &UDPListener{c: c, byAddr: make(map[string]*udpListenSession)}, nil
}

// Addr returns the listener's local UDP address.
func (l *UDPListener) Addr() net.Addr { return l.c.LocalAddr() }

// Close shuts down the UDP listener socket.
func (l *UDPListener) Close() error { return l.c.Close() }

// Dial returns a session for sending to address on the shared listen socket.
func (l *UDPListener) Dial(_ context.Context, address string) (Session, error) {
	raddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, err
	}
	return l.session(raddr), nil
}

// session returns the existing or newly created per-peer listen session.
func (l *UDPListener) session(raddr *net.UDPAddr) *udpListenSession {
	key := raddr.String()
	l.mu.Lock()
	defer l.mu.Unlock()
	if sess, ok := l.byAddr[key]; ok {
		return sess
	}
	sess := newUDPListenSession(l, raddr)
	l.byAddr[key] = sess
	return sess
}

// Start demuxes inbound UDP packets into per-peer sessions until ctx is done.
func (l *UDPListener) Start(ctx context.Context) (<-chan Session, error) {
	ch := make(chan Session)
	go func() {
		defer close(ch)
		buf := make([]byte, udpMax)
		for {
			_ = l.c.SetReadDeadline(time.Now().Add(time.Second))
			n, addr, err := l.c.ReadFromUDP(buf)
			if ctx.Err() != nil {
				return
			}
			if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
				continue
			}
			if err != nil {
				return
			}
			data := append([]byte(nil), buf[:n]...)
			key := addr.String()
			l.mu.Lock()
			sess, exists := l.byAddr[key]
			if !exists {
				sess = newUDPListenSession(l, addr)
				l.byAddr[key] = sess
			}
			l.mu.Unlock()
			if !exists {
				select {
				case ch <- sess:
				case <-ctx.Done():
					return
				}
			}
			sess.deliver(data)
		}
	}()
	return ch, nil
}

type udpListenSession struct {
	l         *UDPListener
	raddr     *net.UDPAddr
	recv      chan []byte
	closed    chan struct{}
	closeOnce sync.Once
}

// newUDPListenSession creates a per-peer session backed by the shared UDP listener.
func newUDPListenSession(l *UDPListener, raddr *net.UDPAddr) *udpListenSession {
	return &udpListenSession{
		l:      l,
		raddr:  raddr,
		recv:   make(chan []byte, 32),
		closed: make(chan struct{}),
	}
}

// deliver queues an inbound datagram for Recv, dropping if the session is closed or full.
func (s *udpListenSession) deliver(data []byte) {
	select {
	case s.recv <- data:
	case <-s.closed:
	default:
	}
}

// LocalAddr returns the listener's local address for this peer session.
func (s *udpListenSession) LocalAddr() net.Addr { return wrapAddr("udp", s.l.c.LocalAddr()) }

// RemoteAddr returns the peer address for this listen session.
func (s *udpListenSession) RemoteAddr() net.Addr { return wrapAddr("udp", s.raddr) }

// Send writes a datagram to this session's peer via the shared UDP socket.
func (s *udpListenSession) Send(data []byte) error {
	n, err := s.l.c.WriteToUDP(data, s.raddr)
	if err != nil {
		return err
	}
	if n != len(data) {
		return fmt.Errorf("partial udp write")
	}
	return nil
}

// Recv waits for the next queued datagram, or ErrTimeout if none arrives in time.
func (s *udpListenSession) Recv(timeout time.Duration) ([]byte, error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case b := <-s.recv:
		return b, nil
	case <-s.closed:
		return nil, net.ErrClosed
	case <-timer.C:
		return nil, ErrTimeout
	}
}

// Close marks the peer session closed and removes it from the listener map.
func (s *udpListenSession) Close() error {
	s.closeOnce.Do(func() { close(s.closed) })
	s.l.mu.Lock()
	if cur := s.l.byAddr[s.raddr.String()]; cur == s {
		delete(s.l.byAddr, s.raddr.String())
	}
	s.l.mu.Unlock()
	return nil
}

var _ Session = (*udpDialSession)(nil)
var _ Session = (*udpListenSession)(nil)
var _ Dialer = (*UDPListener)(nil)
