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

func (s *udpDialSession) LocalAddr() net.Addr  { return wrapAddr("udp", s.c.LocalAddr()) }
func (s *udpDialSession) RemoteAddr() net.Addr { return wrapAddr("udp", s.c.RemoteAddr()) }

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

func (s *udpDialSession) Close() error { return s.c.Close() }

type UDPListener struct {
	c      *net.UDPConn
	mu     sync.Mutex
	byAddr map[string]*udpListenSession
}

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

func (l *UDPListener) Addr() net.Addr { return l.c.LocalAddr() }

func (l *UDPListener) Close() error { return l.c.Close() }

func (l *UDPListener) Dial(_ context.Context, address string) (Session, error) {
	raddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, err
	}
	return l.session(raddr), nil
}

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

func newUDPListenSession(l *UDPListener, raddr *net.UDPAddr) *udpListenSession {
	return &udpListenSession{
		l:      l,
		raddr:  raddr,
		recv:   make(chan []byte, 32),
		closed: make(chan struct{}),
	}
}

func (s *udpListenSession) deliver(data []byte) {
	select {
	case s.recv <- data:
	case <-s.closed:
	default:
	}
}

func (s *udpListenSession) LocalAddr() net.Addr  { return wrapAddr("udp", s.l.c.LocalAddr()) }
func (s *udpListenSession) RemoteAddr() net.Addr { return wrapAddr("udp", s.raddr) }

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
