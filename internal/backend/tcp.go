package backend

import (
	"context"
	"io"
	"net"
	"time"
)

type TCPDialer struct{}

// Dial opens a length-prefixed TCP session to address.
func (TCPDialer) Dial(ctx context.Context, address string) (Session, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	return newTCPSession(c), nil
}

type TCPListener struct {
	ln *net.TCPListener
}

// NewTCPListener binds a TCP listener on address.
func NewTCPListener(address string) (*TCPListener, error) {
	addr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		return nil, err
	}
	ln, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return nil, err
	}
	return &TCPListener{ln: ln}, nil
}

// Addr returns the listener's local address.
func (l *TCPListener) Addr() net.Addr { return l.ln.Addr() }

// Close shuts down the TCP listener.
func (l *TCPListener) Close() error { return l.ln.Close() }

// Start accepts inbound TCP connections and emits Session values until ctx is done.
func (l *TCPListener) Start(ctx context.Context) (<-chan Session, error) {
	ch := make(chan Session)
	go func() {
		defer close(ch)
		for {
			_ = l.ln.SetDeadline(time.Now().Add(time.Second))
			c, err := l.ln.AcceptTCP()
			if ctx.Err() != nil {
				return
			}
			if err != nil {
				if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
					continue
				}
				return
			}
			select {
			case ch <- newTCPSession(c):
			case <-ctx.Done():
				_ = c.Close()
				return
			}
		}
	}()
	return ch, nil
}

type tcpSession struct {
	c      net.Conn
	framer StreamFramer
}

// newTCPSession wraps a TCP connection as a framed Session.
func newTCPSession(c net.Conn) *tcpSession {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	return &tcpSession{c: c}
}

// LocalAddr returns the local address of the TCP session.
func (s *tcpSession) LocalAddr() net.Addr { return wrapAddr("tcp", s.c.LocalAddr()) }

// RemoteAddr returns the remote address of the TCP session.
func (s *tcpSession) RemoteAddr() net.Addr { return wrapAddr("tcp", s.c.RemoteAddr()) }

// Send writes a length-prefixed datagram on the TCP connection.
func (s *tcpSession) Send(data []byte) error {
	buf, err := EncodeFrame(data)
	if err != nil {
		return err
	}
	_, err = s.c.Write(buf)
	return err
}

// Recv reads the next length-prefixed datagram, or ErrTimeout if none arrives in time.
func (s *tcpSession) Recv(timeout time.Duration) ([]byte, error) {
	buf := make([]byte, 64*1024)
	for {
		if err := s.framer.Err(); err != nil {
			return nil, err
		}
		if s.framer.HasFrame() {
			return s.framer.NextFrame()
		}
		if err := s.c.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return nil, err
		}
		n, err := s.c.Read(buf)
		if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
			if n > 0 {
				s.framer.Write(buf[:n])
				continue
			}
			return nil, ErrTimeout
		}
		if n > 0 {
			s.framer.Write(buf[:n])
		}
		if err != nil {
			if err == io.EOF && s.framer.HasFrame() {
				return s.framer.NextFrame()
			}
			if err == io.EOF {
				return nil, err
			}
			return nil, err
		}
	}
}

// Close closes the underlying TCP connection.
func (s *tcpSession) Close() error {
	return s.c.Close()
}

var _ Session = (*tcpSession)(nil)
