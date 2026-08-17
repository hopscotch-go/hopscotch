// Package socks implements a minimal SOCKS5 CONNECT proxy (no auth).
package socks

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	ver5       = 0x05
	cmdConnect = 0x01
	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04
	repSuccess = 0x00
	repGeneral = 0x01
	repHost    = 0x04
)

// DialFunc opens a TCP connection to host (name or IP) and port.
type DialFunc func(ctx context.Context, host string, port uint16) (net.Conn, error)

// Server is a SOCKS5 CONNECT listener.
type Server struct {
	Addr string
	Dial DialFunc
	Log  func(string, ...any)
}

// ListenAndServe accepts SOCKS5 clients until ln is closed.
func (s *Server) ListenAndServe(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handle(c)
	}
}

func (s *Server) handle(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	if err := s.handshake(c); err != nil {
		s.logf("socks handshake: %v", err)
		return
	}
	host, port, err := s.readRequest(c)
	if err != nil {
		s.logf("socks request: %v", err)
		_ = writeReply(c, repGeneral, nil, 0)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	remote, err := s.Dial(ctx, host, port)
	if err != nil {
		s.logf("socks dial %s:%d: %v", host, port, err)
		_ = writeReply(c, repHost, nil, 0)
		return
	}
	defer remote.Close()
	_ = c.SetDeadline(time.Time{})
	if err := writeReply(c, repSuccess, net.IPv4zero, 0); err != nil {
		return
	}
	s.logf("socks connected %s:%d", host, port)
	errc := make(chan error, 2)
	go proxyCopy(errc, c, remote)
	go proxyCopy(errc, remote, c)
	<-errc
}

func (s *Server) handshake(c net.Conn) error {
	var hdr [2]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return err
	}
	if hdr[0] != ver5 {
		return fmt.Errorf("version %d", hdr[0])
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return err
	}
	// no-auth only
	_, err := c.Write([]byte{ver5, 0x00})
	return err
}

func (s *Server) readRequest(c net.Conn) (host string, port uint16, err error) {
	var hdr [4]byte
	if _, err = io.ReadFull(c, hdr[:]); err != nil {
		return
	}
	if hdr[0] != ver5 || hdr[1] != cmdConnect {
		err = fmt.Errorf("unsupported cmd %d", hdr[1])
		return
	}
	switch hdr[3] {
	case atypIPv4:
		var a [4]byte
		if _, err = io.ReadFull(c, a[:]); err != nil {
			return
		}
		host = net.IP(a[:]).String()
	case atypIPv6:
		var a [16]byte
		if _, err = io.ReadFull(c, a[:]); err != nil {
			return
		}
		host = net.IP(a[:]).String()
	case atypDomain:
		var n [1]byte
		if _, err = io.ReadFull(c, n[:]); err != nil {
			return
		}
		b := make([]byte, n[0])
		if _, err = io.ReadFull(c, b); err != nil {
			return
		}
		host = string(b)
	default:
		err = fmt.Errorf("atyp %d", hdr[3])
		return
	}
	var pb [2]byte
	if _, err = io.ReadFull(c, pb[:]); err != nil {
		return
	}
	port = binary.BigEndian.Uint16(pb[:])
	return
}

func writeReply(c net.Conn, rep byte, ip net.IP, port uint16) error {
	if ip == nil {
		ip = net.IPv4zero
	}
	ip4 := ip.To4()
	var b []byte
	if ip4 != nil {
		b = []byte{ver5, rep, 0x00, atypIPv4}
		b = append(b, ip4...)
	} else {
		ip6 := ip.To16()
		b = []byte{ver5, rep, 0x00, atypIPv6}
		b = append(b, ip6...)
	}
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], port)
	b = append(b, pb[:]...)
	_, err := c.Write(b)
	return err
}

func proxyCopy(errc chan<- error, dst, src net.Conn) {
	_, err := io.Copy(dst, src)
	errc <- err
}

func (s *Server) logf(format string, args ...any) {
	if s.Log != nil {
		s.Log(format, args...)
	}
}
