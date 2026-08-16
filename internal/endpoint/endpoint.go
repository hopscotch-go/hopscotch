package endpoint

import (
	"fmt"
	"net"
	"strings"
)

type Endpoint struct {
	Network string // "udp" or "tcp"
	Addr    string // host:port
}

func (e Endpoint) String() string {
	return e.Network + ":" + e.Addr
}

func Parse(s, defaultNet string) (Endpoint, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Endpoint{}, fmt.Errorf("empty endpoint")
	}
	if defaultNet == "" {
		defaultNet = "udp"
	}
	network, addr := defaultNet, s
	switch {
	case strings.HasPrefix(s, "tcp:"):
		network, addr = "tcp", strings.TrimPrefix(s, "tcp:")
	case strings.HasPrefix(s, "udp:"):
		network, addr = "udp", strings.TrimPrefix(s, "udp:")
	}
	if network != "tcp" && network != "udp" {
		return Endpoint{}, fmt.Errorf("network %q: want udp or tcp", network)
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return Endpoint{}, fmt.Errorf("addr %q: %w", addr, err)
	}
	return Endpoint{Network: network, Addr: addr}, nil
}

func Host(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}
