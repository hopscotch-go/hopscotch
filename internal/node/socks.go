package node

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/hopscotch-go/hopscotch/internal/identity"
	"github.com/hopscotch-go/hopscotch/internal/socks"
)

// startSocks starts a local SOCKS5 CONNECT proxy that dials overlay ULAs
// through the userspace stack. Implies userspace if not already enabled.
func (n *Node) startSocks() error {
	if n.cfg.Socks == "" {
		return nil
	}
	if n.stack == nil {
		if err := n.startUserspace(); err != nil {
			return err
		}
	}
	ln, err := net.Listen("tcp", n.cfg.Socks)
	if err != nil {
		return fmt.Errorf("socks: %w", err)
	}
	n.mu.Lock()
	n.socksLn = ln
	n.mu.Unlock()
	s := &socks.Server{
		Dial: n.socksDial,
		Log:  n.log.Printf,
	}
	go func() {
		_ = s.ListenAndServe(ln)
	}()
	n.log.Printf("socks     %s  (CONNECT via userspace overlay)", ln.Addr())
	return nil
}

// socksDial resolves a SOCKS target to an overlay ULA and dials via gVisor.
func (n *Node) socksDial(ctx context.Context, host string, port uint16) (net.Conn, error) {
	ip, err := n.resolveSocksHost(host)
	if err != nil {
		return nil, err
	}
	return n.DialTCP(ctx, ip, port)
}

// resolveSocksHost maps a SOCKS host to a mesh ULA (literal, name, or name.hopscotch).
func (n *Node) resolveSocksHost(host string) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if !identity.IsMeshULA(ip) {
			return nil, fmt.Errorf("not a mesh ULA: %s", host)
		}
		return ip.To16(), nil
	}
	name := strings.ToLower(host)
	if cut, ok := strings.CutSuffix(name, "."+identity.NameURIScheme); ok {
		name = cut
	}
	name = strings.TrimSuffix(name, ".")
	parsed, err := identity.ParseName(name)
	if err != nil {
		return nil, err
	}
	ip := n.overlayIP(parsed)
	if ip == nil {
		return nil, fmt.Errorf("unknown overlay name %q", parsed)
	}
	return ip, nil
}
