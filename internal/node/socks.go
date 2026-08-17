package node

import (
	"context"
	"fmt"
	"net"

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
	ip, err := n.ResolveULA(ctx, host)
	if err != nil {
		return nil, err
	}
	return n.DialTCP(ctx, ip, port)
}
