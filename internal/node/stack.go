package node

import (
	"context"
	"fmt"
	"net"

	"github.com/hopscotch-go/hopscotch/internal/netstack"
	"github.com/hopscotch-go/hopscotch/internal/tun"
)

// startUserspace attaches a gVisor IPv6 stack that dials/listens on this
// node's ULA and injects outbound packets into the overlay forward path.
func (n *Node) startUserspace() error {
	n.loadHostsFile()
	n.mu.Lock()
	if n.stack != nil {
		n.mu.Unlock()
		return nil
	}
	n.mu.Unlock()

	st, err := netstack.New(n.id.ULA(), tun.MTU, func(pkt []byte) {
		n.handlePacket(nil, pkt)
	})
	if err != nil {
		return fmt.Errorf("userspace: %w", err)
	}
	n.mu.Lock()
	n.stack = st
	n.mu.Unlock()
	n.log.Printf("userspace %s  gVisor IPv6 stack (no TUN required)", n.id.ULA())
	return nil
}

// deliverStack injects a locally destined overlay packet into the userspace stack.
func (n *Node) deliverStack(pkt []byte) {
	n.mu.Lock()
	st := n.stack
	n.mu.Unlock()
	if st != nil {
		st.Inject(pkt)
	}
}

// DialTCP opens a TCP connection to an overlay ULA via the userspace stack.
func (n *Node) DialTCP(ctx context.Context, ip net.IP, port uint16) (net.Conn, error) {
	n.mu.Lock()
	st := n.stack
	n.mu.Unlock()
	if st == nil {
		return nil, fmt.Errorf("userspace stack not enabled")
	}
	return st.DialTCP(ctx, ip, port)
}

// ListenTCP listens on this node's overlay ULA via the userspace stack.
func (n *Node) ListenTCP(port uint16) (net.Listener, error) {
	n.mu.Lock()
	st := n.stack
	n.mu.Unlock()
	if st == nil {
		return nil, fmt.Errorf("userspace stack not enabled")
	}
	return st.ListenTCP(port)
}
