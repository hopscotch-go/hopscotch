//go:build !linux

package node

import "fmt"

// writeExitEgress injects a packet into the TUN (userspace/macOS exit path).
func (n *Node) writeExitEgress(inner []byte) error {
	n.mu.Lock()
	d := n.tun
	n.mu.Unlock()
	if d == nil {
		return fmt.Errorf("exit: no tun")
	}
	return d.WritePacket(inner)
}

// setupExitNAT records that this exit uses TUN+host forwarding (no nft on this OS).
func (n *Node) setupExitNAT(ifName string) (func() error, error) {
	n.log.Printf("exit      userspace/TUN egress on %s (enable IP forwarding for SNAT)", ifName)
	return func() error { return nil }, nil
}
