package node

import (
	"net"

	"github.com/hopscotch-go/hopscotch/internal/identity"
)

// egressExit sends an unwrapped internet packet out of this exit node and
// remembers the client ULA for the return path.
func (n *Node) egressExit(clientULA net.IP, inner []byte) {
	if len(inner) == 0 || clientULA == nil {
		return
	}
	n.rememberExitClient(clientULA)
	if n.cfg.LogOverlay {
		n.log.Printf("exit egress client=%s ver=%d len=%d", clientULA, inner[0]>>4, len(inner))
	}
	if err := n.writeExitEgress(inner); err != nil {
		n.log.Printf("exit egress: %v", err)
	}
}

func (n *Node) rememberExitClient(clientULA net.IP) {
	pl := PlumbingIPv4(clientULA)
	n.exitMu.Lock()
	if n.exitClients == nil {
		n.exitClients = make(map[string]net.IP)
	}
	n.exitClients[pl.String()] = append(net.IP(nil), clientULA.To16()...)
	n.exitMu.Unlock()
}

func (n *Node) clientULAForPlumbing(ip net.IP) net.IP {
	n.exitMu.Lock()
	defer n.exitMu.Unlock()
	if n.exitClients == nil {
		return nil
	}
	u := n.exitClients[ip.String()]
	if u == nil {
		return nil
	}
	return append(net.IP(nil), u...)
}

// handleExitTUNIngress processes packets read from the TUN on an exit node
// (return traffic after kernel un-SNAT, or userspace-injected).
func (n *Node) handleExitTUNIngress(pkt []byte) bool {
	if !n.cfg.Exit || len(pkt) == 0 {
		return false
	}
	ver := pkt[0] >> 4
	var clientULA net.IP
	switch ver {
	case 4:
		if len(pkt) < 20 {
			return true
		}
		dst := net.IP(pkt[16:20])
		clientULA = n.clientULAForPlumbing(dst)
		if clientULA == nil {
			// May be our own plumbing or unrelated; try match against known ULAs.
			for _, s := range n.sessionList() {
				if PlumbingIPv4(s.id.ULA()).Equal(dst) {
					clientULA = s.id.ULA()
					break
				}
			}
		}
	case 6:
		dst, _, ok := parseIPv6(pkt)
		if !ok || identity.IsMeshULA(dst) {
			return false // normal mesh delivery
		}
		// Global IPv6 reply destined somewhere — find client by plumbing... v6
		// return uses conntrack via userspace or kernel; for kernel path dst is
		// typically not the client ULA. Fall through to userspace map by dst.
		return false
	default:
		return true
	}
	if clientULA == nil {
		return true
	}
	outer := encapsulateExit(n.id.ULA(), clientULA, pkt)
	if outer == nil {
		return true
	}
	n.handleIPv6(nil, outer)
	return true
}
