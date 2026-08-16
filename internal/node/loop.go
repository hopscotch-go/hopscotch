package node

import (
	"encoding/binary"
	"net"
	"time"

	"github.com/hopscotch-go/hopscotch/internal/identity"
)

// flowSight remembers the last forward of a packet flow at this node.
// Seeing the same ingress→egress again with a lower Hop Limit means the
// packet is circling the session graph under greedy XOR.
type flowSight struct {
	fromID identity.NodeID
	nextID identity.NodeID
	hop    int
	at     time.Time
}

const (
	flowSightTTL = 2 * time.Second
	flowSightMax = 4096
	loopLogEvery = 32 // log first + every Nth detection
)

func flowKey(pkt []byte) uint64 {
	if len(pkt) < ipv6HeaderLen {
		return 0
	}
	h := fnv64(pkt[8:40]) // src+dst
	switch pkt[6] {
	case nextHeaderICMPv6:
		if len(pkt) >= ipv6HeaderLen+8 {
			h ^= uint64(pkt[ipv6HeaderLen]) << 56 // type
			h ^= uint64(binary.BigEndian.Uint32(pkt[ipv6HeaderLen+4 : ipv6HeaderLen+8]))
		}
	case nextHeaderUDP, nextHeaderTCP:
		if len(pkt) >= ipv6HeaderLen+4 {
			h ^= uint64(binary.BigEndian.Uint32(pkt[ipv6HeaderLen : ipv6HeaderLen+4]))
		}
	default:
		if len(pkt) > ipv6HeaderLen {
			n := ipv6HeaderLen + 8
			if n > len(pkt) {
				n = len(pkt)
			}
			h ^= fnv64(pkt[ipv6HeaderLen:n])
		}
	}
	return h
}

func fnv64(b []byte) uint64 {
	var h uint64 = 14695981039346656037
	for _, c := range b {
		h ^= uint64(c)
		h *= 1099511628211
	}
	return h
}

func (n *Node) noteOverlayForward(from, next *session, pkt []byte, hopAfterDec int) {
	if next == nil || len(pkt) < ipv6HeaderLen {
		return
	}
	key := flowKey(pkt)
	var fromID identity.NodeID
	if from != nil {
		fromID = from.id
	}
	nextID := next.id
	now := time.Now()

	n.flowMu.Lock()
	if n.flowSight == nil {
		n.flowSight = make(map[uint64]flowSight)
	}
	prev, ok := n.flowSight[key]
	loop := ok && prev.fromID == fromID && prev.nextID == nextID && hopAfterDec < prev.hop && now.Sub(prev.at) < flowSightTTL
	n.flowSight[key] = flowSight{fromID: fromID, nextID: nextID, hop: hopAfterDec, at: now}
	if len(n.flowSight) > flowSightMax {
		for k, v := range n.flowSight {
			if now.Sub(v.at) > flowSightTTL {
				delete(n.flowSight, k)
			}
		}
		if len(n.flowSight) > flowSightMax {
			n.flowSight = map[uint64]flowSight{key: n.flowSight[key]}
		}
	}
	n.flowMu.Unlock()

	if n.cfg.LogOverlay {
		fromLabel := "tun"
		if from != nil {
			fromLabel = peerLabel(from.id, from.names)
		}
		n.log.Printf("overlay fwd dst=%s from=%s to=%s hlim=%d",
			net.IP(pkt[24:40]), fromLabel, peerLabel(next.id, next.names), hopAfterDec)
	}
	if !loop {
		return
	}
	c := n.overlayLoops.Add(1)
	if c == 1 || c%loopLogEvery == 0 {
		fromLabel := "tun"
		if from != nil {
			fromLabel = peerLabel(from.id, from.names)
		}
		n.log.Printf("overlay loop dst=%s from=%s next=%s hlim=%d count=%d (greedy XOR revisiting the same edge)",
			net.IP(pkt[24:40]), fromLabel, peerLabel(next.id, next.names), hopAfterDec, c)
	}
}

// OverlayLoopCount is how many times this node has forwarded the same
// flow along the same ingress→egress edge with a decreasing Hop Limit.
func (n *Node) OverlayLoopCount() uint64 {
	return n.overlayLoops.Load()
}
