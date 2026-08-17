package node

import (
	"encoding/binary"
	"net"

	"github.com/hopscotch-go/hopscotch/internal/identity"
)

const (
	defaultRouteV6 = "::/0"
	defaultRouteV4 = "0.0.0.0/0"

	nextHeaderIPv4 = 4  // IP-in-IP
	nextHeaderIPv6 = 41 // IPv6 encapsulation
)

// PlumbingIPv4 derives a CGNAT (100.64/10) address from a mesh ULA for TUN
// sourcing. It is local plumbing only — not a mesh identity.
func PlumbingIPv4(ula net.IP) net.IP {
	u := ula.To16()
	if u == nil {
		return nil
	}
	b3 := u[15]
	if b3 == 0 {
		b3 = 1
	}
	return net.IPv4(100, 64+(u[13]%64), u[14], b3)
}

// encapsulateExit wraps an inner IPv4/IPv6 packet in an outer mesh IPv6 header
// destined to exitULA (or client ULA on the return path).
func encapsulateExit(srcULA, dstULA net.IP, inner []byte) []byte {
	if len(inner) < 1 {
		return nil
	}
	src := srcULA.To16()
	dst := dstULA.To16()
	if src == nil || dst == nil {
		return nil
	}
	nh := byte(nextHeaderIPv6)
	if inner[0]>>4 == 4 {
		nh = nextHeaderIPv4
	} else if inner[0]>>4 != 6 {
		return nil
	}
	out := make([]byte, 40+len(inner))
	out[0] = 0x60
	binary.BigEndian.PutUint16(out[4:6], uint16(len(inner)))
	out[6] = nh
	out[7] = 64
	copy(out[8:24], src)
	copy(out[24:40], dst)
	copy(out[40:], inner)
	return out
}

// decapsulateExit returns the inner packet if pkt is an exit tunnel to ourULA.
func decapsulateExit(pkt []byte, ourULA net.IP) (clientULA net.IP, inner []byte, ok bool) {
	dst, _, ok := parseIPv6(pkt)
	if !ok || !dst.Equal(ourULA) || len(pkt) < 40 {
		return nil, nil, false
	}
	nh := pkt[6]
	if nh != nextHeaderIPv4 && nh != nextHeaderIPv6 {
		return nil, nil, false
	}
	src := append(net.IP(nil), pkt[8:24]...)
	if !identity.IsMeshULA(src) {
		return nil, nil, false
	}
	inner = pkt[40:]
	if len(inner) < 1 {
		return nil, nil, false
	}
	ver := inner[0] >> 4
	if nh == nextHeaderIPv4 && ver != 4 {
		return nil, nil, false
	}
	if nh == nextHeaderIPv6 && ver != 6 {
		return nil, nil, false
	}
	return src, inner, true
}

// isDefaultRouteDest reports whether dest is a DV default-route sentinel.
func isDefaultRouteDest(dest string) bool {
	return dest == defaultRouteV4 || dest == defaultRouteV6
}
