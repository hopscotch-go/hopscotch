package node

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/hopscotch-go/hopscotch/internal/identity"
	"github.com/hopscotch-go/hopscotch/internal/tun"
)

// TraceHop is one TTL probe in an overlay traceroute.
type TraceHop struct {
	TTL     int
	Name    string
	ULA     string
	RTT     time.Duration
	Timeout bool
	Reply   string // "time_exceeded", "echo_reply", or ""
}

// TraceResult is the full overlay traceroute toward a ULA or name.
type TraceResult struct {
	Dst   string
	Hops  []TraceHop
	Reach bool
}

// TraceRoute sends ICMPv6 echoes with increasing Hop Limit and records
// which node answers Time Exceeded or Echo Reply. This follows the
// distance-vector RIB — the same path as ping6 — not named-echo flood.
// dest may be a mesh ULA or an overlay name known from self/sessions.
func (n *Node) TraceRoute(ctx context.Context, dest string, maxTTL int) (TraceResult, error) {
	dstIP, err := n.ResolveULA(ctx, dest)
	if err != nil {
		return TraceResult{}, err
	}
	if maxTTL <= 0 {
		maxTTL = 32
	}
	if maxTTL > 255 {
		maxTTL = 255
	}

	tap := make(chan []byte, 8)
	n.setPacketTap(tap)
	defer n.setPacketTap(nil)

	// Ensure local delivery has somewhere to land if no TUN is attached.
	var mem *tun.Mem
	n.mu.Lock()
	haveTun := n.tun != nil
	n.mu.Unlock()
	if !haveTun {
		mem = tun.NewMem()
		n.AttachTun(mem)
		defer func() {
			n.mu.Lock()
			if n.tun == mem {
				n.tun = nil
			}
			n.mu.Unlock()
			_ = mem.Close()
		}()
	}

	out := TraceResult{Dst: dest, Hops: make([]TraceHop, 0, maxTTL)}
	src := n.id.ULA()
	for ttl := 1; ttl <= maxTTL; ttl++ {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		// Drain tap of stale packets.
		for {
			select {
			case <-tap:
			default:
				goto drained
			}
		}
	drained:
		pkt := ipv6ICMPEchoTrace(src, dstIP, uint8(ttl), uint16(ttl))
		start := time.Now()
		n.handlePacket(nil, pkt)

		hop := TraceHop{TTL: ttl}
		deadline := time.NewTimer(800 * time.Millisecond)
		wait := true
		for wait {
			select {
			case <-ctx.Done():
				deadline.Stop()
				return out, ctx.Err()
			case <-deadline.C:
				hop.Timeout = true
				wait = false
			case reply := <-tap:
				if len(reply) < ipv6HeaderLen+1 {
					continue
				}
				if !net.IP(reply[24:40]).Equal(src) {
					continue // not for us
				}
				hop.RTT = time.Since(start)
				hop.ULA = net.IP(reply[8:24]).String()
				hop.Name = n.nameForULA(net.IP(reply[8:24]))
				switch reply[40] {
				case icmpv6TimeExceeded:
					hop.Reply = "time_exceeded"
					wait = false
				case icmpv6EchoReply:
					hop.Reply = "echo_reply"
					out.Reach = true
					wait = false
				case icmpv6DestUnreach:
					hop.Reply = "dest_unreach"
					wait = false
				default:
					continue
				}
			}
		}
		deadline.Stop()
		out.Hops = append(out.Hops, hop)
		if out.Reach {
			break
		}
	}
	return out, nil
}

// setPacketTap installs or clears a channel that receives locally delivered overlay packets.
func (n *Node) setPacketTap(ch chan []byte) {
	n.mu.Lock()
	n.pktTap = ch
	n.mu.Unlock()
}

// tapPacket non-blocking copies pkt to the packet tap if set.
func (n *Node) tapPacket(pkt []byte) {
	n.mu.Lock()
	ch := n.pktTap
	n.mu.Unlock()
	if ch == nil {
		return
	}
	select {
	case ch <- append([]byte(nil), pkt...):
	default:
	}
}

// ResolveULA maps a mesh ULA literal or overlay name to a ULA.
// Names unknown from self/sessions are resolved with a named-echo flood.
func (n *Node) ResolveULA(ctx context.Context, dest string) (net.IP, error) {
	if ip := net.ParseIP(dest); ip != nil {
		if !identity.IsMeshULA(ip) {
			return nil, fmt.Errorf("not a mesh ULA: %s", dest)
		}
		return ip.To16(), nil
	}
	name := strings.ToLower(dest)
	if cut, ok := strings.CutSuffix(name, "."+identity.NameURIScheme); ok {
		name = cut
	}
	name = strings.TrimSuffix(name, ".")
	parsed, err := identity.ParseName(name)
	if err != nil {
		return nil, err
	}
	if ip := n.overlayIP(parsed); ip != nil {
		return ip, nil
	}
	got, err := n.Echo(ctx, parsed)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(got.ULA)
	if ip == nil || !identity.IsMeshULA(ip) {
		return nil, fmt.Errorf("resolve %q: no ULA in echo reply", parsed)
	}
	return ip.To16(), nil
}

// resolveOverlayDest maps a mesh ULA literal or overlay name using local
// knowledge only (self + live sessions). Prefer ResolveULA when a mesh
// probe is acceptable.
func (n *Node) resolveOverlayDest(dest string) (net.IP, error) {
	if ip := net.ParseIP(dest); ip != nil {
		if !identity.IsMeshULA(ip) {
			return nil, fmt.Errorf("not a mesh ULA: %s", dest)
		}
		return ip.To16(), nil
	}
	name := strings.ToLower(dest)
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
		return nil, fmt.Errorf("unknown name %q (no self/session ULA)", parsed)
	}
	return ip, nil
}

// nameForULA resolves a mesh ULA to a self or live peer name.
func (n *Node) nameForULA(ula net.IP) string {
	if ula.Equal(n.id.ULA()) {
		return n.hopName()
	}
	for _, s := range n.sessionList() {
		if s.id.ULA().Equal(ula) {
			if len(s.names) > 0 {
				return s.names[0]
			}
			return s.id.Short()
		}
	}
	return ""
}

// ipv6ICMPEchoTrace builds an overlay ICMPv6 echo with the given Hop Limit.
func ipv6ICMPEchoTrace(src, dst net.IP, hop uint8, seq uint16) []byte {
	p := make([]byte, 56)
	p[0] = 0x60
	p[4], p[5] = 0, 16
	p[6] = nextHeaderICMPv6
	p[7] = hop
	copy(p[8:24], src.To16())
	copy(p[24:40], dst.To16())
	p[40] = icmpv6EchoRequest
	p[44], p[45] = 0x74, 0x72 // 'tr'
	p[46] = byte(seq >> 8)
	p[47] = byte(seq)
	sum := icmpv6Checksum(p)
	p[42] = byte(sum >> 8)
	p[43] = byte(sum)
	return p
}
