// Package netstack is a gVisor userspace IPv6 stack for overlay sockets
// without a kernel TUN.
package netstack

import (
	"context"
	"fmt"
	"net"
	"sync"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const nicID = 1

// Outbound delivers an IPv6 packet from the stack toward the overlay.
type Outbound func([]byte)

// Stack is a userspace IPv6 TCP/UDP/ICMPv6 endpoint for one overlay ULA.
type Stack struct {
	ip     net.IP
	stack  *stack.Stack
	ep     *channel.Endpoint
	cancel context.CancelFunc

	mu     sync.Mutex
	closed bool
}

// New builds a gVisor stack bound to ip (/128) and starts pumping outbound
// packets to out. MTU should match the overlay path (typically 1280).
func New(ip net.IP, mtu uint32, out Outbound) (*Stack, error) {
	ip = ip.To16()
	if ip == nil {
		return nil, fmt.Errorf("netstack: need IPv6 address")
	}
	if out == nil {
		return nil, fmt.Errorf("netstack: nil outbound")
	}
	if mtu < 1280 {
		mtu = 1280
	}

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol6},
	})
	ep := channel.New(512, mtu, "")
	if err := s.CreateNIC(nicID, ep); err != nil {
		return nil, fmt.Errorf("netstack: CreateNIC: %s", err)
	}
	if err := s.SetPromiscuousMode(nicID, true); err != nil {
		return nil, fmt.Errorf("netstack: promiscuous: %s", err)
	}
	if err := s.SetSpoofing(nicID, true); err != nil {
		return nil, fmt.Errorf("netstack: spoofing: %s", err)
	}
	protoAddr := tcpip.ProtocolAddress{
		Protocol: ipv6.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFromSlice(ip),
			PrefixLen: 128,
		},
	}
	if err := s.AddProtocolAddress(nicID, protoAddr, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("netstack: address: %s", err)
	}
	s.SetRouteTable([]tcpip.Route{{
		Destination: header.IPv6EmptySubnet,
		NIC:         nicID,
	}})

	ctx, cancel := context.WithCancel(context.Background())
	ns := &Stack{
		ip:     append(net.IP(nil), ip...),
		stack:  s,
		ep:     ep,
		cancel: cancel,
	}
	go ns.pumpOutbound(ctx, out)
	return ns, nil
}

// IP returns the overlay ULA assigned to this stack.
func (ns *Stack) IP() net.IP {
	return append(net.IP(nil), ns.ip...)
}

// Inject delivers an inbound overlay IPv6 packet into the userspace stack.
func (ns *Stack) Inject(pkt []byte) {
	if len(pkt) < header.IPv6MinimumSize || pkt[0]>>4 != 6 {
		return
	}
	ns.mu.Lock()
	closed := ns.closed
	ns.mu.Unlock()
	if closed {
		return
	}
	pb := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(append([]byte(nil), pkt...)),
	})
	ns.ep.InjectInbound(header.IPv6ProtocolNumber, pb)
	pb.DecRef()
}

// DialTCP opens a TCP connection to ip:port over the userspace stack.
func (ns *Stack) DialTCP(ctx context.Context, ip net.IP, port uint16) (net.Conn, error) {
	ip = ip.To16()
	if ip == nil {
		return nil, fmt.Errorf("netstack: dial needs IPv6")
	}
	ns.mu.Lock()
	closed := ns.closed
	ns.mu.Unlock()
	if closed {
		return nil, net.ErrClosed
	}
	addr := tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.AddrFromSlice(ip),
		Port: port,
	}
	return gonet.DialContextTCP(ctx, ns.stack, addr, ipv6.ProtocolNumber)
}

// ListenTCP listens on port of this stack's ULA.
func (ns *Stack) ListenTCP(port uint16) (net.Listener, error) {
	ns.mu.Lock()
	closed := ns.closed
	ns.mu.Unlock()
	if closed {
		return nil, net.ErrClosed
	}
	addr := tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.AddrFromSlice(ns.ip),
		Port: port,
	}
	return gonet.ListenTCP(ns.stack, addr, ipv6.ProtocolNumber)
}

// Close tears down the stack and stops the outbound pump.
func (ns *Stack) Close() {
	ns.mu.Lock()
	if ns.closed {
		ns.mu.Unlock()
		return
	}
	ns.closed = true
	ns.mu.Unlock()
	ns.cancel()
	ns.ep.Close()
	ns.stack.Close()
}

func (ns *Stack) pumpOutbound(ctx context.Context, out Outbound) {
	for {
		pkt := ns.ep.ReadContext(ctx)
		if pkt == nil {
			return
		}
		view := pkt.ToView()
		if view != nil {
			b := view.ToSlice()
			view.Release()
			if len(b) > 0 {
				out(b)
			}
		}
		pkt.DecRef()
	}
}
