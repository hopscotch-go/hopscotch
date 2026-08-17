package node

import (
	"net"

	"github.com/hopscotch-go/hopscotch/internal/endpoint"
	"github.com/hopscotch-go/hopscotch/internal/tun"
)

type underlayPin struct {
	refs   int
	revert func() error
}

func underlayIPFromAddr(addr string) net.IP {
	ep, err := endpoint.Parse(addr, "udp")
	if err == nil {
		addr = ep.Addr
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			return nil
		}
		ip = ips[0]
	}
	if ip.IsLoopback() {
		return nil
	}
	return ip
}

func underlayIPFromNetAddr(addr net.Addr) net.IP {
	if addr == nil {
		return nil
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsLoopback() {
		return nil
	}
	return ip
}

func (n *Node) retainUnderlayPin(ip net.IP) {
	if ip == nil {
		return
	}
	key := ip.String()
	n.exitMu.Lock()
	if n.underlayPins == nil {
		n.underlayPins = make(map[string]*underlayPin)
	}
	if p := n.underlayPins[key]; p != nil {
		p.refs++
		n.exitMu.Unlock()
		return
	}
	n.exitMu.Unlock()

	revert, err := tun.PinHost(ip)
	if err != nil {
		n.log.Printf("underlay pin %s: %v", ip, err)
		return
	}

	n.exitMu.Lock()
	if p := n.underlayPins[key]; p != nil {
		p.refs++
		n.exitMu.Unlock()
		_ = revert()
		return
	}
	n.underlayPins[key] = &underlayPin{refs: 1, revert: revert}
	n.exitMu.Unlock()
	n.log.Printf("underlay pin %s via physical gateway", ip)
}

func (n *Node) releaseUnderlayPin(ip net.IP) {
	if ip == nil {
		return
	}
	key := ip.String()
	n.exitMu.Lock()
	p := n.underlayPins[key]
	if p == nil {
		n.exitMu.Unlock()
		return
	}
	p.refs--
	if p.refs > 0 {
		n.exitMu.Unlock()
		return
	}
	delete(n.underlayPins, key)
	revert := p.revert
	n.exitMu.Unlock()
	if revert != nil {
		_ = revert()
	}
}

func (n *Node) clearUnderlayPins() {
	n.exitMu.Lock()
	pins := n.underlayPins
	n.underlayPins = nil
	n.exitMu.Unlock()
	for _, p := range pins {
		if p != nil && p.revert != nil {
			_ = p.revert()
		}
	}
}
