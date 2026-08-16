package backend

import "net"

// HopAddr is a net.Addr that includes the backend network so TCP and UDP
// sessions to the same host:port do not collide in the mux.
type HopAddr struct {
	Net  string
	Addr net.Addr
}

func (h HopAddr) Network() string { return h.Net }

func (h HopAddr) String() string {
	if h.Addr == nil {
		return h.Net
	}
	return h.Net + ":" + h.Addr.String()
}

func wrapAddr(network string, addr net.Addr) net.Addr {
	if addr == nil {
		return HopAddr{Net: network}
	}
	if _, ok := addr.(HopAddr); ok {
		return addr
	}
	return HopAddr{Net: network, Addr: addr}
}
