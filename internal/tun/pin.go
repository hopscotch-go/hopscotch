package tun

import "net"

// PhysicalGateway returns the underlay default gateway (Wi‑Fi/Ethernet),
// ignoring hopscotch /1 and interface-scoped utun defaults.
func PhysicalGateway(inet6 bool) net.IP {
	return physicalGateway(inet6)
}

// PinHost installs a host route for dst via the physical default gateway so
// underlay QUIC is not captured by exit-node /1 routes on the same machine.
// Loopback is a no-op. Revert removes the pin.
func PinHost(dst net.IP) (func() error, error) {
	if dst == nil || isLoopbackIP(dst) {
		return func() error { return nil }, nil
	}
	return pinHost(dst)
}
