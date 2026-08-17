//go:build !darwin && !linux

package tun

import (
	"fmt"
	"net"
)

// Open reports that TUN is unsupported on this platform.
func Open() (Device, error) {
	return nil, fmt.Errorf("tun: not supported on this OS")
}

// Configure reports that TUN is unsupported on this platform.
func Configure(d Device, opts Opts) error {
	return fmt.Errorf("tun: not supported on this OS")
}

// InstallDNS is a no-op on platforms without TUN support.
func InstallDNS(string, int) (func() error, error) { return nil, nil }

func installDefaultRoutes(string, []PinRoute) (func() error, error) {
	return nil, fmt.Errorf("tun: not supported on this OS")
}

func physicalGateway(bool) net.IP { return nil }

func pinHost(net.IP) (func() error, error) {
	return nil, fmt.Errorf("tun: not supported on this OS")
}
