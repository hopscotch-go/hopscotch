//go:build !darwin && !linux

package tun

import (
	"fmt"
	"net"
)

func Open() (Device, error) {
	return nil, fmt.Errorf("tun: not supported on this OS")
}

func Configure(d Device, opts Opts) error {
	return fmt.Errorf("tun: not supported on this OS")
}

func InstallDNS(string, int) (func() error, error) { return nil, nil }
