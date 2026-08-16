package tun

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
)

// MTU is the overlay IPv6 MTU. IPv6 forbids a link MTU below 1280.
// Packets that do not fit a QUIC datagram are sent on a uni-stream.
const MTU = 1280

type Device interface {
	Name() string
	ReadPacket() ([]byte, error)
	WritePacket([]byte) error
	Close() error
}

type Opts struct {
	IP      net.IP
	Gateway bool // unscoped fd00::/8 and overlay DNS
	DNSPort int  // darwin stub; 0 means default 53
}

func Setup(opts Opts) (Device, error) {
	d, err := Open()
	if err != nil {
		return nil, rootHint(err)
	}
	revert, err := apply(d, opts)
	if err != nil {
		_ = d.Close()
		return nil, err
	}
	if revert != nil {
		return &withHooks{Device: d, beforeClose: revert}, nil
	}
	return d, nil
}

func apply(d Device, opts Opts) (func() error, error) {
	if err := Configure(d, opts); err != nil {
		return nil, rootHint(err)
	}
	if !opts.Gateway {
		return nil, nil
	}
	if err := StripHopscotchHosts(); err != nil {
		return nil, rootHint(err)
	}
	var hooks []func() error
	revert, err := InstallDNS(d.Name(), opts.DNSPort)
	if err != nil {
		return nil, rootHint(err)
	}
	if revert != nil {
		hooks = append(hooks, revert)
	}
	if extra := gatewayNetFilter(d.Name()); extra != nil {
		hooks = append(hooks, extra)
	}
	if len(hooks) == 0 {
		return nil, nil
	}
	return func() error {
		var first error
		for i := len(hooks) - 1; i >= 0; i-- {
			if err := hooks[i](); err != nil && first == nil {
				first = err
			}
		}
		return first
	}, nil
}

type withHooks struct {
	Device
	beforeClose func() error
}

func (w *withHooks) Close() error {
	if w.beforeClose != nil {
		_ = w.beforeClose()
	}
	return w.Device.Close()
}

func rootHint(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, os.ErrPermission) {
		return fmt.Errorf("%w (need root: sudo ./hopscotch --tun)", err)
	}
	var errno syscall.Errno
	if errors.As(err, &errno) && (errno == syscall.EPERM || errno == syscall.EACCES) {
		return fmt.Errorf("%w (need root: sudo ./hopscotch --tun)", err)
	}
	return err
}

func safeIfName(name string) bool {
	if name == "" {
		return false
	}
	for _, c := range name {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' {
			continue
		}
		return false
	}
	return true
}
