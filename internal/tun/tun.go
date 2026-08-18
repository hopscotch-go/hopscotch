package tun

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
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
	IP           net.IP
	Gateway      bool       // unscoped fd00::/8 and overlay DNS
	DNSPort      int        // darwin stub; 0 means default 53
	DefaultRoute bool       // unused at Setup; exit_node installs /1+/1 later via InstallDefaultRoutes
	PlumbingIP   net.IP     // optional IPv4 for TUN sourcing (CGNAT plumbing)
	Exit         bool       // exit node: route plumbing CGNAT via TUN for return path
	PinGateways  []PinRoute // underlay host routes that must bypass TUN defaults
}

// PinRoute keeps underlay peer traffic off the exit default route.
// Gateway may be nil; the previous default gateway is used when pinning.
type PinRoute struct {
	Dst     net.IP
	Gateway net.IP
}

// isLoopbackIP reports whether ip is IPv4 loopback or IPv6 ::1.
// These must never be pinned via the LAN gateway — that breaks 127.0.0.1 peers.
func isLoopbackIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}

// skipTunnelDev reports whether a route should be ignored when picking the
// physical default gateway (hopscotch TUN and other tunnels).
func skipTunnelDev(name string) bool {
	return strings.Contains(name, "hopscotch") ||
		strings.HasPrefix(name, "tun") ||
		strings.HasPrefix(name, "utun")
}

// Setup opens a TUN device, configures addressing/routing, and optionally
// installs gateway DNS and netfilter hooks.
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

// InstallDefaultRoutes installs /1+/1 host defaults via ifName and pins
// underlay peers. Returns a revert func for Close / path-loss teardown.
func InstallDefaultRoutes(ifName string, pins []PinRoute) (func() error, error) {
	return installDefaultRoutes(ifName, pins)
}

// apply configures the device and returns a Close-time revert for gateway setup.
func apply(d Device, opts Opts) (func() error, error) {
	if err := Configure(d, opts); err != nil {
		return nil, rootHint(err)
	}
	var hooks []func() error
	rollback := func() {
		_ = combineHooks(hooks)()
	}
	if !opts.Gateway {
		return combineHooks(hooks), nil
	}
	if err := StripHopscotchHosts(); err != nil {
		rollback()
		return nil, rootHint(err)
	}
	revert, err := InstallDNS(d.Name(), opts.DNSPort)
	if err != nil {
		rollback()
		return nil, rootHint(err)
	}
	if revert != nil {
		hooks = append(hooks, revert)
	}
	if extra := gatewayNetFilter(d.Name()); extra != nil {
		hooks = append(hooks, extra)
	}
	return combineHooks(hooks), nil
}

func combineHooks(hooks []func() error) func() error {
	if len(hooks) == 0 {
		return nil
	}
	return func() error {
		var first error
		for i := len(hooks) - 1; i >= 0; i-- {
			if err := hooks[i](); err != nil && first == nil {
				first = err
			}
		}
		return first
	}
}

type withHooks struct {
	Device
	beforeClose func() error
}

// Close runs registered revert hooks, then closes the underlying device.
func (w *withHooks) Close() error {
	if w.beforeClose != nil {
		_ = w.beforeClose()
	}
	return w.Device.Close()
}

// rootHint annotates permission errors with a sudo hint for TUN setup.
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

// safeIfName reports whether name is a safe alphanumeric interface identifier.
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
