//go:build linux

package tun

import (
	"fmt"
	"net"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"

	"github.com/hopscotch-go/hopscotch/internal/identity"
)

func InstallDNS(ifName string, _ int) (func() error, error) {
	ifi, err := net.InterfaceByName(ifName)
	if err != nil {
		return nil, err
	}
	idx := int32(ifi.Index)
	v6 := identity.ResolverULA().To16()
	if err := resolvedCall("org.freedesktop.resolve1.Manager.SetLinkDNS", idx, []resolvedAddr{
		{Family: unix.AF_INET6, Address: []byte(v6)},
	}); err != nil {
		return nil, err
	}
	if err := resolvedCall("org.freedesktop.resolve1.Manager.SetLinkDomains", idx, []resolvedDomain{{
		Name:        identity.NameURIScheme,
		RoutingOnly: false,
	}}); err != nil {
		_ = resolvedCall("org.freedesktop.resolve1.Manager.RevertLink", idx)
		return nil, err
	}
	if err := resolvedCall("org.freedesktop.resolve1.Manager.SetLinkDefaultRoute", idx, false); err != nil {
		_ = resolvedCall("org.freedesktop.resolve1.Manager.RevertLink", idx)
		return nil, err
	}
	_ = resolvedCall("org.freedesktop.resolve1.Manager.SetLinkLLMNR", idx, "no")
	_ = resolvedCall("org.freedesktop.resolve1.Manager.SetLinkMulticastDNS", idx, "no")
	return func() error {
		return resolvedCall("org.freedesktop.resolve1.Manager.RevertLink", idx)
	}, nil
}

type resolvedAddr struct {
	Family  int32
	Address []byte
}

type resolvedDomain struct {
	Name        string
	RoutingOnly bool
}

func resolvedCall(method string, args ...any) error {
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return fmt.Errorf("systemd-resolved: %w", err)
	}
	defer conn.Close()
	obj := conn.Object("org.freedesktop.resolve1", "/org/freedesktop/resolve1")
	c := obj.Call(method, 0, args...)
	if c.Err != nil {
		return fmt.Errorf("systemd-resolved: %w", c.Err)
	}
	return nil
}
