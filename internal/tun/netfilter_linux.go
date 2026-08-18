//go:build linux

package tun

import (
	"github.com/godbus/dbus/v5"
)

const (
	firewalldBus  = "org.fedoraproject.FirewallD1"
	firewalldPath = "/org/fedoraproject/FirewallD1"
)

// gatewayNetFilter puts the TUN in firewalld's trusted zone so INPUT on
// hopscotch0 is not dropped. No-op if firewalld is not running.
func gatewayNetFilter(ifName string) func() error {
	if !safeIfName(ifName) {
		return nil
	}
	if !firewalldRunning() {
		return nil
	}
	if err := firewalldSetZone(ifName, "trusted"); err != nil {
		return nil
	}
	return func() error {
		_ = firewalldSetZone(ifName, "")
		return nil
	}
}

func firewalldRunning() bool {
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return false
	}
	defer conn.Close()
	obj := conn.Object(firewalldBus, dbus.ObjectPath(firewalldPath))
	var state string
	if err := obj.Call(firewalldBus+".getState", 0).Store(&state); err != nil {
		return false
	}
	return state == "RUNNING"
}

func firewalldSetZone(iface, zone string) error {
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return err
	}
	defer conn.Close()
	obj := conn.Object(firewalldBus, dbus.ObjectPath(firewalldPath))
	return obj.Call(firewalldBus+".zone.changeZoneOfInterface", 0, iface, zone).Err
}
