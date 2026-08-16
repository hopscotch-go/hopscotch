//go:build linux

package tun

import (
	"context"
	"os/exec"
	"time"
)

// gatewayNetFilter puts the TUN in firewalld's trusted zone so INPUT on
// hopscotch0 is not dropped. No-op if firewalld is not running.
func gatewayNetFilter(ifName string) func() error {
	if !safeIfName(ifName) {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "firewall-cmd", "--state").Run(); err != nil {
		return nil
	}
	if err := exec.CommandContext(ctx, "firewall-cmd", "--zone=trusted", "--add-interface="+ifName).Run(); err != nil {
		return nil
	}
	return func() error {
		c, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = exec.CommandContext(c, "firewall-cmd", "--zone=trusted", "--remove-interface="+ifName).Run()
		return nil
	}
}
