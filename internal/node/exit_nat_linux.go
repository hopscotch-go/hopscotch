//go:build linux

package node

import (
	"fmt"
	"os/exec"
	"strings"
)

// writeExitEgress injects a packet into the TUN so the kernel can forward/SNAT it.
func (n *Node) writeExitEgress(inner []byte) error {
	n.mu.Lock()
	d := n.tun
	n.mu.Unlock()
	if d == nil {
		return fmt.Errorf("no tun")
	}
	return d.WritePacket(inner)
}

// setupExitNAT enables IPv4/IPv6 forwarding, accepts FORWARD for the TUN, and
// MASQUERADEs egress. Without a forward accept, VPS images with a DROP policy
// blackhole exit traffic (clients see hung TCP).
func (n *Node) setupExitNAT(ifName string) (func() error, error) {
	if !safeExitIfName(ifName) {
		return nil, fmt.Errorf("exit nat: bad ifname %q", ifName)
	}
	for _, args := range [][]string{
		{"sysctl", "-w", "net.ipv4.ip_forward=1"},
		{"sysctl", "-w", "net.ipv4.conf.all.forwarding=1"},
		{"sysctl", "-w", "net.ipv6.conf.all.forwarding=1"},
		{"sysctl", "-w", "net.ipv4.conf.all.rp_filter=0"},
		{"sysctl", "-w", "net.ipv4.conf." + ifName + ".rp_filter=0"},
	} {
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			// rp_filter on a missing iface name is non-fatal
			if strings.Contains(args[len(args)-1], "rp_filter") {
				continue
			}
			return nil, fmt.Errorf("exit nat %v: %w (%s)", args, err, out)
		}
	}
	_ = exec.Command("nft", "delete", "table", "inet", "hopscotch_exit").Run()
	script := fmt.Sprintf(`table inet hopscotch_exit {
	chain postrouting {
		type nat hook postrouting priority 100;
		oifname != "%s" masquerade
	}
	chain forward {
		type filter hook forward priority -150;
		iifname "%s" accept
		oifname "%s" accept
	}
}
`, ifName, ifName, ifName)
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("exit nat nft: %w (%s)", err, out)
	}

	// iptables/ip6tables DROP policies still drop even when nft accepts.
	iptablesInsertForward(ifName)

	n.log.Printf("exit      nat inet hopscotch_exit masquerade + forward (oif != %s)", ifName)
	return func() error {
		iptablesDeleteForward(ifName)
		_ = exec.Command("nft", "delete", "table", "inet", "hopscotch_exit").Run()
		return nil
	}, nil
}

func iptablesInsertForward(ifName string) {
	for _, bin := range []string{"iptables", "ip6tables"} {
		_ = exec.Command(bin, "-I", "FORWARD", "1", "-i", ifName, "-j", "ACCEPT").Run()
		_ = exec.Command(bin, "-I", "FORWARD", "1", "-o", ifName, "-j", "ACCEPT").Run()
	}
}

func iptablesDeleteForward(ifName string) {
	for _, bin := range []string{"iptables", "ip6tables"} {
		_ = exec.Command(bin, "-D", "FORWARD", "-i", ifName, "-j", "ACCEPT").Run()
		_ = exec.Command(bin, "-D", "FORWARD", "-o", ifName, "-j", "ACCEPT").Run()
	}
}

func safeExitIfName(name string) bool {
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
