package node

import (
	"context"
	"net"
	"time"

	"github.com/hopscotch-go/hopscotch/internal/tun"
)

// How long host defaults stay up after a brief RIB blip before teardown.
const exitDefaultsDownGrace = 3 * time.Second

// syncExitHostDefaults installs or tears down host /1+/1 routes.
// Defaults stay down until we know the exit ULA, see a DV default from an
// exit, and have a RIB next hop — otherwise /1 blackholes the internet.
// Teardown is debounced so sparse route ads do not flap Wi‑Fi.
func (n *Node) syncExitHostDefaults() {
	if n.cfg.ExitNode == "" {
		return
	}
	n.mu.Lock()
	d := n.tun
	n.mu.Unlock()
	if d == nil {
		n.clearExitHostDefaultsNow()
		return
	}
	if !n.hasDefaultExitRoute() {
		n.scheduleExitHostDefaultsDown()
		go n.resolveExitULABackground()
		return
	}
	ula := n.resolvedExitULA()
	if ula == nil {
		n.scheduleExitHostDefaultsDown()
		go n.resolveExitULABackground()
		return
	}
	if n.nextHop(ula, nil) == nil {
		n.scheduleExitHostDefaultsDown()
		return
	}
	n.cancelExitHostDefaultsDown()
	n.ensureExitHostDefaults(d.Name())
}

func (n *Node) hasDefaultExitRoute() bool {
	n.routeMu.Lock()
	defer n.routeMu.Unlock()
	_, ok4 := n.routes[defaultRouteV4]
	_, ok6 := n.routes[defaultRouteV6]
	return ok4 || ok6
}

func (n *Node) resolveExitULABackground() {
	if n.cfg.ExitNode == "" {
		return
	}
	n.exitMu.Lock()
	if n.exitULA != nil || n.exitResolving {
		n.exitMu.Unlock()
		return
	}
	n.exitResolving = true
	n.exitMu.Unlock()
	defer func() {
		n.exitMu.Lock()
		n.exitResolving = false
		n.exitMu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(n.ctx, 8*time.Second)
	defer cancel()
	ip, err := n.ResolveULA(ctx, n.cfg.ExitNode)
	if err != nil || ip == nil {
		return
	}
	n.exitMu.Lock()
	n.exitULA = append(net.IP(nil), ip...)
	n.exitMu.Unlock()
	n.log.Printf("exit_node %s → %s (mesh resolve)", n.cfg.ExitNode, ip)
	n.syncExitHostDefaults()
}

func (n *Node) ensureExitHostDefaults(ifName string) {
	n.exitMu.Lock()
	defer n.exitMu.Unlock()
	if n.exitDefaultsRevert != nil {
		return
	}
	// Hold exitMu across install: two callers (route update + name resolve)
	// used to both succeed, then the loser reverted and deleted the /1 routes.
	pins := n.underlayPinRoutes()
	revert, err := tun.InstallDefaultRoutes(ifName, pins)
	if err != nil {
		n.log.Printf("exit_node defaults: %v", err)
		return
	}
	n.exitDefaultsRevert = revert
	n.log.Printf("exit_node host defaults UP via %s (/1+/1)", ifName)
}

func (n *Node) scheduleExitHostDefaultsDown() {
	n.exitMu.Lock()
	defer n.exitMu.Unlock()
	if n.exitDefaultsRevert == nil {
		return
	}
	if n.exitDefaultsTimer != nil {
		return // already scheduled
	}
	n.exitDefaultsTimer = time.AfterFunc(exitDefaultsDownGrace, func() {
		n.exitMu.Lock()
		n.exitDefaultsTimer = nil
		n.exitMu.Unlock()
		if n.exitPathReady() {
			return
		}
		n.clearExitHostDefaultsNow()
	})
}

func (n *Node) cancelExitHostDefaultsDown() {
	n.exitMu.Lock()
	defer n.exitMu.Unlock()
	if n.exitDefaultsTimer != nil {
		n.exitDefaultsTimer.Stop()
		n.exitDefaultsTimer = nil
	}
}

func (n *Node) exitPathReady() bool {
	if n.cfg.ExitNode == "" || !n.hasDefaultExitRoute() {
		return false
	}
	ula := n.resolvedExitULA()
	return ula != nil && n.nextHop(ula, nil) != nil
}

func (n *Node) clearExitHostDefaults() {
	n.clearExitHostDefaultsNow()
}

func (n *Node) clearExitHostDefaultsNow() {
	n.exitMu.Lock()
	if n.exitDefaultsTimer != nil {
		n.exitDefaultsTimer.Stop()
		n.exitDefaultsTimer = nil
	}
	revert := n.exitDefaultsRevert
	n.exitDefaultsRevert = nil
	n.exitMu.Unlock()
	if revert == nil {
		return
	}
	if err := revert(); err != nil {
		n.log.Printf("exit_node defaults teardown: %v", err)
		return
	}
	n.log.Printf("exit_node host defaults DOWN (no path to exit)")
}
