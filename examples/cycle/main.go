// Session graph with a ring and a long spur. Overlay uses hop-count
// distance-vector over live sessions, so the spur is preferred as the
// shorter path to blaz when bar↔buzz exists:
//
//	foo → bar → baz → buzz → bar
//	                   ↓
//	                 bizz → mid1 → mid2 → mid3 → blaz
//
// Sessions are only the boot peer edges (isolated-machine pretence).
//
// Launch via "Cycle: mesh" (separate processes) or "Cycle: in-process" in launch.json.
//
//	go run ./examples/cycle
//	go run . traceroute --config examples/cycle/foo.yaml blaz
//	go run . ping --config examples/cycle/foo.yaml blaz
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/hopscotch-go/hopscotch/internal/identity"
	"github.com/hopscotch-go/hopscotch/internal/node"
	"github.com/hopscotch-go/hopscotch/internal/peers"
	"github.com/hopscotch-go/hopscotch/internal/tun"
)

// main boots the in-process cycle mesh demo and runs echo, traceroute, and overlay probes.
func main() {
	dir := flag.String("dir", filepath.Join("examples", ".local", "cycle"), "cert/config dir")
	verbose := flag.Bool("v", false, "print raw per-node hopscotch logs")
	logOverlay := flag.Bool("log-overlay", false, "log every overlay nextHop forward")
	statusEvery := flag.Duration("status", 10*time.Second, "status interval (0 to disable)")
	hopLimit := flag.Uint("hop-limit", 64, "IPv6 Hop Limit for the overlay ICMP probe")
	maxTTL := flag.Int("max-ttl", 24, "max Hop Limit for built-in overlay traceroute")
	flag.Parse()

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))

	names := []string{"foo", "bar", "baz", "buzz", "bizz", "mid1", "mid2", "mid3", "blaz"}
	const spurHops = 8 // foo→bar→baz→buzz→bizz→mid1→mid2→mid3→blaz
	if err := os.MkdirAll(*dir, 0o755); err != nil {
		fatal("mkdir", "err", err)
	}
	if err := ensureCerts(*dir, names); err != nil {
		fatal("certs", "err", err)
	}
	ca := filepath.Join(*dir, "ca.crt")

	all := make([]*node.Node, 0, len(names))
	defer func() {
		for i := len(all) - 1; i >= 0; i-- {
			all[i].Close()
		}
	}()

	start := func(name string, peerAddrs ...string) *node.Node {
		cfg := node.Config{
			Identity:   filepath.Join(*dir, name+".pem"),
			Cert:       filepath.Join(*dir, name+".crt"),
			CA:         ca,
			Network:    "udp",
			Listen:     "127.0.0.1:0",
			Gateway:    false,
			LogOverlay: *logOverlay,
			Log:        log.New(io.Discard, "", 0),
		}
		if *verbose || *logOverlay {
			cfg.Log = log.New(os.Stderr, name+" ", log.LstdFlags)
		}
		for _, a := range peerAddrs {
			cfg.Peers = append(cfg.Peers, peers.Peer{Addr: a})
		}
		if name == "foo" {
			cfg.Control = filepath.Join(*dir, "foo.sock")
		}
		n, err := node.New(cfg)
		if err != nil {
			fatal("node new", "name", name, "err", err)
		}
		if err := n.Start(); err != nil {
			fatal("node start", "name", name, "err", err)
		}
		all = append(all, n)
		return n
	}

	slog.Info("boot", "phase", "ring", "shape", "bar→baz→buzz→bar; foo→bar")
	bar := start("bar")
	foo := start("foo", bar.AdvertiseAddr())
	waitPeers(foo, 1, 15*time.Second)
	waitPeers(bar, 1, 15*time.Second)
	baz := start("baz", bar.AdvertiseAddr())
	waitPeers(baz, 1, 15*time.Second)
	waitPeers(bar, 2, 15*time.Second)
	buzz := start("buzz", baz.AdvertiseAddr(), bar.AdvertiseAddr())
	waitPeers(buzz, 2, 15*time.Second)
	waitPeers(bar, 3, 15*time.Second)
	slog.Info("rib snapshot", "phase", "ring up")
	logMeshRoutes(all)

	slog.Info("boot", "phase", "spur", "shape", "buzz→bizz→mid1→mid2→mid3→blaz")
	bizz := start("bizz", buzz.AdvertiseAddr())
	waitPeers(bizz, 1, 15*time.Second)
	waitPeers(buzz, 3, 15*time.Second)
	mid1 := start("mid1", bizz.AdvertiseAddr())
	waitPeers(mid1, 1, 15*time.Second)
	waitPeers(bizz, 2, 15*time.Second)
	mid2 := start("mid2", mid1.AdvertiseAddr())
	waitPeers(mid2, 1, 15*time.Second)
	waitPeers(mid1, 2, 15*time.Second)
	mid3 := start("mid3", mid2.AdvertiseAddr())
	waitPeers(mid3, 1, 15*time.Second)
	waitPeers(mid2, 2, 15*time.Second)
	blaz := start("blaz", mid3.AdvertiseAddr())
	waitPeers(blaz, 1, 15*time.Second)
	waitPeers(mid3, 2, 15*time.Second)
	waitRoute(foo, blaz.ID().ULA(), 10*time.Second)
	slog.Info("rib snapshot", "phase", "spur converged")
	logMeshRoutes(all)

	fooYAML := filepath.Join(*dir, "foo.yaml")
	if err := os.WriteFile(fooYAML, []byte(
		"identity: foo.pem\nca: ca.crt\ncert: foo.crt\ncontrol: foo.sock\ngateway: false\npeers:\n  - udp:127.0.0.1:1\n",
	), 0o644); err != nil {
		fatal("write control yaml", "err", err)
	}

	slog.Info("topology",
		"entry", "foo→bar",
		"ring", "bar→baz→buzz→bar",
		"spur", "buzz→bizz→mid1→mid2→mid3→blaz",
		"session_hops_min", spurHops,
		"note", "DV routes over boot peer sessions only",
	)
	slog.Info("ready",
		"foo_peers", foo.PeerCount(),
		"bar_peers", bar.PeerCount(),
		"buzz_peers", buzz.PeerCount(),
		"bizz_peers", bizz.PeerCount(),
		"mid3_peers", mid3.PeerCount(),
		"blaz_peers", blaz.PeerCount(),
		"foo_metric_blaz", foo.RouteMetric(blaz.ID().ULA()),
		"control", fooYAML,
	)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	got, err := foo.Echo(ctx, "blaz")
	cancel()
	if err != nil {
		slog.Error("named echo", "from", "foo", "to", "blaz", "err", err)
	} else {
		slog.Info("named echo",
			"from", "foo",
			"to", "blaz",
			"hops", got.Hops,
			"rtt", got.RTT.Round(time.Microsecond),
			"path", strings.Join(got.Path, "→"),
			"note", "fan-out; not overlay DV",
		)
	}

	trCtx, trCancel := context.WithTimeout(context.Background(), time.Duration(*maxTTL)*time.Second+5*time.Second)
	trace, err := foo.TraceRoute(trCtx, "blaz", *maxTTL)
	trCancel()
	if err != nil {
		slog.Error("overlay traceroute", "err", err)
	} else {
		for _, h := range trace.Hops {
			if h.Timeout {
				slog.Warn("overlay traceroute", "ttl", h.TTL, "result", "*")
				continue
			}
			label := h.Name
			if label == "" {
				label = h.ULA
			}
			slog.Info("overlay traceroute",
				"ttl", h.TTL,
				"hop", label,
				"reply", h.Reply,
				"rtt", h.RTT.Round(time.Microsecond),
			)
		}
		slog.Info("overlay traceroute", "reached", trace.Reach, "note", "hop-count DV path; dest_unreach means no RIB entry yet")
	}

	probeOverlay(foo, blaz, uint8(*hopLimit), spurHops)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	slog.Info("running",
		"ping", fmt.Sprintf("go run . ping --config %s blaz", fooYAML),
		"traceroute", fmt.Sprintf("go run . traceroute --config %s blaz", fooYAML),
	)

	var tick <-chan time.Time
	if *statusEvery > 0 {
		t := time.NewTicker(*statusEvery)
		defer t.Stop()
		tick = t.C
	}
	for {
		select {
		case <-sig:
			slog.Info("shutdown")
			return
		case <-tick:
			slog.Info("status",
				"foo_peers", foo.PeerCount(),
				"bar_peers", bar.PeerCount(),
				"buzz_peers", buzz.PeerCount(),
				"bizz_peers", bizz.PeerCount(),
				"mid1_peers", mid1.PeerCount(),
				"mid3_peers", mid3.PeerCount(),
				"blaz_peers", blaz.PeerCount(),
				"foo_metric_blaz", foo.RouteMetric(blaz.ID().ULA()),
			)
			logMeshRoutes(all)
		}
	}
}

// logMeshRoutes prints each node's distance-vector RIB with destination names.
func logMeshRoutes(nodes []*node.Node) {
	ulaName := make(map[string]string, len(nodes))
	for _, n := range nodes {
		name := "node"
		if ns := n.Names(); len(ns) > 0 {
			name = ns[0]
		}
		ulaName[n.ID().ULA().String()] = name
	}
	for _, n := range nodes {
		name := "node"
		if ns := n.Names(); len(ns) > 0 {
			name = ns[0]
		}
		routes := n.Routes()
		parts := make([]string, 0, len(routes))
		for _, r := range routes {
			dest := ulaName[r.DestIP]
			if dest == "" {
				dest = r.Dest
			}
			parts = append(parts, fmt.Sprintf("%s→%s(%d)", dest, r.Next, r.Metric))
		}
		slog.Info("rib", "node", name, "routes", len(routes), "table", strings.Join(parts, " "))
	}
}

// ensureCerts bootstraps CA and per-node certs for the cycle demo.
func ensureCerts(dir string, names []string) error {
	slog.Info("boot", "phase", "certs", "nodes", len(names), "dir", dir)
	return identity.BootstrapDir(dir, names)
}

// probeOverlay injects an IPv6 ICMP echo from foo toward blaz over the TUN path.
func probeOverlay(foo, blaz *node.Node, hopLimit uint8, shortestHops int) {
	dev := tun.NewMem()
	defer dev.Close()
	foo.AttachTun(dev)

	req := ipv6ICMPEcho(foo.ID().ULA(), blaz.ID().ULA(), hopLimit)
	slog.Info("overlay probe",
		"from", "foo",
		"to", "blaz",
		"hop_limit", hopLimit,
		"session_spur_hops", shortestHops,
		"note", "hop-count DV over peer sessions",
	)
	if err := dev.Inject(req); err != nil {
		slog.Error("overlay inject", "err", err)
		return
	}
	select {
	case <-time.After(3 * time.Second):
		slog.Warn("overlay probe", "result", "timeout",
			"hint", "check RouteMetric / traceroute; routes may still be converging")
	case pkt := <-dev.Recv():
		if len(pkt) < 41 {
			slog.Warn("overlay probe", "result", "short_packet", "len", len(pkt))
			return
		}
		switch pkt[40] {
		case 129: // echo reply
			slog.Info("overlay probe",
				"result", "echo_reply",
				"reply_hlim", pkt[7],
				"src", net.IP(pkt[8:24]).String(),
			)
		case 3: // time exceeded
			slog.Warn("overlay probe",
				"result", "time_exceeded",
				"code", pkt[41],
				"note", "Hop Limit expired (short limit or residual loop)",
			)
		case 1: // dest unreachable
			slog.Warn("overlay probe",
				"result", "dest_unreach",
				"code", pkt[41],
				"note", "no RIB entry for destination",
			)
		default:
			slog.Info("overlay probe", "result", "other_icmp", "type", pkt[40])
		}
	}
}

// fatal logs an error and exits the process.
func fatal(msg string, args ...any) {
	slog.Error(msg, args...)
	os.Exit(1)
}

// waitPeers blocks until n has at least want peers or the deadline passes.
func waitPeers(n *node.Node, want int, d time.Duration) {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if n.PeerCount() >= want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	fatal("wait peers", "names", n.Names(), "want", want, "got", n.PeerCount())
}

// waitRoute blocks until n has a positive route metric to dst or the deadline passes.
func waitRoute(n *node.Node, dst net.IP, d time.Duration) {
	if n.RouteMetric(dst) > 0 {
		return
	}
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if n.RouteMetric(dst) > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	fatal("wait route", "names", n.Names(), "dst", dst.String(), "metric", n.RouteMetric(dst))
}

// ipv6ICMPEcho builds a raw IPv6 ICMPv6 echo-request packet.
func ipv6ICMPEcho(src, dst net.IP, hop uint8) []byte {
	p := make([]byte, 56)
	p[0] = 0x60
	p[4], p[5] = 0, 16
	p[6] = 58 // ICMPv6
	p[7] = hop
	copy(p[8:24], src.To16())
	copy(p[24:40], dst.To16())
	p[40] = 128 // echo request
	p[44], p[45] = 0x12, 0x34
	p[46], p[47] = 0, 1
	sum := icmpv6Checksum(p)
	p[42] = byte(sum >> 8)
	p[43] = byte(sum)
	return p
}

// icmpv6Checksum computes the ICMPv6 checksum for a full IPv6 packet.
func icmpv6Checksum(pkt []byte) uint16 {
	var sum uint32
	plen := uint32(len(pkt) - 40)
	for i := 8; i < 40; i += 2 {
		sum += uint32(pkt[i])<<8 | uint32(pkt[i+1])
	}
	sum += plen>>16 + plen&0xffff
	sum += 58
	for i := 40; i+1 < len(pkt); i += 2 {
		sum += uint32(pkt[i])<<8 | uint32(pkt[i+1])
	}
	if (len(pkt)-40)%2 == 1 {
		sum += uint32(pkt[len(pkt)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
