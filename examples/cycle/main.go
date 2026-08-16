// Session graph with a ring and a long spur — without strict XOR progress,
// greedy nextHop can circle the ring:
//
//	foo → bar → baz → buzz → bar
//	                   ↓
//	                 bizz → mid1 → mid2 → mid3 → blaz
//
// Nodes use NoDialCloser: only the boot-time peer edges exist (pretend each
// node is on an isolated machine). Overlay cannot shortcut foo→mid2.
//
// Launch via "cycle" in launch.json.
//
//	go run ./examples/cycle -force-loop
//	go run . traceroute --config examples/.local/cycle/foo.yaml blaz
//	go run . ping --config examples/.local/cycle/foo.yaml blaz
package main

import (
	"context"
	"crypto/ed25519"
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

func main() {
	dir := flag.String("dir", filepath.Join("examples", ".local", "cycle"), "cert/config dir")
	verbose := flag.Bool("v", false, "print raw per-node hopscotch logs")
	logOverlay := flag.Bool("log-overlay", false, "log every overlay nextHop forward")
	forceLoop := flag.Bool("force-loop", false, "regenerate certs until buzz XOR prefers bar (loop risk)")
	statusEvery := flag.Duration("status", 10*time.Second, "status interval (0 to disable)")
	hopLimit := flag.Uint("hop-limit", 64, "IPv6 Hop Limit for the overlay ICMP probe")
	maxTTL := flag.Int("max-ttl", 24, "max Hop Limit for built-in overlay traceroute")
	flag.Parse()

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))

	names := []string{"foo", "bar", "baz", "buzz", "bizz", "mid1", "mid2", "mid3", "blaz"}
	const spurHops = 8 // foo→bar→baz→buzz→bizz→mid1→mid2→mid3→blaz (session path; dial may shorten)
	if err := os.MkdirAll(*dir, 0o755); err != nil {
		fatal("mkdir", "err", err)
	}
	if err := ensureCerts(*dir, names, *forceLoop); err != nil {
		fatal("certs", "err", err)
	}
	ca := filepath.Join(*dir, "ca.crt")

	all := make([]*node.Node, 0, len(names))
	defer func() {
		for i := len(all) - 1; i >= 0; i-- {
			all[i].Close()
		}
	}()

	start := func(name string, _ bool, peerAddrs ...string) *node.Node {
		cfg := node.Config{
			Identity:     filepath.Join(*dir, name+".pem"),
			Cert:         filepath.Join(*dir, name+".crt"),
			CA:           ca,
			Network:      "udp",
			Listen:       "127.0.0.1:0",
			Gateway:      false,
			NoDialCloser: true, // isolated-machine pretence: only boot peers get sessions
			LogOverlay:   *logOverlay,
			Log:          log.New(io.Discard, "", 0),
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
	bar := start("bar", true)
	foo := start("foo", false, bar.AdvertiseAddr())
	waitPeers(foo, 1, 15*time.Second)
	waitPeers(bar, 1, 15*time.Second)
	baz := start("baz", true, bar.AdvertiseAddr())
	waitPeers(baz, 1, 15*time.Second)
	waitPeers(bar, 2, 15*time.Second)
	buzz := start("buzz", true, baz.AdvertiseAddr(), bar.AdvertiseAddr())
	waitPeers(buzz, 2, 15*time.Second)
	waitPeers(bar, 3, 15*time.Second)

	slog.Info("boot", "phase", "spur", "shape", "buzz→bizz→mid1→mid2→mid3→blaz")
	bizz := start("bizz", true, buzz.AdvertiseAddr())
	waitPeers(bizz, 1, 15*time.Second)
	waitPeers(buzz, 3, 15*time.Second)
	mid1 := start("mid1", true, bizz.AdvertiseAddr())
	waitPeers(mid1, 1, 15*time.Second)
	waitPeers(bizz, 2, 15*time.Second)
	mid2 := start("mid2", true, mid1.AdvertiseAddr())
	waitPeers(mid2, 1, 15*time.Second)
	waitPeers(mid1, 2, 15*time.Second)
	mid3 := start("mid3", true, mid2.AdvertiseAddr())
	waitPeers(mid3, 1, 15*time.Second)
	waitPeers(mid2, 2, 15*time.Second)
	blaz := start("blaz", true, mid3.AdvertiseAddr())
	waitPeers(blaz, 1, 15*time.Second)
	waitPeers(mid3, 2, 15*time.Second)

	barPrefersBaz := identity.CloserULA(blaz.ID().ULA(), baz.ID().ULA(), buzz.ID().ULA())
	buzzPrefersBar := !identity.CloserULA(blaz.ID().ULA(), bizz.ID().ULA(), bar.ID().ULA())
	loopRisk := barPrefersBaz && buzzPrefersBar
	preferBar := "baz"
	if !barPrefersBaz {
		preferBar = "buzz"
	}
	preferBuzz := "bar"
	if !buzzPrefersBar {
		preferBuzz = "bizz"
	}

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
		"note", "NoDialCloser: no overlay shortcuts; only boot peer sessions",
	)
	slog.Info("ready",
		"foo_peers", foo.PeerCount(),
		"bar_peers", bar.PeerCount(),
		"buzz_peers", buzz.PeerCount(),
		"bizz_peers", bizz.PeerCount(),
		"mid3_peers", mid3.PeerCount(),
		"blaz_peers", blaz.PeerCount(),
		"control", fooYAML,
	)
	slog.Info("xor toward blaz",
		"at_bar_from", "foo",
		"bar_candidates", []string{"baz", "buzz"},
		"bar_prefer", preferBar,
		"at_buzz_from", "baz",
		"buzz_candidates", []string{"bar", "bizz"},
		"buzz_prefer", preferBuzz,
		"loop_risk", loopRisk,
		"note", "naive XOR would loop here; strict progress + dial-closer should not",
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
			"note", "fan-out; not overlay XOR",
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
		slog.Info("overlay traceroute", "reached", trace.Reach, "note", "repeats would mean a cycle; dest_unreach means stuck without progress")
	}

	probeOverlay(foo, blaz, uint8(*hopLimit), spurHops)

	var loops uint64
	for _, n := range all {
		loops += n.OverlayLoopCount()
	}
	slog.Info("overlay loop detections",
		"total", loops,
		"buzz", buzz.OverlayLoopCount(),
		"bar", bar.OverlayLoopCount(),
		"baz", baz.OverlayLoopCount(),
		"note", "count of same-edge forwards with decreasing Hop Limit",
	)

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
			var l uint64
			for _, n := range all {
				l += n.OverlayLoopCount()
			}
			slog.Info("status",
				"foo_peers", foo.PeerCount(),
				"bar_peers", bar.PeerCount(),
				"buzz_peers", buzz.PeerCount(),
				"bizz_peers", bizz.PeerCount(),
				"mid1_peers", mid1.PeerCount(),
				"mid3_peers", mid3.PeerCount(),
				"blaz_peers", blaz.PeerCount(),
				"xor_bar", preferBar,
				"xor_buzz", preferBuzz,
				"loop_risk", loopRisk,
				"overlay_loops", l,
			)
		}
	}
}

func ensureCerts(dir string, names []string, forceLoop bool) error {
	const maxAttempts = 80
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if forceLoop && attempt > 1 {
			for _, name := range names {
				_ = os.Remove(filepath.Join(dir, name+".pem"))
				_ = os.Remove(filepath.Join(dir, name+".crt"))
			}
		}
		slog.Info("boot", "phase", "certs", "nodes", len(names), "dir", dir, "attempt", attempt)
		if err := identity.BootstrapDir(dir, names); err != nil {
			return err
		}
		if !forceLoop {
			return nil
		}
		barULA, err := ulaFromPEM(filepath.Join(dir, "bar.pem"))
		if err != nil {
			return err
		}
		bazULA, err := ulaFromPEM(filepath.Join(dir, "baz.pem"))
		if err != nil {
			return err
		}
		buzzULA, err := ulaFromPEM(filepath.Join(dir, "buzz.pem"))
		if err != nil {
			return err
		}
		bizzULA, err := ulaFromPEM(filepath.Join(dir, "bizz.pem"))
		if err != nil {
			return err
		}
		blazULA, err := ulaFromPEM(filepath.Join(dir, "blaz.pem"))
		if err != nil {
			return err
		}
		// Loop path foo→bar→baz→buzz→bar→… needs:
		// - at bar (from foo): prefer baz over buzz
		// - at buzz (from baz): prefer bar over bizz
		barPrefersBaz := identity.CloserULA(blazULA, bazULA, buzzULA)
		buzzPrefersBar := !identity.CloserULA(blazULA, bizzULA, barULA)
		if barPrefersBaz && buzzPrefersBar {
			slog.Info("force-loop", "ok", true, "attempt", attempt, "bar_next", "baz", "buzz_next", "bar")
			return nil
		}
		slog.Info("force-loop", "ok", false, "attempt", attempt,
			"bar_prefers_baz", barPrefersBaz, "buzz_prefers_bar", buzzPrefersBar)
	}
	return fmt.Errorf("force-loop: no loop-risk keying after %d attempts", maxAttempts)
}

func ulaFromPEM(path string) (net.IP, error) {
	priv, err := identity.LoadKey(path)
	if err != nil {
		return nil, err
	}
	pub := priv.Public().(ed25519.PublicKey)
	return identity.IDFromPublic(pub).ULA(), nil
}

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
		"note", "NoDialCloser: peer-only greedy walk; expect the spur (not foo→mid*)",
	)
	if err := dev.Inject(req); err != nil {
		slog.Error("overlay inject", "err", err)
		return
	}
	select {
	case <-time.After(3 * time.Second):
		slog.Warn("overlay probe", "result", "timeout",
			"hint", "greedy XOR may be circling; TE may also fail to return — check overlay_loops + traceroute")
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
				"note", "no XOR-progress neighbor (and dial-closer did not help in time)",
			)
		default:
			slog.Info("overlay probe", "result", "other_icmp", "type", pkt[40])
		}
	}
}

func fatal(msg string, args ...any) {
	slog.Error(msg, args...)
	os.Exit(1)
}

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
