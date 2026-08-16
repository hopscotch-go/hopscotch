// Multi-path diamond DAG in one process:
//
//	src ──┬── p0n0 → p0n1 → … → p0n{d-1} ──┐
//	      ├── p1n0 → p1n1 → … → p1n{d-1} ──┼── dst
//	      └── …                            ┘
//
// src dials every path head; each path is a dial-chain; dst dials every tail.
// Launch via "Diamond: 50 in-process" or "Diamond: 50 mesh" (50 OS processes).
// Default size: 6×8 + src/dst = 50 nodes.
//
//	go run ./examples/diamond -width 6 -depth 8
//	go run ./examples/diamond/mesh
//	go run . traceroute --config examples/.local/diamond/src.yaml dst
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
)

// main boots an in-process diamond mesh and probes src→dst echo and traceroute.
func main() {
	width := flag.Int("width", 6, "parallel paths between src and dst")
	depth := flag.Int("depth", 8, "nodes per path (total nodes = 2 + width×depth)")
	dir := flag.String("dir", filepath.Join("examples", ".local", "diamond"), "cert/config dir")
	verbose := flag.Bool("v", false, "print raw per-node hopscotch logs")
	statusEvery := flag.Duration("status", 10*time.Second, "status interval (0 to disable)")
	flag.Parse()
	if *width < 2 {
		fatal("width must be >= 2")
	}
	if *depth < 1 {
		fatal("depth must be >= 1")
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	names := []string{"src", "dst"}
	for w := 0; w < *width; w++ {
		for d := 0; d < *depth; d++ {
			names = append(names, pathName(w, d))
		}
	}
	if err := os.MkdirAll(*dir, 0o755); err != nil {
		fatal("mkdir", "err", err)
	}

	total := 2 + (*width)*(*depth)
	slog.Info("boot",
		"phase", "certs",
		"nodes", total,
		"width", *width,
		"depth", *depth,
		"dir", *dir,
	)
	if err := identity.BootstrapDir(*dir, names); err != nil {
		fatal("bootstrap", "err", err)
	}
	ca := filepath.Join(*dir, "ca.crt")

	all := make([]*node.Node, 0, len(names))
	defer func() {
		for i := len(all) - 1; i >= 0; i-- {
			all[i].Close()
		}
	}()

	start := func(name string, listen bool, peerAddrs ...string) *node.Node {
		cfg := node.Config{
			Identity: filepath.Join(*dir, name+".pem"),
			Cert:     filepath.Join(*dir, name+".crt"),
			CA:       ca,
			Network:  "udp",
			Gateway:  false,
			Log:      log.New(io.Discard, "", 0),
		}
		if *verbose {
			cfg.Log = log.New(os.Stderr, name+" ", log.LstdFlags)
		}
		if listen {
			cfg.Listen = "127.0.0.1:0"
		}
		for _, a := range peerAddrs {
			cfg.Peers = append(cfg.Peers, peers.Peer{Addr: a})
		}
		if name == "src" {
			cfg.Control = filepath.Join(*dir, "src.sock")
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

	slog.Info("boot", "phase", "paths", "width", *width, "depth", *depth)
	paths := make([][]*node.Node, *width)
	for w := 0; w < *width; w++ {
		paths[w] = make([]*node.Node, *depth)
		t0 := time.Now()
		for d := 0; d < *depth; d++ {
			if d == 0 {
				paths[w][d] = start(pathName(w, d), true)
			} else {
				paths[w][d] = start(pathName(w, d), true, paths[w][d-1].AdvertiseAddr())
				waitPeers(paths[w][d], 1, 60*time.Second)
			}
		}
		slog.Info("path ready",
			"path", w,
			"nodes", *depth,
			"head", pathName(w, 0),
			"tail", pathName(w, *depth-1),
			"bringup", time.Since(t0).Round(time.Millisecond),
		)
	}

	headAddrs := make([]string, 0, *width)
	tailAddrs := make([]string, 0, *width)
	for w := 0; w < *width; w++ {
		headAddrs = append(headAddrs, paths[w][0].AdvertiseAddr())
		tailAddrs = append(tailAddrs, paths[w][*depth-1].AdvertiseAddr())
	}

	slog.Info("boot", "phase", "edges")
	src := start("src", false, headAddrs...)
	dst := start("dst", false, tailAddrs...)
	waitPeers(src, *width, 60*time.Second)
	waitPeers(dst, *width, 60*time.Second)
	for w := 0; w < *width; w++ {
		waitPeers(paths[w][0], 2, 60*time.Second)
		waitPeers(paths[w][*depth-1], 2, 60*time.Second)
	}

	waitRoute(src, dst.ID().ULA(), 30*time.Second)

	srcYAML := filepath.Join(*dir, "src.yaml")
	if err := os.WriteFile(srcYAML, []byte(
		"identity: src.pem\nca: ca.crt\ncert: src.crt\ncontrol: src.sock\ngateway: false\npeers:\n  - udp:127.0.0.1:1\n",
	), 0o644); err != nil {
		fatal("write control yaml", "err", err)
	}

	ok, bad := pathReport(paths)
	slog.Info("ready",
		"nodes", total,
		"width", *width,
		"depth", *depth,
		"src_connected", src.PeerCount(),
		"src_want", *width,
		"dst_connected", dst.PeerCount(),
		"dst_want", *width,
		"src_metric_dst", src.RouteMetric(dst.ID().ULA()),
		"paths_ok", ok,
		"paths_want", *width,
		"control", srcYAML,
	)
	if len(bad) > 0 {
		slog.Warn("paths unhealthy", "bad", bad)
	}
	slog.Info("topology",
		"shape", fmt.Sprintf("src→{%d paths×%d}→dst", *width, *depth),
		"example", fmt.Sprintf("%s→…→%s", pathName(0, 0), pathName(0, *depth-1)),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	got, err := src.Echo(ctx, "dst")
	cancel()
	if err != nil {
		slog.Error("echo", "from", "src", "to", "dst", "err", err)
	} else {
		slog.Info("echo",
			"from", "src",
			"to", "dst",
			"hops", got.Hops,
			"rtt", got.RTT.Round(time.Microsecond),
			"path", strings.Join(got.Path, "→"),
			"note", "named echo flood; overlay DV path may differ",
		)
	}

	trCtx, trCancel := context.WithTimeout(context.Background(), 60*time.Second)
	trace, err := src.TraceRoute(trCtx, "dst", *depth+4)
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
		slog.Info("overlay traceroute",
			"reached", trace.Reach,
			"src_metric_dst", src.RouteMetric(dst.ID().ULA()),
		)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	slog.Info("running", "ping", fmt.Sprintf("go run . ping --config %s dst", srcYAML))

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
			ok, bad := pathReport(paths)
			attrs := []any{
				"src_connected", src.PeerCount(),
				"src_want", *width,
				"dst_connected", dst.PeerCount(),
				"dst_want", *width,
				"paths_ok", ok,
				"paths_want", *width,
				"healthy", len(bad) == 0,
			}
			if len(bad) > 0 {
				attrs = append(attrs, "bad", bad)
				slog.Warn("status", attrs...)
			} else {
				slog.Info("status", attrs...)
			}
		}
	}
}

// fatal logs an error and exits the process.
func fatal(msg string, args ...any) {
	slog.Error(msg, args...)
	os.Exit(1)
}

// pathReport counts healthy parallel paths and lists any with too few peers.
func pathReport(paths [][]*node.Node) (ok int, bad []string) {
	for w, path := range paths {
		broken := ""
		for d, n := range path {
			want := 2
			if n.PeerCount() < want {
				broken = fmt.Sprintf("%s(peers=%d want=%d)", pathName(w, d), n.PeerCount(), want)
				break
			}
		}
		if broken == "" {
			ok++
		} else {
			bad = append(bad, fmt.Sprintf("p%02d:%s", w, broken))
		}
	}
	return ok, bad
}

// pathName returns the mesh name for path index w at depth d.
func pathName(w, d int) string {
	return fmt.Sprintf("p%02dn%02d", w, d)
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
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if n.RouteMetric(dst) > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	fatal("wait route", "names", n.Names(), "dst", dst.String(), "metric", n.RouteMetric(dst))
}
