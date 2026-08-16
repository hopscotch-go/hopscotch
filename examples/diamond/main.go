// Multi-path diamond DAG in one process:
//
//	src ──┬── p0n0 → p0n1 → … → p0n{d-1} ──┐
//	      ├── p1n0 → p1n1 → … → p1n{d-1} ──┼── dst
//	      └── …                            ┘
//
// src dials every path head; each path is a dial-chain; dst dials every tail.
// Launch via "diamond" in launch.json.
//
//	go run . ping --config examples/.local/diamond/src.yaml dst
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
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

func main() {
	width := flag.Int("width", 8, "parallel paths between src and dst")
	depth := flag.Int("depth", 12, "nodes per path")
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
				waitPeers(paths[w][d], 1, 15*time.Second)
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
	waitPeers(src, *width, 30*time.Second)
	waitPeers(dst, *width, 30*time.Second)
	for w := 0; w < *width; w++ {
		waitPeers(paths[w][0], 2, 30*time.Second)
		waitPeers(paths[w][*depth-1], 2, 30*time.Second)
	}

	best := 0
	for w := 1; w < *width; w++ {
		if identity.CloserULA(dst.ID().ULA(), paths[w][0].ID().ULA(), paths[best][0].ID().ULA()) {
			best = w
		}
	}

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
		"paths_ok", ok,
		"paths_want", *width,
		"xor_prefer_head", pathName(best, 0),
		"xor_prefer_path", best,
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
			"note", "named echo may fan out; overlay picks one XOR next hop",
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

func fatal(msg string, args ...any) {
	slog.Error(msg, args...)
	os.Exit(1)
}

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

func pathName(w, d int) string {
	return fmt.Sprintf("p%02dn%02d", w, d)
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
