// 100-node dial chain in one process (n00 ← n01 ← … ← n99).
// Launch via "chain-100" in launch.json.
//
//	go run . ping --config examples/.local/chain/head.yaml n99
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/hopscotch-go/hopscotch/internal/identity"
	"github.com/hopscotch-go/hopscotch/internal/node"
	"github.com/hopscotch-go/hopscotch/internal/peers"
)

func main() {
	n := flag.Int("n", 100, "number of nodes in the chain")
	dir := flag.String("dir", filepath.Join("examples", ".local", "chain"), "cert/config dir")
	flag.Parse()
	if *n < 2 {
		log.Fatal("need at least 2 nodes")
	}

	names := make([]string, *n)
	for i := range names {
		names[i] = fmt.Sprintf("n%02d", i)
	}
	if err := os.MkdirAll(*dir, 0o755); err != nil {
		log.Fatal(err)
	}
	if err := identity.BootstrapDir(*dir, names); err != nil {
		log.Fatal(err)
	}
	ca := filepath.Join(*dir, "ca.crt")

	nodes := make([]*node.Node, 0, *n)
	defer func() {
		for i := len(nodes) - 1; i >= 0; i-- {
			nodes[i].Close()
		}
	}()

	log.SetFlags(0)
	log.Printf("starting %d-node chain in %s", *n, *dir)

	for i := 0; i < *n; i++ {
		name := names[i]
		cfg := node.Config{
			Identity: filepath.Join(*dir, name+".pem"),
			Cert:     filepath.Join(*dir, name+".crt"),
			CA:       ca,
			Network:  "udp",
			Gateway:  false,
		}
		if i == 0 || i == *n-1 || i%10 == 0 {
			cfg.Log = log.New(os.Stdout, name+" ", 0)
		} else {
			cfg.Log = log.New(io.Discard, "", 0)
		}
		if i == 0 {
			cfg.Listen = "127.0.0.1:0"
		} else {
			cfg.Listen = "127.0.0.1:0"
			cfg.Peers = []peers.Peer{{Addr: nodes[i-1].AdvertiseAddr()}}
		}
		if i == 0 {
			cfg.Control = filepath.Join(*dir, "head.sock")
		}
		if i == *n-1 {
			cfg.Control = filepath.Join(*dir, "tail.sock")
		}
		nd, err := node.New(cfg)
		if err != nil {
			log.Fatal(err)
		}
		if err := nd.Start(); err != nil {
			log.Fatal(err)
		}
		nodes = append(nodes, nd)
		if i > 0 {
			waitPeers(nd, 1, 15*time.Second)
		}
	}

	log.Printf("chain up: %s → … → %s (%d session hops)", names[*n-1], names[0], *n-1)

	headYAML := filepath.Join(*dir, "head.yaml")
	if err := os.WriteFile(headYAML, []byte(fmt.Sprintf(
		"identity: %s.pem\nca: ca.crt\ncert: %s.crt\ncontrol: head.sock\ngateway: false\npeers:\n  - udp:127.0.0.1:1\n",
		names[0], names[0],
	)), 0o644); err != nil {
		log.Fatal(err)
	}
	log.Printf("ping from head:  go run . ping --config %s %s", headYAML, names[*n-1])

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	got, err := nodes[0].Echo(ctx, names[*n-1])
	if err != nil {
		log.Printf("%s→%s echo failed: %v", names[0], names[*n-1], err)
	} else {
		log.Printf("%s→%s echo ok hops=%d rtt=%s", names[0], names[*n-1], got.Hops, got.RTT)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	log.Printf("running; Ctrl-C to stop")
	<-sig
	log.Printf("shutting down")
}

func waitPeers(n *node.Node, want int, d time.Duration) {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if n.PeerCount() >= want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	log.Fatalf("%s: want %d peers, got %d", n.Names(), want, n.PeerCount())
}
