package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/hopscotch-go/hopscotch/internal/config"
	"github.com/hopscotch-go/hopscotch/internal/identity"
	"github.com/hopscotch-go/hopscotch/internal/node"
	"github.com/hopscotch-go/hopscotch/internal/proto"
)

type stringList []string

// String returns the joined flag values for flag.Value display.
func (s *stringList) String() string { return strings.Join(*s, ", ") }

// Set appends one repeated flag value to the list.
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// usage prints the hopscotch CLI help text and flag defaults.
func usage() {
	fmt.Fprintf(os.Stderr, `hopscotch — private mesh of CA-named nodes

Dial configured peers; overlay hops follow a distance-vector table over
live QUIC sessions. NodeID is SHA-256 of an ed25519 public key; overlay
IPv6 ULAs are derived from that ID.

Every node needs a CA-signed certificate. Self-signed peers are rejected.

  hopscotch --config examples/hub/foo.yaml
  hopscotch ping --config examples/hub/foo.yaml baz
  hopscotch traceroute --config examples/hub/foo.yaml baz
  hopscotch ula --config examples/hub/foo.yaml
  hopscotch ula --config examples/hub/foo.yaml baz

Exit nodes (Tailscale-like): --exit advertises SNAT egress; --exit-node=name
installs host /1+/1 defaults via TUN toward that mesh name (pins underlay peers).

  sudo ./hopscotch --config examples/hub/baz.yaml --tun --exit
  sudo ./hopscotch --config examples/hub/foo.yaml --tun --exit-node=baz

With --tun (needs root), one node is the host overlay NIC (fd00::/8
and overlay DNS). Then ping6 of a connected peer name works.

  sudo ./hopscotch --config examples/hub/foo.yaml --tun

With --userspace, a gVisor IPv6 stack binds the node ULA in-process
(no root). Use DialTCP/ListenTCP over the overlay without a TUN.

  ./hopscotch --config examples/hub/foo.yaml --userspace

With --socks 127.0.0.1:1080, apps can CONNECT through the mesh by
overlay name (curl --socks5-hostname 127.0.0.1:1080 http://baz.hopscotch/).

  ./hopscotch --config examples/hub/foo.yaml --socks 127.0.0.1:1080

  hopscotch ca init --key ca.key --cert ca.crt
  hopscotch ca sign --ca-key ca.key --ca-cert ca.crt --identity node.pem --out node.crt --name foo
  hopscotch --ca ca.crt --cert node.crt --identity node.pem --listen 127.0.0.1:4433
  hopscotch --ca ca.crt --cert node.crt --identity node.pem --listen udp:127.0.0.1:4433 --listen tcp:127.0.0.1:4433
  hopscotch --ca ca.crt --cert node.crt --identity node.pem --listen 127.0.0.1:4434 --peers peers.txt

--listen may be repeated. Prefix with udp: or tcp: (default udp).
--peers is a file of hops, one per line: `+"`addr`"+` or `+"`pubkey addr`"+`.
In YAML, peers are a list of addresses or {addr, pubkey} maps.
addr is host:port or udp:host:port / tcp:host:port.
pubkey is 64 hex chars of the ed25519 public key (not NodeID).

Flags:
`)
	flag.PrintDefaults()
}

// main runs the hopscotch node CLI, or dispatches ping, traceroute, and ca subcommands.
func main() {
	log.SetFlags(log.Ltime | log.Lmsgprefix)

	if len(os.Args) >= 2 && os.Args[1] == "ping" {
		if err := runPing(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
		return
	}

	if len(os.Args) >= 2 && os.Args[1] == "traceroute" {
		if err := runTraceroute(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
		return
	}

	if len(os.Args) >= 2 && os.Args[1] == "ca" {
		if err := runCA(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
		return
	}

	if len(os.Args) >= 2 && os.Args[1] == "ula" {
		if err := runULA(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
		return
	}

	configPath := flag.String("config", "", "node YAML config (paths relative to the file)")
	var listens stringList
	flag.Var(&listens, "listen", "bind address, repeatable (`udp:host:port` or `tcp:host:port`)")
	peersFile := flag.String("peers", "", "file of known hops (addr, or pubkey + addr)")
	idFile := flag.String("identity", "", "PEM file for a stable ed25519 key (created if missing)")
	caFile := flag.String("ca", "", "mesh CA certificate PEM")
	certFile := flag.String("cert", "", "this node's CA-signed certificate PEM")
	tunFlag := flag.Bool("tun", false, "bring up a TUN for overlay IPv6")
	userspaceFlag := flag.Bool("userspace", false, "gVisor userspace IPv6 stack (DialTCP/ListenTCP; no root)")
	socksFlag := flag.String("socks", "", "local SOCKS5 listen address (implies userspace), e.g. 127.0.0.1:1080")
	httpFlag := flag.Int("http", 0, "serve a tiny HTTP banner on this overlay TCP port (implies userspace)")
	exitFlag := flag.Bool("exit", false, "advertise as an exit node (SNAT internet traffic; requires --tun)")
	exitNodeFlag := flag.String("exit-node", "", "use named mesh node as exit (installs host defaults; requires --tun)")
	gwFlag := flag.Bool("gateway", true, "this TUN is the host overlay NIC (fd00::/8 and overlay DNS); -gateway=false for extra nodes on the same machine")
	flag.Usage = usage
	flag.Parse()

	ncfg, err := nodeConfigFromFlags(*configPath, listens, *peersFile, *idFile, *caFile, *certFile)
	if err != nil {
		if err == errUsage {
			usage()
			os.Exit(2)
		}
		log.Fatal(err)
	}
	if *tunFlag {
		ncfg.Tun = true
	}
	if *userspaceFlag {
		ncfg.Userspace = true
	}
	if *socksFlag != "" {
		ncfg.Socks = *socksFlag
	}
	if *httpFlag > 0 {
		ncfg.HTTPPort = *httpFlag
	}
	if *exitFlag {
		ncfg.Exit = true
	}
	if *exitNodeFlag != "" {
		ncfg.ExitNode = *exitNodeFlag
	}
	gatewayOnCmdline := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "gateway" {
			gatewayOnCmdline = true
		}
	})
	if gatewayOnCmdline {
		ncfg.Gateway = *gwFlag
	}

	log.SetPrefix("hopscotch ")

	n, err := node.New(ncfg)
	if err != nil {
		log.Fatal(err)
	}
	if err := n.Start(); err != nil {
		log.Fatal(err)
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	log.Printf("shutting down")
	n.Close()
}

var errUsage = fmt.Errorf("usage")

// nodeConfigFromFlags builds a node.Config from a YAML path or discrete CLI flags.
func nodeConfigFromFlags(configPath string, listens []string, peersFile, idFile, caFile, certFile string) (node.Config, error) {
	if configPath != "" {
		f, err := config.Load(configPath)
		if err != nil {
			return node.Config{}, err
		}
		return node.Config{
			Listens:   f.Listen,
			Peers:     f.Peers,
			Identity:  f.Identity,
			CA:        f.CA,
			Cert:      f.Cert,
			Control:   f.Control,
			Tun:       f.Tun,
			Userspace: f.Userspace,
			Socks:     f.Socks,
			Gateway:   f.Gateway,
			Exit:      f.Exit,
			ExitNode:  f.ExitNode,
			Log:       log.Default(),
		}, nil
	}
	if idFile == "" || caFile == "" || certFile == "" {
		return node.Config{}, errUsage
	}
	if len(listens) == 0 && peersFile == "" {
		return node.Config{}, errUsage
	}
	return node.Config{
		Listens:   listens,
		PeersFile: peersFile,
		Identity:  idFile,
		CA:        caFile,
		Cert:      certFile,
		Gateway:   true,
		Log:       log.Default(),
	}, nil
}

// runPing sends an overlay ping via a running node's control socket.
func runPing(args []string) error {
	fs := flag.NewFlagSet("ping", flag.ContinueOnError)
	configPath := fs.String("config", "", "yaml of a running node (uses its control socket)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *configPath == "" || fs.NArg() != 1 {
		return fmt.Errorf("usage: hopscotch ping --config examples/hub/foo.yaml baz")
	}
	target := fs.Arg(0)
	f, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if f.Control == "" {
		return fmt.Errorf("%s: no control socket (set control:)", *configPath)
	}
	conn, err := net.DialTimeout("unix", f.Control, 2*time.Second)
	if err != nil {
		return fmt.Errorf("connect to %s: %w (is that node running?)", f.Control, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(12 * time.Second))
	if err := proto.Write(conn, proto.Message{Type: "ping", Name: target}); err != nil {
		return err
	}
	msg, err := proto.Read(conn)
	if err != nil {
		return err
	}
	if msg.Type == "error" || msg.Error != "" {
		if msg.Error == "" {
			msg.Error = "ping failed"
		}
		return fmt.Errorf("%s", msg.Error)
	}
	via := ""
	if len(msg.Path) > 1 {
		via = " via " + strings.Join(msg.Path[:len(msg.Path)-1], ",")
	}
	fmt.Printf("pong %s hops=%d%s rtt=%.2fms\n", msg.Name, msg.Hops, via, msg.RTTMs)
	return nil
}

// runTraceroute runs an overlay traceroute via a running node's control socket.
func runTraceroute(args []string) error {
	fs := flag.NewFlagSet("traceroute", flag.ContinueOnError)
	configPath := fs.String("config", "", "yaml of a running node (uses its control socket)")
	maxTTL := fs.Int("max-ttl", 16, "maximum IPv6 Hop Limit to probe")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *configPath == "" || fs.NArg() < 1 {
		return fmt.Errorf("usage: hopscotch traceroute --config examples/hub/foo.yaml [--max-ttl 16] baz")
	}
	target := fs.Arg(0)
	f, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if f.Control == "" {
		return fmt.Errorf("%s: no control socket (set control:)", *configPath)
	}
	conn, err := net.DialTimeout("unix", f.Control, 2*time.Second)
	if err != nil {
		return fmt.Errorf("connect to %s: %w (is that node running?)", f.Control, err)
	}
	defer conn.Close()
	deadline := time.Duration(*maxTTL)*time.Second + 10*time.Second
	_ = conn.SetDeadline(time.Now().Add(deadline))
	if err := proto.Write(conn, proto.Message{Type: "traceroute", Name: target, MaxTTL: *maxTTL}); err != nil {
		return err
	}
	msg, err := proto.Read(conn)
	if err != nil {
		return err
	}
	if msg.Type == "error" || msg.Error != "" {
		if msg.Error == "" {
			msg.Error = "traceroute failed"
		}
		return fmt.Errorf("%s", msg.Error)
	}
	fmt.Printf("traceroute to %s (overlay DV, max-ttl=%d)\n", msg.Name, *maxTTL)
	teSeen := map[string]int{}
	unreach := ""
	for _, h := range msg.Trace {
		if h.Timeout {
			fmt.Printf(" %2d  *\n", h.TTL)
			continue
		}
		label := h.Name
		if label == "" {
			label = h.Addr
		} else if h.Addr != "" {
			label = fmt.Sprintf("%s (%s)", h.Name, h.Addr)
		}
		fmt.Printf(" %2d  %s  %.2fms  %s\n", h.TTL, label, h.RTTMs, h.Reply)
		switch h.Reply {
		case "time_exceeded":
			if h.Name != "" {
				teSeen[h.Name]++
			}
		case "dest_unreach":
			if unreach == "" {
				if h.Name != "" {
					unreach = h.Name
				} else {
					unreach = h.Addr
				}
			}
		}
	}
	if msg.Reached {
		fmt.Printf("reached %s\n", msg.Name)
	} else {
		fmt.Printf("not reached\n")
	}
	for name, n := range teSeen {
		if n > 1 {
			fmt.Printf("note: %q sent time_exceeded %d times — possible overlay cycle\n", name, n)
		}
	}
	if unreach != "" && !msg.Reached {
		fmt.Printf("note: stuck at %s (dest_unreach) — no route in the distance-vector table\n", unreach)
	}
	return nil
}

// runCA handles ca init, sign, and bootstrap subcommands for mesh certificates.
func runCA(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: hopscotch ca init|sign|bootstrap")
	}
	switch args[0] {
	case "init":
		fs := flag.NewFlagSet("ca init", flag.ContinueOnError)
		key := fs.String("key", "ca.key", "CA private key PEM")
		cert := fs.String("cert", "ca.crt", "CA certificate PEM")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if err := identity.InitCAFiles(*key, *cert); err != nil {
			return err
		}
		log.Printf("wrote %s and %s", *key, *cert)
		return nil
	case "sign":
		fs := flag.NewFlagSet("ca sign", flag.ContinueOnError)
		caKey := fs.String("ca-key", "ca.key", "CA private key PEM")
		caCert := fs.String("ca-cert", "ca.crt", "CA certificate PEM")
		idFile := fs.String("identity", "node.pem", "node private key PEM (created if missing)")
		out := fs.String("out", "node.crt", "signed node certificate PEM")
		var names stringList
		fs.Var(&names, "name", "mesh name stored in the cert (repeatable)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if err := identity.SignNodeFiles(*caKey, *caCert, *idFile, *out, names...); err != nil {
			return err
		}
		if len(names) > 0 {
			log.Printf("signed %s → %s names=%s", *idFile, *out, strings.Join(names, ","))
		} else {
			log.Printf("signed %s → %s", *idFile, *out)
		}
		return nil
	case "bootstrap":
		fs := flag.NewFlagSet("ca bootstrap", flag.ContinueOnError)
		dir := fs.String("dir", "examples/.local", "directory for ca.key, ca.crt, and per-node pem/crt")
		var nodes stringList
		fs.Var(&nodes, "node", "mesh name to ensure (repeatable); writes <name>.pem and <name>.crt")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if len(nodes) == 0 {
			return fmt.Errorf("ca bootstrap: at least one --node")
		}
		if err := identity.BootstrapDir(*dir, nodes); err != nil {
			return err
		}
		log.Printf("bootstrapped %s (%s)", *dir, strings.Join(nodes, ", "))
		return nil
	default:
		return fmt.Errorf("unknown ca command %q (want init, sign, or bootstrap)", args[0])
	}
}

// runULA prints a mesh ULA: this node's identity, or a name via control socket.
func runULA(args []string) error {
	fs := flag.NewFlagSet("ula", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", "", "node YAML (identity; with a name, uses control socket)")
	idFile := fs.String("identity", "", "node private key PEM")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 1 {
		return fmt.Errorf("usage: hopscotch ula --config node.yaml [name]\n       hopscotch ula --identity node.pem")
	}

	if fs.NArg() == 1 {
		target := fs.Arg(0)
		if *configPath == "" {
			return fmt.Errorf("usage: hopscotch ula --config node.yaml %s", target)
		}
		f, err := config.Load(*configPath)
		if err != nil {
			return err
		}
		if f.Control == "" {
			return fmt.Errorf("%s: no control socket (set control:)", *configPath)
		}
		conn, err := net.DialTimeout("unix", f.Control, 2*time.Second)
		if err != nil {
			return fmt.Errorf("connect to %s: %w (is that node running?)", f.Control, err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(12 * time.Second))
		if err := proto.Write(conn, proto.Message{Type: "ula", Name: target}); err != nil {
			return err
		}
		msg, err := proto.Read(conn)
		if err != nil {
			return err
		}
		if msg.Type == "error" || msg.Error != "" {
			if msg.Error == "" {
				msg.Error = "ula lookup failed"
			}
			return fmt.Errorf("%s", msg.Error)
		}
		if msg.ULA == "" {
			return fmt.Errorf("empty ULA for %q", target)
		}
		fmt.Println(msg.ULA)
		return nil
	}

	identityPath := *idFile
	if *configPath != "" {
		f, err := config.Load(*configPath)
		if err != nil {
			return err
		}
		if identityPath == "" {
			identityPath = f.Identity
		}
	}
	if identityPath == "" {
		return fmt.Errorf("usage: hopscotch ula --config node.yaml [name]\n       hopscotch ula --identity node.pem")
	}
	id, err := identity.IDFromKeyFile(identityPath)
	if err != nil {
		return err
	}
	fmt.Println(id.ULA().String())
	return nil
}
