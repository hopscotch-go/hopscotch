package node

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"io"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hopscotch-go/hopscotch/internal/identity"
	"github.com/hopscotch-go/hopscotch/internal/peers"
)

func TestTwoNodeJoinUDP(t *testing.T) { testTwoNodeJoin(t, "udp") }
func TestTwoNodeJoinTCP(t *testing.T) { testTwoNodeJoin(t, "tcp") }

func TestJoinTCPPeerToDualListener(t *testing.T) {
	dir := t.TempDir()
	caPath, caCert, caKey := writeCA(t, dir)
	a := startNode(t, dir, "a", caPath, caCert, caKey, Config{
		Listens: []string{"udp:127.0.0.1:0", "tcp:127.0.0.1:0"},
	})
	defer a.Close()
	if len(a.AdvertiseAddrs()) != 2 {
		t.Fatalf("advertise %v", a.AdvertiseAddrs())
	}

	b := startNode(t, dir, "b", caPath, caCert, caKey, Config{
		Listen:  "127.0.0.1:0",
		Network: "udp",
		Peers:   []peers.Peer{{Addr: a.AdvertiseByNetwork("tcp")}},
	})
	defer b.Close()
	waitPeers(t, a, 1)
	waitPeers(t, b, 1)
}

func testTwoNodeJoin(t *testing.T, network string) {
	t.Helper()
	dir := t.TempDir()
	a, b := startPair(t, dir, network)
	defer a.Close()
	defer b.Close()
	waitPeers(t, a, 1)
	waitPeers(t, b, 1)
}

func TestRequiresCA(t *testing.T) {
	dir := t.TempDir()
	_, err := New(Config{
		Listen:   "127.0.0.1:0",
		Identity: filepath.Join(dir, "a.pem"),
	})
	if err == nil {
		t.Fatal("expected error without ca and cert")
	}
}

func TestOurCertMustMatchCA(t *testing.T) {
	dir := t.TempDir()
	caPath, _, _ := writeCA(t, dir)
	otherPath := filepath.Join(dir, "other.crt")
	_, otherCA, otherKey := writeCAAs(t, otherPath)
	id, cert := signNode(t, dir, "x", otherCA, otherKey)
	_, err := New(Config{
		Listen:   "127.0.0.1:0",
		Identity: id,
		CA:       caPath,
		Cert:     cert,
	})
	if err == nil {
		t.Fatal("expected error when our cert is not signed by --ca")
	}
}

func TestCANamesOnSession(t *testing.T) {
	dir := t.TempDir()
	caPath, caCert, caKey := writeCA(t, dir)
	a := startNode(t, dir, "foo", caPath, caCert, caKey, Config{
		Listen:  "127.0.0.1:0",
		Network: "udp",
	})
	defer a.Close()
	b := startNode(t, dir, "bar", caPath, caCert, caKey, Config{
		Listen:  "127.0.0.1:0",
		Network: "udp",
		Peers:   []peers.Peer{{Addr: a.AdvertiseAddr()}},
	})
	defer b.Close()
	waitPeers(t, a, 1)
	waitPeers(t, b, 1)
	if got := a.Names(); len(got) != 1 || got[0] != "foo" {
		t.Fatalf("a names %v", got)
	}
	if got := a.NamesOf(b.ID()); len(got) != 1 || got[0] != "bar" {
		t.Fatalf("a sees b as %v", got)
	}
	if got := b.NamesOf(a.ID()); len(got) != 1 || got[0] != "foo" {
		t.Fatalf("b sees a as %v", got)
	}
}

func TestCARejectsForeignCA(t *testing.T) {
	dir := t.TempDir()
	caPath, caCert, caKey := writeCA(t, dir)
	a := startNode(t, dir, "a", caPath, caCert, caKey, Config{
		Listen:  "127.0.0.1:0",
		Network: "udp",
	})
	defer a.Close()
	b := startNode(t, dir, "b", caPath, caCert, caKey, Config{
		Listen:  "127.0.0.1:0",
		Network: "udp",
		Peers:   []peers.Peer{{Addr: a.AdvertiseAddr()}},
	})
	defer b.Close()
	waitPeers(t, a, 1)

	otherPath := filepath.Join(dir, "other.crt")
	_, otherCA, otherKey := writeCAAs(t, otherPath)
	c := startNode(t, dir, "c", otherPath, otherCA, otherKey, Config{
		Listen:  "127.0.0.1:0",
		Network: "udp",
		Peers:   []peers.Peer{{Addr: a.AdvertiseAddr()}},
	})
	defer c.Close()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if c.PeerCount() != 0 {
			t.Fatalf("foreign-CA node joined the mesh")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if a.PeerCount() != 1 {
		t.Fatalf("CA node lost its signed peer, count=%d", a.PeerCount())
	}
}

func TestHubStarEcho(t *testing.T) {
	dir := t.TempDir()
	caPath, caCert, caKey := writeCA(t, dir)
	bar := startNode(t, dir, "bar", caPath, caCert, caKey, Config{
		Listen:  "127.0.0.1:0",
		Network: "udp",
	})
	defer bar.Close()
	foo := startNode(t, dir, "foo", caPath, caCert, caKey, Config{
		Peers:   []peers.Peer{{Addr: bar.AdvertiseAddr()}},
		Control: filepath.Join(dir, "foo.sock"),
	})
	defer foo.Close()
	baz := startNode(t, dir, "baz", caPath, caCert, caKey, Config{
		Peers: []peers.Peer{{Addr: bar.AdvertiseAddr()}},
	})
	defer baz.Close()
	waitPeers(t, foo, 1)
	waitPeers(t, baz, 1)
	waitPeers(t, bar, 2)
	if foo.PeerCount() != 1 || baz.PeerCount() != 1 {
		t.Fatalf("star broke: foo=%d baz=%d bar=%d", foo.PeerCount(), baz.PeerCount(), bar.PeerCount())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, err := foo.Echo(ctx, "baz")
	if err != nil {
		t.Fatal(err)
	}
	if got.Hops < 2 {
		t.Fatalf("expected path through bar, hops=%d path=%v", got.Hops, got.Path)
	}
	if got.Name != "baz" {
		t.Fatalf("name %s", got.Name)
	}
}

func TestJoinRedials(t *testing.T) {
	dir := t.TempDir()
	caPath, caCert, caKey := writeCA(t, dir)
	hub := startNode(t, dir, "hub", caPath, caCert, caKey, Config{
		Listen:  "127.0.0.1:0",
		Network: "udp",
	})
	addr := hub.AdvertiseAddr()
	spoke := startNode(t, dir, "spoke", caPath, caCert, caKey, Config{
		Peers: []peers.Peer{{Addr: addr}},
	})
	defer spoke.Close()
	waitPeers(t, spoke, 1)
	waitPeers(t, hub, 1)
	hub.Close()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && spoke.PeerCount() != 0 {
		time.Sleep(20 * time.Millisecond)
	}
	if spoke.PeerCount() != 0 {
		t.Fatal("spoke still connected after hub close")
	}
	hub2 := startNode(t, dir, "hub2", caPath, caCert, caKey, Config{
		Listen:  addr,
		Network: "udp",
	})
	defer hub2.Close()
	waitPeers(t, spoke, 1)
	waitPeers(t, hub2, 1)
}

func startPair(t *testing.T, dir, network string) (*Node, *Node) {
	t.Helper()
	caPath, caCert, caKey := writeCA(t, dir)
	a := startNode(t, dir, "a", caPath, caCert, caKey, Config{
		Listen:  "127.0.0.1:0",
		Network: network,
	})
	b := startNode(t, dir, "b", caPath, caCert, caKey, Config{
		Listen:  "127.0.0.1:0",
		Network: network,
		Peers:   []peers.Peer{{Addr: a.AdvertiseByNetwork(network)}},
	})
	return a, b
}

func startNode(t *testing.T, dir, name, caPath string, ca *x509.Certificate, caKey ed25519.PrivateKey, cfg Config) *Node {
	t.Helper()
	id, cert := signNode(t, dir, name, ca, caKey)
	cfg.Identity = id
	cfg.Cert = cert
	cfg.CA = caPath
	if cfg.Log == nil {
		cfg.Log = log.New(&testWriter{t: t, name: name}, "", 0)
	}
	n, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Start(); err != nil {
		t.Fatal(err)
	}
	return n
}

func writeCA(t *testing.T, dir string) (string, *x509.Certificate, ed25519.PrivateKey) {
	t.Helper()
	return writeCAAs(t, filepath.Join(dir, "ca.crt"))
}

func writeCAAs(t *testing.T, caPath string) (string, *x509.Certificate, ed25519.PrivateKey) {
	t.Helper()
	c, k, err := identity.CreateCA()
	if err != nil {
		t.Fatal(err)
	}
	if err := identity.WriteCert(caPath, c); err != nil {
		t.Fatal(err)
	}
	return caPath, c, k
}

func signNode(t *testing.T, dir, name string, ca *x509.Certificate, caKey ed25519.PrivateKey) (string, string) {
	t.Helper()
	idPath := filepath.Join(dir, name+".pem")
	certPath := filepath.Join(dir, name+".crt")
	priv, err := identity.LoadOrCreate(idPath)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	cert, err := identity.SignNode(ca, caKey, pub, name)
	if err != nil {
		t.Fatal(err)
	}
	if err := identity.WriteCert(certPath, cert); err != nil {
		t.Fatal(err)
	}
	return idPath, certPath
}

func TestJoinViaPeersFile(t *testing.T) {
	dir := t.TempDir()
	caPath, caCert, caKey := writeCA(t, dir)
	a := startNode(t, dir, "a", caPath, caCert, caKey, Config{
		Listen:  "127.0.0.1:0",
		Network: "udp",
	})
	defer a.Close()

	peersPath := filepath.Join(dir, "peers.txt")
	if err := os.WriteFile(peersPath, []byte(a.AdvertiseAddr()+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	b := startNode(t, dir, "b", caPath, caCert, caKey, Config{
		Listen:    "127.0.0.1:0",
		Network:   "udp",
		PeersFile: peersPath,
	})
	defer b.Close()
	waitPeers(t, a, 1)
	waitPeers(t, b, 1)
}

func TestPeerPinRejectsWrongKey(t *testing.T) {
	dir := t.TempDir()
	caPath, caCert, caKey := writeCA(t, dir)
	a := startNode(t, dir, "a", caPath, caCert, caKey, Config{
		Listen:  "127.0.0.1:0",
		Network: "udp",
	})
	defer a.Close()

	wrong := bytes.Repeat([]byte{0xab}, 32)
	b := startNode(t, dir, "b", caPath, caCert, caKey, Config{
		Listen:  "127.0.0.1:0",
		Network: "udp",
		Peers:   []peers.Peer{{Addr: a.AdvertiseAddr(), Pub: wrong}},
	})
	defer b.Close()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if b.PeerCount() != 0 {
			t.Fatal("pinned wrong key but still joined")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func waitPeers(t *testing.T, n *Node, want int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if n.PeerCount() >= want {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("want %d peers, got %d", want, n.PeerCount())
}

type testWriter struct {
	t    *testing.T
	name string
}

func (w *testWriter) Write(p []byte) (int, error) {
	w.t.Helper()
	w.t.Logf("%s %s", w.name, bytes.TrimRight(p, "\n"))
	return len(p), nil
}

var _ io.Writer = (*testWriter)(nil)
