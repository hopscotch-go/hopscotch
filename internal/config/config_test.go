package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadScalarListenAndPeers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "n.yaml")
	pub := strings.Repeat("ab", 32)
	if err := os.WriteFile(path, []byte(`
identity: ./keys/n.pem
ca: ./keys/ca.crt
cert: ./keys/n.crt
listen: 127.0.0.1:4433
peers:
  - udp:10.0.0.1:9
  - addr: tcp:10.0.0.2:8
    pubkey: `+pub+`
`), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if f.Identity != filepath.Join(dir, "keys", "n.pem") {
		t.Fatalf("identity %s", f.Identity)
	}
	if f.CA != filepath.Join(dir, "keys", "ca.crt") || f.Cert != filepath.Join(dir, "keys", "n.crt") {
		t.Fatalf("ca/cert %s %s", f.CA, f.Cert)
	}
	if len(f.Listen) != 1 || f.Listen[0] != "127.0.0.1:4433" {
		t.Fatalf("listen %v", f.Listen)
	}
	if len(f.Peers) != 2 {
		t.Fatalf("peers %v", f.Peers)
	}
	if f.Peers[0].Addr != "udp:10.0.0.1:9" || f.Peers[0].Pub != nil {
		t.Fatalf("peer0 %+v", f.Peers[0])
	}
	if f.Peers[1].Addr != "tcp:10.0.0.2:8" || len(f.Peers[1].Pub) != 32 {
		t.Fatalf("peer1 %+v", f.Peers[1])
	}
}

func TestLoadListenList(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "n.yaml")
	if err := os.WriteFile(path, []byte(`
identity: n.pem
ca: ca.crt
cert: n.crt
listen:
  - udp:127.0.0.1:4433
  - tcp:127.0.0.1:4433
`), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Listen) != 2 {
		t.Fatalf("listen %v", f.Listen)
	}
}

func TestLoadRejectsUnknownField(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "n.yaml")
	if err := os.WriteFile(path, []byte(`
identity: n.pem
ca: ca.crt
cert: n.crt
listen: 127.0.0.1:1
open: true
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected unknown field error")
	}
}

func TestLoadExampleHub(t *testing.T) {
	bar, err := Load(filepath.Join("..", "..", "examples", "hub", "bar.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(bar.Listen) != 1 || bar.Listen[0] != "udp:127.0.0.1:4434" {
		t.Fatalf("listen %v", bar.Listen)
	}
	if len(bar.Peers) != 1 || bar.Peers[0].Addr != "udp:127.0.0.1:4435" {
		t.Fatalf("bar peers %+v", bar.Peers)
	}
	foo, err := Load(filepath.Join("..", "..", "examples", "hub", "foo.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(foo.Peers) != 1 || foo.Peers[0].Addr != "udp:127.0.0.1:4434" {
		t.Fatalf("foo peers %+v", foo.Peers)
	}
	if len(foo.Listen) != 0 {
		t.Fatalf("foo should be dial-only, listen %v", foo.Listen)
	}
	if !strings.HasSuffix(foo.Control, filepath.Join("examples", ".local", "foo.sock")) {
		t.Fatalf("control %s", foo.Control)
	}
	if !strings.HasSuffix(bar.Identity, filepath.Join("examples", ".local", "bar.pem")) {
		t.Fatalf("identity %s", bar.Identity)
	}
	if !foo.Gateway {
		t.Fatal("foo is the host overlay NIC")
	}
	if bar.Gateway {
		t.Fatal("bar is an extra node on this Mac")
	}
	baz, err := Load(filepath.Join("..", "..", "examples", "hub", "baz.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !baz.Gateway {
		t.Fatal("baz gateway defaults true")
	}
	if len(baz.Listen) != 1 || baz.Listen[0] != "udp:127.0.0.1:4435" {
		t.Fatalf("baz listen %v", baz.Listen)
	}
	if len(baz.Peers) != 0 {
		t.Fatalf("baz should be dialed, got peers %+v", baz.Peers)
	}
}

func TestLoadTun(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "n.yaml")
	if err := os.WriteFile(path, []byte(`
identity: n.pem
ca: ca.crt
cert: n.crt
listen: 127.0.0.1:1
tun: true
`), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !f.Tun {
		t.Fatal("tun")
	}
	if !f.Gateway {
		t.Fatal("gateway should default true")
	}
}

func TestLoadGatewayFalse(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "n.yaml")
	if err := os.WriteFile(path, []byte(`
identity: n.pem
ca: ca.crt
cert: n.crt
listen: 127.0.0.1:1
gateway: false
`), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if f.Gateway {
		t.Fatal("gateway")
	}
}

func TestLoadRequiresListen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "n.yaml")
	if err := os.WriteFile(path, []byte(`
identity: n.pem
ca: ca.crt
cert: n.crt
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected missing listen or peers")
	}
}
