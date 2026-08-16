package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"
)

func TestULAIsUniqueLocal(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := IDFromPublic(priv.Public().(ed25519.PublicKey))
	ip := id.ULA()
	if !IsMeshULA(ip) {
		t.Fatalf("%s", ip)
	}
	if ip.String() != id.ULA().String() {
		t.Fatal("ULA not stable")
	}
}

func TestIsMeshULA(t *testing.T) {
	if !IsMeshULA(net.ParseIP("fd00::1")) {
		t.Fatal("fd00::1")
	}
	if IsMeshULA(net.ParseIP("fe80::1")) {
		t.Fatal("link-local")
	}
	if IsMeshULA(net.ParseIP("10.0.0.1")) {
		t.Fatal("v4")
	}
}

func TestResolverULA(t *testing.T) {
	ip := ResolverULA()
	if ip.String() != "fd00::53" {
		t.Fatalf("%s", ip)
	}
	if !IsMeshULA(ip) || !IsResolverULA(ip) {
		t.Fatal("resolver ULA")
	}
	if IsResolverULA(net.ParseIP("fd00::1")) {
		t.Fatal("node ULA is not resolver")
	}
}

func TestCloserULA(t *testing.T) {
	target := net.ParseIP("fd00::aa")
	near := net.ParseIP("fd00::ab")
	far := net.ParseIP("fd00::ff")
	if !CloserULA(target, near, far) {
		t.Fatal("near should win")
	}
	if CloserULA(target, far, near) {
		t.Fatal("far should lose")
	}
}
