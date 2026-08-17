package node

import (
	"testing"

	"github.com/hopscotch-go/hopscotch/internal/identity"
)

func TestEncapsulateDecapsulateIPv4(t *testing.T) {
	client := identity.NodeID{1, 2, 3}.ULA()
	exit := identity.NodeID{4, 5, 6}.ULA()
	inner := []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0, 1, 2, 3, 4, 8, 8, 8, 8}
	pkt := encapsulateExit(client, exit, inner)
	if pkt == nil {
		t.Fatal("nil encap")
	}
	src, got, ok := decapsulateExit(pkt, exit)
	if !ok {
		t.Fatal("decap failed")
	}
	if !src.Equal(client) {
		t.Fatalf("src %s", src)
	}
	if string(got) != string(inner) {
		t.Fatalf("inner mismatch")
	}
}

func TestPlumbingIPv4(t *testing.T) {
	ula := identity.NodeID{9, 8, 7}.ULA()
	ip := PlumbingIPv4(ula)
	if ip == nil || ip.To4() == nil || ip.To4()[0] != 100 {
		t.Fatalf("%v", ip)
	}
	if PlumbingIPv4(ula).Equal(PlumbingIPv4(identity.NodeID{1}.ULA())) && ula.Equal(identity.NodeID{1}.ULA()) {
		t.Fatal("unexpected")
	}
}
