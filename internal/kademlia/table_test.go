package kademlia

import (
	"testing"

	"github.com/hopscotch-go/hopscotch/internal/identity"
)

func idAtBit(bit int) identity.NodeID {
	var id identity.NodeID
	id[bit/8] = 1 << (7 - uint(bit%8))
	return id
}

func TestBucketIndex(t *testing.T) {
	var self identity.NodeID
	if BucketIndex(self, self) != -1 {
		t.Fatal("self should not land in a bucket")
	}
	if got := BucketIndex(self, idAtBit(0)); got != 0 {
		t.Fatalf("bit 0: got bucket %d", got)
	}
	if got := BucketIndex(self, idAtBit(9)); got != 9 {
		t.Fatalf("bit 9: got bucket %d", got)
	}
	if got := BucketIndex(self, idAtBit(255)); got != 255 {
		t.Fatalf("bit 255: got bucket %d", got)
	}
}

func TestClosest(t *testing.T) {
	var self identity.NodeID
	tb := NewTable(self)
	far := Contact{ID: idAtBit(0), Addrs: []string{"1:1"}}
	near := Contact{ID: idAtBit(200), Addrs: []string{"1:2"}}
	mid := Contact{ID: idAtBit(40), Addrs: []string{"1:3"}}
	tb.Insert(far)
	tb.Insert(near)
	tb.Insert(mid)

	got := tb.Closest(self, 3)
	if len(got) != 3 || got[0].ID != near.ID || got[1].ID != mid.ID || got[2].ID != far.ID {
		t.Fatalf("order: %+v", got)
	}
}

func TestBucketCap(t *testing.T) {
	var self identity.NodeID
	tb := NewTable(self)
	// all of these share bucket 0 (first bit set, rest can vary in lower bits
	// wait - idAtBit(0) is only one ID. Use IDs with bit 0 set and unique lower bits.
	for i := 0; i < K+5; i++ {
		var id identity.NodeID
		id[0] = 0x80
		id[31] = byte(i + 1)
		tb.Insert(Contact{ID: id, Addrs: []string{"x"}})
	}
	if tb.Size() != K {
		t.Fatalf("size %d want %d", tb.Size(), K)
	}
}

func TestInsertUpdatesAddr(t *testing.T) {
	var self identity.NodeID
	tb := NewTable(self)
	id := idAtBit(3)
	tb.Insert(Contact{ID: id, Addrs: []string{"old"}})
	tb.Insert(Contact{ID: id, Addrs: []string{"new"}})
	c, ok := tb.Get(id)
	if !ok || len(c.Addrs) != 2 || c.Addrs[0] != "old" || c.Addrs[1] != "new" {
		t.Fatalf("got %+v ok=%v", c, ok)
	}
}
