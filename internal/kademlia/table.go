package kademlia

import (
	"bytes"
	"math/bits"
	"sort"
	"sync"
	"time"

	"github.com/hopscotch-go/hopscotch/internal/identity"
)

const (
	K     = 20 // contacts per bucket
	Alpha = 3  // parallel FIND_NODE queries
	Bits  = 256
)

type Contact struct {
	ID       identity.NodeID
	Addrs    []string
	LastSeen time.Time
}

func (c Contact) Addr() string {
	if len(c.Addrs) == 0 {
		return ""
	}
	return c.Addrs[0]
}

type Table struct {
	self    identity.NodeID
	mu      sync.Mutex
	buckets [Bits][]Contact
}

func NewTable(self identity.NodeID) *Table {
	return &Table{self: self}
}

func Distance(a, b identity.NodeID) (d identity.NodeID) {
	for i := 0; i < len(a); i++ {
		d[i] = a[i] ^ b[i]
	}
	return d
}

// BucketIndex is the bit position of the first 1 in self XOR id
// (0 = farthest prefix, 255 = closest). Returns -1 if id == self.
func BucketIndex(self, id identity.NodeID) int {
	d := Distance(self, id)
	for i, b := range d[:] {
		if b != 0 {
			return i*8 + bits.LeadingZeros8(b)
		}
	}
	return -1
}

func Closer(target, a, b identity.NodeID) bool {
	da := Distance(target, a)
	db := Distance(target, b)
	return bytes.Compare(da[:], db[:]) < 0
}

func (t *Table) Insert(c Contact) {
	if c.ID == t.self {
		return
	}
	if len(c.Addrs) == 0 {
		return
	}
	idx := BucketIndex(t.self, c.ID)
	if idx < 0 {
		return
	}
	c.LastSeen = time.Now()

	t.mu.Lock()
	defer t.mu.Unlock()
	b := t.buckets[idx]
	for i, x := range b {
		if x.ID == c.ID {
			x.Addrs = mergeAddrs(x.Addrs, c.Addrs)
			x.LastSeen = c.LastSeen
			t.buckets[idx] = append(append(b[:i], b[i+1:]...), x)
			return
		}
	}
	if len(b) < K {
		t.buckets[idx] = append(b, c)
	}
}

func (t *Table) Remove(id identity.NodeID) {
	idx := BucketIndex(t.self, id)
	if idx < 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	b := t.buckets[idx]
	for i, x := range b {
		if x.ID == id {
			t.buckets[idx] = append(b[:i], b[i+1:]...)
			return
		}
	}
}

func (t *Table) Get(id identity.NodeID) (Contact, bool) {
	idx := BucketIndex(t.self, id)
	if idx < 0 {
		return Contact{}, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, x := range t.buckets[idx] {
		if x.ID == id {
			return x, true
		}
	}
	return Contact{}, false
}

func (t *Table) Closest(target identity.NodeID, n int) []Contact {
	all := t.Contacts()
	sort.Slice(all, func(i, j int) bool {
		return Closer(target, all[i].ID, all[j].ID)
	})
	if n > len(all) {
		n = len(all)
	}
	return all[:n]
}

func (t *Table) Contacts() []Contact {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []Contact
	for _, b := range t.buckets {
		out = append(out, b...)
	}
	return out
}

func (t *Table) Size() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for _, b := range t.buckets {
		n += len(b)
	}
	return n
}

func mergeAddrs(old, add []string) []string {
	seen := make(map[string]bool, len(old)+len(add))
	var out []string
	for _, a := range old {
		if a == "" || seen[a] {
			continue
		}
		seen[a] = true
		out = append(out, a)
	}
	for _, a := range add {
		if a == "" || seen[a] {
			continue
		}
		seen[a] = true
		out = append(out, a)
	}
	return out
}
