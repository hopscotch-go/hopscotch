package node

import (
	"net"
	"sort"
	"time"

	"github.com/hopscotch-go/hopscotch/internal/identity"
	"github.com/hopscotch-go/hopscotch/internal/kademlia"
)

const (
	dialCloserSyncWait   = 500 * time.Millisecond
	dialExactSyncWait    = 2 * time.Second
	dialCloserMaxSync    = 4
	lookupCloserCooldown = 2 * time.Second
)

// ensureCloserSessions tries to open QUIC sessions so nextHop(dst, from)
// can succeed — preferably an exact ULA match to dst, else a progress hop.
func (n *Node) ensureCloserSessions(dst net.IP, from *session) {
	if n.nextHop(dst, from) != nil {
		return
	}
	hint := nodeIDHintFromULA(dst)
	n.kickLookupCloser(dst)

	for attempt := 0; attempt < 4; attempt++ {
		n.harvestCloser(hint)
		// After learning new contacts, also ask any newly connected peers.
		cands := mergeContacts(n.exactContacts(dst), n.closerContacts(dst))
		cands = mergeContacts(cands, n.nearestContacts(dst, dialCloserMaxSync))
		if len(cands) == 0 {
			return
		}
		// Prefer exact destination first.
		sort.SliceStable(cands, func(i, j int) bool {
			iExact := cands[i].ID.ULA().Equal(dst)
			jExact := cands[j].ID.ULA().Equal(dst)
			if iExact != jExact {
				return iExact
			}
			return false
		})
		c := cands[0]
		wait := dialCloserSyncWait
		if c.ID.ULA().Equal(dst) {
			wait = dialExactSyncWait
		}
		n.dialContactWait(c, wait)
		if n.nextHop(dst, from) != nil {
			return
		}
		for _, extra := range cands[1:] {
			go n.dialContact(extra)
		}
	}
}

func mergeContacts(a, b []kademlia.Contact) []kademlia.Contact {
	seen := make(map[identity.NodeID]bool, len(a)+len(b))
	var out []kademlia.Contact
	for _, c := range a {
		if seen[c.ID] {
			continue
		}
		seen[c.ID] = true
		out = append(out, c)
	}
	for _, c := range b {
		if seen[c.ID] || len(c.Addrs) == 0 {
			continue
		}
		seen[c.ID] = true
		out = append(out, c)
	}
	return out
}

func (n *Node) exactContacts(dst net.IP) []kademlia.Contact {
	var out []kademlia.Contact
	for _, c := range n.table.Contacts() {
		if c.ID == n.id || len(c.Addrs) == 0 || n.session(c.ID) != nil {
			continue
		}
		if c.ID.ULA().Equal(dst) {
			out = append(out, c)
		}
	}
	return out
}

// nearestContacts returns table contacts with no live session, closest to
// dst by ULA XOR — used for dial-on-demand even when they are not closer
// than self (e.g. dial the destination itself for an exact nextHop match).
func (n *Node) nearestContacts(dst net.IP, limit int) []kademlia.Contact {
	var out []kademlia.Contact
	for _, c := range n.table.Contacts() {
		if c.ID == n.id || len(c.Addrs) == 0 || n.session(c.ID) != nil {
			continue
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		iExact := out[i].ID.ULA().Equal(dst)
		jExact := out[j].ID.ULA().Equal(dst)
		if iExact != jExact {
			return iExact
		}
		return identity.CloserULA(dst, out[i].ID.ULA(), out[j].ID.ULA())
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func (n *Node) harvestCloser(hint identity.NodeID) {
	for _, s := range n.sessionList() {
		c := kademlia.Contact{ID: s.id, Addrs: contactAddrs(nil, s.addr)}
		if len(c.Addrs) == 0 {
			continue
		}
		got, err := n.queryFindNode(c, hint)
		if err != nil {
			continue
		}
		for _, next := range got {
			if next.ID == n.id || len(next.Addrs) == 0 || n.allSelfAddrs(next.Addrs) {
				continue
			}
			n.table.Insert(next)
		}
	}
}

func (n *Node) closerContacts(dst net.IP) []kademlia.Contact {
	self := n.id.ULA()
	var out []kademlia.Contact
	for _, c := range n.table.Contacts() {
		if c.ID == n.id || len(c.Addrs) == 0 {
			continue
		}
		if n.session(c.ID) != nil {
			continue
		}
		if !identity.CloserULA(dst, c.ID.ULA(), self) {
			continue
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		iExact := out[i].ID.ULA().Equal(dst)
		jExact := out[j].ID.ULA().Equal(dst)
		if iExact != jExact {
			return iExact
		}
		return identity.CloserULA(dst, out[i].ID.ULA(), out[j].ID.ULA())
	})
	return out
}

func (n *Node) dialContact(c kademlia.Contact) {
	if n.session(c.ID) != nil {
		return
	}
	for _, addr := range c.Addrs {
		if addr == "" || n.isSelfAddr(addr) {
			continue
		}
		if _, err := n.dial(addr); err == nil {
			return
		}
	}
}

func (n *Node) dialContactWait(c kademlia.Contact, wait time.Duration) {
	if n.session(c.ID) != nil {
		return
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		n.dialContact(c)
	}()
	select {
	case <-done:
	case <-time.After(wait):
	case <-n.ctx.Done():
	}
}

func (n *Node) kickLookupCloser(dst net.IP) {
	key := dst.String()
	now := time.Now()
	n.mu.Lock()
	if n.lookupCloserAt == nil {
		n.lookupCloserAt = make(map[string]time.Time)
	}
	if t, ok := n.lookupCloserAt[key]; ok && now.Sub(t) < lookupCloserCooldown {
		n.mu.Unlock()
		return
	}
	n.lookupCloserAt[key] = now
	n.mu.Unlock()

	hint := nodeIDHintFromULA(dst)
	go func() {
		_ = n.lookup(hint)
		for _, c := range mergeContacts(n.exactContacts(dst), n.closerContacts(dst)) {
			go n.dialContact(c)
		}
	}()
}

// nodeIDHintFromULA builds a FIND_NODE target that shares the ULA's
// embedded NodeID bits so iterative lookup walks toward similar IDs.
func nodeIDHintFromULA(ula net.IP) identity.NodeID {
	var id identity.NodeID
	u := ula.To16()
	if u == nil {
		return id
	}
	copy(id[0:5], u[1:6])
	copy(id[24:32], u[8:16])
	return id
}
