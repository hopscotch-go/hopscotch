package node

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/hopscotch-go/hopscotch/internal/identity"
	"github.com/hopscotch-go/hopscotch/internal/proto"
)

// Hop-count distance-vector over live QUIC sessions. Overlay nextHop looks
// up the RIB; membership is configured peers plus inbound dials.
const (
	routeInfinity = 16
	routeRefresh  = 15 * time.Second
	// routeHolddown keeps a dest learned via a peer across one sparse
	// advertisement (session churn). Real withdraws clear after this
	// elapses without the dest reappearing in that peer's updates.
	routeHolddown = 3 * time.Second
)

type ribEntry struct {
	next  identity.NodeID
	metric int
	stale time.Time // non-zero: missing from peer ads since this time
}

// RouteInfo is a snapshot of one RIB entry for logging / introspection.
type RouteInfo struct {
	Dest   string // destination name or ULA
	DestIP string
	Next   string // next-hop name or short id
	Metric int
}

// onSessionUp installs a direct RIB route for a new peer and advertises.
func (n *Node) onSessionUp(s *session) {
	dest := s.id.ULA().String()
	n.routeMu.Lock()
	if n.routes == nil {
		n.routes = make(map[string]ribEntry)
	}
	n.routes[dest] = ribEntry{next: s.id, metric: 1}
	n.routeMu.Unlock()
	n.logRoutes("session up", peerLabel(s.id, s.names))
	n.sendRoutesTo(s)
	n.advertiseRoutes()
}

// onSessionDown withdraws RIB entries via a dead peer and re-advertises.
func (n *Node) onSessionDown(s *session) {
	if s == nil {
		return
	}
	n.mu.Lock()
	cur := n.sessions[s.id]
	n.mu.Unlock()
	if cur != nil && cur != s {
		return // replaced by a newer session; keep routes
	}
	id := s.id
	n.routeMu.Lock()
	changed := false
	for dest, e := range n.routes {
		if e.next == id {
			delete(n.routes, dest)
			changed = true
		}
	}
	n.routeMu.Unlock()
	if changed {
		n.logRoutes("session down", peerLabel(id, s.names))
		n.advertiseRoutes()
	}
	n.releaseUnderlayPin(s.underlayIP)
}

// handleRoutes applies a peer's distance-vector update to the RIB.
func (n *Node) handleRoutes(from *session, msg proto.Message) {
	if from == nil {
		return
	}
	self := n.id.ULA().String()
	changed := false
	n.routeMu.Lock()
	if n.routes == nil {
		n.routes = make(map[string]ribEntry)
	}
	// Direct neighbor is always one hop, regardless of advertisements.
	peerULA := from.id.ULA().String()
	if cur, ok := n.routes[peerULA]; !ok || cur.next != from.id || cur.metric != 1 {
		n.routes[peerULA] = ribEntry{next: from.id, metric: 1}
		changed = true
	}
	seen := map[string]bool{peerULA: true}
	for _, r := range msg.Routes {
		dest := r.Dest
		if isDefaultRouteDest(dest) {
			// ok
		} else {
			ip := net.ParseIP(r.Dest)
			if ip == nil || !identity.IsMeshULA(ip) || identity.IsResolverULA(ip) {
				continue
			}
			dest = ip.String()
		}
		if dest == self {
			continue
		}
		seen[dest] = true
		metric := r.Metric + 1
		if r.Metric >= routeInfinity || metric >= routeInfinity {
			if cur, ok := n.routes[dest]; ok && cur.next == from.id {
				delete(n.routes, dest)
				changed = true
			}
			continue
		}
		cur, ok := n.routes[dest]
		if !ok || cur.next == from.id || metric < cur.metric {
			if !ok || cur.next != from.id || cur.metric != metric || !cur.stale.IsZero() {
				n.routes[dest] = ribEntry{next: from.id, metric: metric}
				changed = true
			}
		}
	}
	// Implicit withdraw with holddown: mark missing, delete only after
	// routeHolddown without re-advertisement (avoids sparse-ad flaps).
	now := time.Now()
	for dest, e := range n.routes {
		if e.next != from.id || seen[dest] {
			continue
		}
		if e.stale.IsZero() {
			e.stale = now
			n.routes[dest] = e
			continue
		}
		if now.Sub(e.stale) >= routeHolddown {
			delete(n.routes, dest)
			changed = true
		}
	}
	n.routeMu.Unlock()
	if changed {
		n.logRoutes("from "+peerLabel(from.id, from.names), "")
		n.advertiseRoutes()
	}
}

// expireStaleRoutes deletes holddown-expired RIB entries and re-advertises.
func (n *Node) expireStaleRoutes() {
	now := time.Now()
	changed := false
	n.routeMu.Lock()
	for dest, e := range n.routes {
		if e.stale.IsZero() || now.Sub(e.stale) < routeHolddown {
			continue
		}
		delete(n.routes, dest)
		changed = true
	}
	n.routeMu.Unlock()
	if changed {
		n.logRoutes("holddown expire", "")
		n.advertiseRoutes()
	}
}

// advertiseRoutes pushes this node's RIB view to all live sessions.
func (n *Node) advertiseRoutes() {
	for _, s := range n.sessionList() {
		n.sendRoutesTo(s)
	}
}

// sendRoutesTo sends a split-horizon route advertisement to s.
func (n *Node) sendRoutesTo(s *session) {
	if s == nil {
		return
	}
	routes := make([]proto.Route, 0, 16)
	routes = append(routes, proto.Route{Dest: n.id.ULA().String(), Metric: 0})
	if n.cfg.Exit {
		routes = append(routes,
			proto.Route{Dest: defaultRouteV6, Metric: 0},
			proto.Route{Dest: defaultRouteV4, Metric: 0},
		)
	}
	n.routeMu.Lock()
	for dest, e := range n.routes {
		if e.next == s.id {
			continue // split horizon
		}
		if e.metric >= routeInfinity {
			continue
		}
		routes = append(routes, proto.Route{Dest: dest, Metric: e.metric})
	}
	n.routeMu.Unlock()
	if n.cfg.LogOverlay {
		parts := make([]string, 0, len(routes))
		for _, r := range routes {
			parts = append(parts, fmt.Sprintf("%s=%d", n.ulaLabel(r.Dest), r.Metric))
		}
		n.log.Printf("routes advertise → %s [%s]", peerLabel(s.id, s.names), strings.Join(parts, " "))
	}
	_ = n.write(s, proto.Message{Type: "routes", Routes: routes})
}

// Routes returns a stable snapshot of the RIB (sorted by dest label).
func (n *Node) Routes() []RouteInfo {
	n.routeMu.Lock()
	type pair struct {
		dest string
		e    ribEntry
	}
	raw := make([]pair, 0, len(n.routes))
	for dest, e := range n.routes {
		raw = append(raw, pair{dest, e})
	}
	n.routeMu.Unlock()

	out := make([]RouteInfo, 0, len(raw))
	for _, p := range raw {
		out = append(out, RouteInfo{
			Dest:   n.ulaLabel(p.dest),
			DestIP: p.dest,
			Next:   n.idLabel(p.e.next),
			Metric: p.e.metric,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Metric != out[j].Metric {
			return out[i].Metric < out[j].Metric
		}
		return out[i].Dest < out[j].Dest
	})
	return out
}

// logRoutes logs a RIB snapshot after an update.
func (n *Node) logRoutes(reason, detail string) {
	routes := n.Routes()
	if detail != "" {
		n.log.Printf("routes updated (%s %s) count=%d", reason, detail, len(routes))
	} else {
		n.log.Printf("routes updated (%s) count=%d", reason, len(routes))
	}
	for _, r := range routes {
		n.log.Printf("  %-8s via %-8s metric=%d", r.Dest, r.Next, r.Metric)
	}
	if n.cfg.ExitNode != "" {
		n.syncExitHostDefaults()
	}
}

// ulaLabel maps a ULA string to a human-readable name for logs.
func (n *Node) ulaLabel(ula string) string {
	if isDefaultRouteDest(ula) {
		return ula
	}
	if ula == n.id.ULA().String() {
		return n.hopName()
	}
	ip := net.ParseIP(ula)
	if ip != nil {
		n.mu.Lock()
		defer n.mu.Unlock()
		for _, s := range n.sessions {
			if s.id.ULA().Equal(ip) {
				return routePeerName(s.id, s.names)
			}
		}
	}
	if len(ula) > 12 {
		return ula[len(ula)-12:]
	}
	return ula
}

// idLabel maps a NodeID to a display name for logs.
func (n *Node) idLabel(id identity.NodeID) string {
	if id == n.id {
		return n.hopName()
	}
	n.mu.Lock()
	s := n.sessions[id]
	n.mu.Unlock()
	if s != nil {
		return routePeerName(id, s.names)
	}
	return id.Short()
}

// routePeerName prefers the first cert name, else the short id.
func routePeerName(id identity.NodeID, names []string) string {
	if len(names) > 0 {
		return names[0]
	}
	return id.Short()
}

// routeNextHop returns the live session for dst's RIB entry, if any.
func (n *Node) routeNextHop(dst net.IP) *session {
	if dst == nil {
		return nil
	}
	key := dst.String()
	n.routeMu.Lock()
	e, ok := n.routes[key]
	n.routeMu.Unlock()
	if !ok || e.metric >= routeInfinity {
		return nil
	}
	return n.session(e.next)
}

// RouteMetric returns the hop-count metric to dst, or -1 if unknown.
func (n *Node) RouteMetric(dst net.IP) int {
	if dst == nil {
		return -1
	}
	if dst.Equal(n.id.ULA()) {
		return 0
	}
	n.routeMu.Lock()
	defer n.routeMu.Unlock()
	e, ok := n.routes[dst.String()]
	if !ok {
		return -1
	}
	return e.metric
}

// waitRoute blocks until dst appears in the RIB or timeout elapses.
func (n *Node) waitRoute(dst net.IP, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if n.routeNextHop(dst) != nil {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return n.routeNextHop(dst) != nil
}
