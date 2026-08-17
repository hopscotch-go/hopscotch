package node

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/hopscotch-go/hopscotch/internal/identity"
	"github.com/hopscotch-go/hopscotch/internal/proto"
)

const echoTTL = 128

var errNoSession = errors.New("no session")

type echoWait struct {
	back *session
	ch   chan proto.Message
}

type EchoResult struct {
	Name string
	ULA  string
	Path []string
	Hops int
	RTT  time.Duration
}

// echoKey builds the map key for an in-flight named-echo RPC.
func echoKey(origin string, rpc uint64) string {
	return origin + "-" + strconv.FormatUint(rpc, 10)
}

// hopName returns this node's preferred display name for echo paths.
func (n *Node) hopName() string {
	if len(n.names) > 0 {
		return n.names[0]
	}
	return n.id.Short()
}

// hasName reports whether name is one of this node's overlay names.
func (n *Node) hasName(name string) bool {
	for _, nm := range n.names {
		if nm == name {
			return true
		}
	}
	return false
}

// session returns the live session for id, if any.
func (n *Node) session(id identity.NodeID) *session {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.sessions[id]
}

// sessionByName finds a live session advertising the given overlay name.
func (n *Node) sessionByName(name string) *session {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, s := range n.sessions {
		for _, nm := range s.names {
			if nm == name {
				return s
			}
		}
	}
	return nil
}

// sessionList returns a snapshot of live peer sessions.
func (n *Node) sessionList() []*session {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]*session, 0, len(n.sessions))
	for _, s := range n.sessions {
		out = append(out, s)
	}
	return out
}

// Echo runs a named-echo flood to measure path and RTT to name.
func (n *Node) Echo(ctx context.Context, rawName string) (EchoResult, error) {
	name, err := identity.ParseName(rawName)
	if err != nil {
		return EchoResult{}, err
	}
	if n.hasName(name) {
		return EchoResult{Name: name, ULA: n.id.ULA().String(), Path: []string{n.hopName()}, Hops: 0}, nil
	}

	start := time.Now()
	rpc := n.rpcSeq.Add(1)
	key := echoKey(n.id.Hex(), rpc)
	ch := make(chan proto.Message, 1)
	n.mu.Lock()
	n.echoWait[key] = echoWait{ch: ch}
	n.mu.Unlock()
	defer n.clearEcho(key)

	msg := proto.Message{Type: "echo", RPC: rpc, Origin: n.id.Hex(), Name: name, TTL: echoTTL}
	if err := n.dispatchEcho(nil, msg); err != nil {
		return EchoResult{}, err
	}

	select {
	case <-ctx.Done():
		return EchoResult{}, fmt.Errorf("ping %s: %w", name, ctx.Err())
	case reply := <-ch:
		if reply.Type == "echo_err" || reply.Error != "" {
			errMsg := reply.Error
			if errMsg == "" {
				errMsg = "no route"
			}
			return EchoResult{}, fmt.Errorf("ping %s: %s", name, errMsg)
		}
		return EchoResult{Name: name, ULA: reply.ULA, Path: append([]string(nil), reply.Path...), Hops: len(reply.Path), RTT: time.Since(start)}, nil
	}
}

// handleEcho processes an inbound echo on the control plane.
func (n *Node) handleEcho(from *session, msg proto.Message) {
	name, err := identity.ParseName(msg.Name)
	if err != nil {
		return
	}
	if n.hasName(name) {
		_ = n.write(from, proto.Message{
			Type:   "echo_ok",
			RPC:    msg.RPC,
			Origin: msg.Origin,
			Name:   name,
			ULA:    n.id.ULA().String(),
			Path:   append(append([]string{}, msg.Path...), n.hopName()),
		})
		return
	}
	key := echoKey(msg.Origin, msg.RPC)
	n.mu.Lock()
	if _, ok := n.echoWait[key]; ok {
		n.mu.Unlock()
		return
	}
	n.echoWait[key] = echoWait{back: from}
	n.mu.Unlock()

	next := msg
	next.Name = name
	next.TTL--
	next.Path = append(append([]string{}, msg.Path...), n.hopName())
	if next.TTL < 0 {
		n.finishEcho(key, proto.Message{Type: "echo_err", RPC: msg.RPC, Origin: msg.Origin, Name: name, Error: "ttl exceeded"})
		return
	}
	if err := n.dispatchEcho(from, next); err != nil {
		n.finishEcho(key, proto.Message{Type: "echo_err", RPC: msg.RPC, Origin: msg.Origin, Name: name, Error: err.Error()})
	}
}

// dispatchEcho forwards an echo toward a named session or floods peers.
func (n *Node) dispatchEcho(from *session, msg proto.Message) error {
	if dest := n.sessionByName(msg.Name); dest != nil && dest != from {
		return n.write(dest, msg)
	}
	sent := 0
	var last error
	for _, s := range n.sessionList() {
		if s == from {
			continue
		}
		if err := n.write(s, msg); err != nil {
			last = err
			continue
		}
		sent++
	}
	if sent == 0 {
		if last != nil {
			return last
		}
		return fmt.Errorf("no route to %s", msg.Name)
	}
	return nil
}

// completeEcho delivers an echo reply/error to the waiting waiter.
func (n *Node) completeEcho(msg proto.Message) {
	n.finishEcho(echoKey(msg.Origin, msg.RPC), msg)
}

// finishEcho completes or relays an echo response for key.
func (n *Node) finishEcho(key string, msg proto.Message) {
	n.mu.Lock()
	w, ok := n.echoWait[key]
	if ok {
		delete(n.echoWait, key)
	}
	n.mu.Unlock()
	if !ok {
		return
	}
	if w.back != nil {
		_ = n.write(w.back, msg)
		return
	}
	if w.ch != nil {
		select {
		case w.ch <- msg:
		default:
		}
	}
}

// clearEcho removes a pending echo waiter.
func (n *Node) clearEcho(key string) {
	n.mu.Lock()
	delete(n.echoWait, key)
	n.mu.Unlock()
}
