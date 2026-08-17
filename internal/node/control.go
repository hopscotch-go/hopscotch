package node

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/hopscotch-go/hopscotch/internal/proto"
)

// listenControl opens the unix control socket for local ping/traceroute.
// If another hopscotch is already serving this path, Start fails instead of
// stealing the socket (and the mesh session that goes with the same identity).
func (n *Node) listenControl() error {
	if err := os.MkdirAll(filepath.Dir(n.controlPath), 0o700); err != nil {
		return err
	}
	if err := ensureControlSocketFree(n.controlPath); err != nil {
		return err
	}
	ln, err := net.Listen("unix", n.controlPath)
	if err != nil {
		return err
	}
	if err := os.Chmod(n.controlPath, 0o666); err != nil {
		_ = ln.Close()
		_ = os.Remove(n.controlPath)
		return err
	}
	n.control = ln
	go n.controlLoop()
	return nil
}

// ensureControlSocketFree errors if path is a live control socket; removes a stale sock file.
func ensureControlSocketFree(path string) error {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	conn, err := net.DialTimeout("unix", path, time.Second)
	if err == nil {
		_ = conn.Close()
		return fmt.Errorf("control socket %s already in use (node already running?)", path)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// controlLoop accepts control-socket connections.
func (n *Node) controlLoop() {
	for {
		conn, err := n.control.Accept()
		if err != nil {
			return
		}
		go n.handleControl(conn)
	}
}

// handleControl serves one control-plane request over a unix connection.
func (n *Node) handleControl(conn net.Conn) {
	defer conn.Close()
	msg, err := proto.Read(conn)
	if err != nil {
		return
	}
	switch msg.Type {
	case "ping":
		_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
		ctx, cancel := context.WithTimeout(n.ctx, 10*time.Second)
		defer cancel()
		got, err := n.Echo(ctx, msg.Name)
		reply := proto.Message{Type: "pong", RPC: msg.RPC, Name: msg.Name}
		if err != nil {
			reply.Type = "error"
			reply.Error = err.Error()
		} else {
			reply.Name = got.Name
			reply.Path = got.Path
			reply.Hops = got.Hops
			reply.RTTMs = float64(got.RTT.Microseconds()) / 1000
		}
		_ = proto.Write(conn, reply)
	case "traceroute":
		maxTTL := msg.MaxTTL
		if maxTTL <= 0 {
			maxTTL = 32
		}
		_ = conn.SetDeadline(time.Now().Add(time.Duration(maxTTL)*time.Second + 5*time.Second))
		ctx, cancel := context.WithTimeout(n.ctx, time.Duration(maxTTL)*time.Second+2*time.Second)
		defer cancel()
		got, err := n.TraceRoute(ctx, msg.Name, maxTTL)
		reply := proto.Message{Type: "traceroute_ok", RPC: msg.RPC, Name: msg.Name}
		if err != nil {
			reply.Type = "error"
			reply.Error = err.Error()
		} else {
			reply.Name = got.Dst
			reply.Reached = got.Reach
			reply.Trace = make([]proto.TraceHop, len(got.Hops))
			for i, h := range got.Hops {
				reply.Trace[i] = proto.TraceHop{
					TTL:     h.TTL,
					Name:    h.Name,
					Addr:    h.ULA,
					RTTMs:   float64(h.RTT.Microseconds()) / 1000,
					Timeout: h.Timeout,
					Reply:   h.Reply,
				}
			}
		}
		_ = proto.Write(conn, reply)
	case "ula":
		_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
		ctx, cancel := context.WithTimeout(n.ctx, 10*time.Second)
		defer cancel()
		ip, err := n.ResolveULA(ctx, msg.Name)
		reply := proto.Message{Type: "ula_ok", RPC: msg.RPC, Name: msg.Name}
		if err != nil {
			reply.Type = "error"
			reply.Error = err.Error()
		} else {
			reply.ULA = ip.String()
		}
		_ = proto.Write(conn, reply)
	default:
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		_ = proto.Write(conn, proto.Message{Type: "error", Error: "unknown control command " + msg.Type})
	}
}
