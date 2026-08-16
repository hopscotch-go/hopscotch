package node

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/hopscotch-go/hopscotch/internal/proto"
)

func (n *Node) listenControl() error {
	if err := os.MkdirAll(filepath.Dir(n.controlPath), 0o700); err != nil {
		return err
	}
	_ = os.Remove(n.controlPath)
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

func (n *Node) controlLoop() {
	for {
		conn, err := n.control.Accept()
		if err != nil {
			return
		}
		go n.handleControl(conn)
	}
}

func (n *Node) handleControl(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	msg, err := proto.Read(conn)
	if err != nil {
		return
	}
	switch msg.Type {
	case "ping":
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
	default:
		_ = proto.Write(conn, proto.Message{Type: "error", Error: "unknown control command " + msg.Type})
	}
}
