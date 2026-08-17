package node

import (
	"fmt"
	"io"
	"net/http"
)

// startHTTP serves a tiny banner on the userspace stack (demo / throwaway).
func (n *Node) startHTTP() error {
	if n.cfg.HTTPPort <= 0 || n.cfg.HTTPPort > 65535 {
		return fmt.Errorf("http: invalid port %d", n.cfg.HTTPPort)
	}
	if n.stack == nil {
		if err := n.startUserspace(); err != nil {
			return err
		}
	}
	ln, err := n.ListenTCP(uint16(n.cfg.HTTPPort))
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		name := n.hopName()
		_, _ = io.WriteString(w, "hopscotch "+name+"\n")
	})
	srv := &http.Server{Handler: mux}
	go func() {
		_ = srv.Serve(ln)
	}()
	go func() {
		<-n.ctx.Done()
		_ = srv.Close()
	}()
	n.log.Printf("http      %s:%d  (userspace overlay)", n.id.ULA(), n.cfg.HTTPPort)
	return nil
}
