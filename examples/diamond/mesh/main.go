// Multi-process diamond: one OS process per node (real hopscotch binaries).
//
//	src ──┬── 6 paths × 8 deep ──┼── dst   → 50 nodes
//
//	go build -o hopscotch .
//	go run ./examples/diamond/mesh
//	./hopscotch traceroute --config examples/.local/diamond/src.yaml dst
package main

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	width    = 6
	depth    = 8
	basePort = 4601 // path ports: basePort + w*depth + d
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))

	root, err := repoRoot()
	if err != nil {
		fatal(err)
	}
	dir := filepath.Join(root, "examples", ".local", "diamond")
	bin := filepath.Join(root, "hopscotch")
	if _, err := os.Stat(bin); err != nil {
		fatal(fmt.Errorf("hopscotch binary not found at %s (run: go build -o hopscotch .)", bin))
	}

	names := []string{"src", "dst"}
	for w := 0; w < width; w++ {
		for d := 0; d < depth; d++ {
			names = append(names, pathName(w, d))
		}
	}
	total := 2 + width*depth
	slog.Info("boot", "phase", "certs", "nodes", total, "width", width, "depth", depth, "dir", dir)

	if err := os.MkdirAll(dir, 0o755); err != nil {
		fatal(err)
	}
	args := []string{"ca", "bootstrap", "--dir", dir}
	for _, n := range names {
		args = append(args, "--node", n)
	}
	boot := exec.Command(bin, args...)
	boot.Dir = root
	boot.Stdout = os.Stdout
	boot.Stderr = os.Stderr
	if err := boot.Run(); err != nil {
		fatal(fmt.Errorf("bootstrap: %w", err))
	}

	slog.Info("boot", "phase", "write configs")
	if err := writeConfigs(dir); err != nil {
		fatal(err)
	}

	order := make([]string, 0, total)
	for w := 0; w < width; w++ {
		for d := 0; d < depth; d++ {
			order = append(order, pathName(w, d))
		}
	}
	order = append(order, "dst", "src")

	var (
		mu   sync.Mutex
		cmds []*exec.Cmd
	)
	start := func(name string) error {
		cfg := filepath.Join(dir, name+".yaml")
		c := exec.Command(bin, "--config", cfg)
		c.Dir = root
		w := &prefixWriter{prefix: name + " ", out: os.Stdout}
		c.Stdout = w
		c.Stderr = w
		if err := c.Start(); err != nil {
			return err
		}
		mu.Lock()
		cmds = append(cmds, c)
		mu.Unlock()
		slog.Info("started", "node", name, "pid", c.Process.Pid)
		return nil
	}

	for _, name := range order {
		if err := start(name); err != nil {
			killAll(&mu, cmds)
			fatal(err)
		}
		time.Sleep(15 * time.Millisecond)
	}

	slog.Info("ready",
		"nodes", total,
		"shape", fmt.Sprintf("src→{%d×%d}→dst", width, depth),
		"ping", fmt.Sprintf("./hopscotch ping --config %s dst", filepath.Join(dir, "src.yaml")),
		"traceroute", fmt.Sprintf("./hopscotch traceroute --config %s dst", filepath.Join(dir, "src.yaml")),
	)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	slog.Info("shutdown")
	killAll(&mu, cmds)
}

type prefixWriter struct {
	prefix string
	out    io.Writer
	buf    []byte
	mu     sync.Mutex
}

func (w *prefixWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf = append(w.buf, p...)
	for {
		i := strings.IndexByte(string(w.buf), '\n')
		if i < 0 {
			break
		}
		line := append([]byte(nil), w.buf[:i+1]...)
		w.buf = w.buf[i+1:]
		if _, err := io.WriteString(w.out, w.prefix); err != nil {
			return len(p), err
		}
		if _, err := w.out.Write(line); err != nil {
			return len(p), err
		}
	}
	return len(p), nil
}

func writeConfigs(dir string) error {
	write := func(name, body string) error {
		return os.WriteFile(filepath.Join(dir, name+".yaml"), []byte(body), 0o644)
	}
	port := func(w, d int) int { return basePort + w*depth + d }

	var srcPeers, dstPeers strings.Builder
	for w := 0; w < width; w++ {
		fmt.Fprintf(&srcPeers, "  - udp:127.0.0.1:%d\n", port(w, 0))
		fmt.Fprintf(&dstPeers, "  - udp:127.0.0.1:%d\n", port(w, depth-1))
	}

	if err := write("src", fmt.Sprintf(`identity: src.pem
ca: ca.crt
cert: src.crt
control: src.sock
gateway: false
peers:
%s`, srcPeers.String())); err != nil {
		return err
	}
	if err := write("dst", fmt.Sprintf(`identity: dst.pem
ca: ca.crt
cert: dst.crt
control: dst.sock
gateway: false
peers:
%s`, dstPeers.String())); err != nil {
		return err
	}

	for w := 0; w < width; w++ {
		for d := 0; d < depth; d++ {
			name := pathName(w, d)
			var b strings.Builder
			fmt.Fprintf(&b, "identity: %s.pem\nca: ca.crt\ncert: %s.crt\ncontrol: %s.sock\ngateway: false\n", name, name, name)
			fmt.Fprintf(&b, "listen:\n  - udp:127.0.0.1:%d\n", port(w, d))
			if d > 0 {
				fmt.Fprintf(&b, "peers:\n  - udp:127.0.0.1:%d\n", port(w, d-1))
			}
			if err := write(name, b.String()); err != nil {
				return err
			}
		}
	}
	return nil
}

func pathName(w, d int) string {
	return fmt.Sprintf("p%02dn%02d", w, d)
}

func repoRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	dir := wd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found from %s", wd)
		}
		dir = parent
	}
}

func killAll(mu *sync.Mutex, cmds []*exec.Cmd) {
	mu.Lock()
	defer mu.Unlock()
	for _, c := range cmds {
		if c.Process != nil {
			_ = c.Process.Signal(syscall.SIGTERM)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for _, c := range cmds {
		done := make(chan struct{})
		go func(c *exec.Cmd) {
			_ = c.Wait()
			close(done)
		}(c)
		select {
		case <-done:
		case <-time.After(time.Until(deadline)):
			if c.Process != nil {
				_ = c.Process.Kill()
			}
			<-done
		}
	}
}

func fatal(err error) {
	slog.Error("fatal", "err", err)
	os.Exit(1)
}
