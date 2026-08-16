package tun

import (
	"bufio"
	"net"
	"os"
	"strings"

	"github.com/hopscotch-go/hopscotch/internal/identity"
)

const (
	hostsBegin = "# hopscotch BEGIN"
	hostsEnd   = "# hopscotch END"
)

var systemHosts = "/etc/hosts"

type Host struct {
	Name string
	IP   net.IP
}

func ParseHostsFile(path string) ([]Host, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	byName := map[string]*Host{}
	var order []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ipStr, name, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		if !identity.IsMeshULA(ip) {
			continue
		}
		n, err := identity.ParseName(name)
		if err != nil {
			continue
		}
		h := byName[n]
		if h == nil {
			h = &Host{Name: n}
			byName[n] = h
			order = append(order, n)
		}
		h.IP = ip.To16()
	}
	out := make([]Host, 0, len(order))
	for _, n := range order {
		out = append(out, *byName[n])
	}
	return out, sc.Err()
}

// StripHopscotchHosts removes a leftover # hopscotch BEGIN/END block from
// /etc/hosts (older builds wrote names there). Overlay names now come from DNS.
func StripHopscotchHosts() error {
	cur, err := os.ReadFile(systemHosts)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	next := stripHostsBlock(string(cur))
	if next == string(cur) {
		return nil
	}
	return os.WriteFile(systemHosts, []byte(next), 0o644)
}

func stripHostsBlock(existing string) string {
	var kept []string
	skip := false
	for _, line := range strings.Split(strings.ReplaceAll(existing, "\r\n", "\n"), "\n") {
		if line == hostsBegin {
			skip = true
			continue
		}
		if skip {
			if line == hostsEnd {
				skip = false
			}
			continue
		}
		kept = append(kept, line)
	}
	for len(kept) > 0 && kept[len(kept)-1] == "" {
		kept = kept[:len(kept)-1]
	}
	if len(kept) == 0 {
		return ""
	}
	return strings.Join(kept, "\n") + "\n"
}
