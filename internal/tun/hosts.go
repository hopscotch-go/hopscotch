package tun

import (
	"os"
	"strings"
)

const (
	hostsBegin = "# hopscotch BEGIN"
	hostsEnd   = "# hopscotch END"
)

var systemHosts = "/etc/hosts"

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

// stripHostsBlock removes a hopscotch BEGIN/END section from hosts file text.
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
