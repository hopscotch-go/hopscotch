package peers

import (
	"bufio"
	"crypto/ed25519"
	"fmt"
	"os"
	"strings"

	"github.com/hopscotch-go/hopscotch/internal/endpoint"
	"github.com/hopscotch-go/hopscotch/internal/identity"
)

// Peer is a known underlay hop. Addr is a canonical endpoint (udp:host:port).
// Pub, if set, is the ed25519 key we require on that hop (pinning).
type Peer struct {
	Addr string
	Pub  ed25519.PublicKey
}

func Load(path string) ([]Peer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(string(b))
}

func Parse(text string) ([]Peer, error) {
	var out []Peer
	sc := bufio.NewScanner(strings.NewReader(text))
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := sc.Text()
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		p, err := parseFields(fields)
		if err != nil {
			return nil, fmt.Errorf("peers line %d: %w", lineNo, err)
		}
		out = append(out, p)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func parseFields(fields []string) (Peer, error) {
	var p Peer
	switch len(fields) {
	case 1:
		ep, err := endpoint.Parse(fields[0], "udp")
		if err != nil {
			return p, err
		}
		p.Addr = ep.String()
	case 2:
		pub, err := identity.ParsePublicKey(fields[0])
		if err != nil {
			return p, err
		}
		ep, err := endpoint.Parse(fields[1], "udp")
		if err != nil {
			return p, err
		}
		p.Pub = pub
		p.Addr = ep.String()
	default:
		return p, fmt.Errorf("want `addr` or `pubkey addr`")
	}
	return p, nil
}
