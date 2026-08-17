package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/hopscotch-go/hopscotch/internal/endpoint"
	"github.com/hopscotch-go/hopscotch/internal/identity"
	"github.com/hopscotch-go/hopscotch/internal/peers"
)

// File is a node config as loaded from YAML. Paths are absolute.
type File struct {
	Identity  string
	CA        string
	Cert      string
	Control   string
	Listen    []string
	Peers     []peers.Peer
	Tun       bool
	Userspace bool
	Socks     string
	Gateway   bool
}

type rawFile struct {
	Identity  string     `yaml:"identity"`
	CA        string     `yaml:"ca"`
	Cert      string     `yaml:"cert"`
	Control   string     `yaml:"control"`
	Listen    stringList `yaml:"listen"`
	Peers     []rawPeer  `yaml:"peers"`
	Tun       bool       `yaml:"tun"`
	Userspace bool       `yaml:"userspace"`
	Socks     string     `yaml:"socks"`
	Gateway   *bool      `yaml:"gateway"`
}

type stringList []string

// UnmarshalYAML accepts a single string or a list of strings for listen.
func (s *stringList) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		*s = []string{value.Value}
		return nil
	case yaml.SequenceNode:
		var xs []string
		if err := value.Decode(&xs); err != nil {
			return err
		}
		*s = xs
		return nil
	default:
		return fmt.Errorf("listen: want a string or a list of strings")
	}
}

type rawPeer struct {
	Addr   string
	Pubkey string
}

// UnmarshalYAML accepts a peer as an address string or {addr, pubkey} map.
func (p *rawPeer) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		p.Addr = value.Value
		return nil
	case yaml.MappingNode:
		var aux struct {
			Addr   string `yaml:"addr"`
			Pubkey string `yaml:"pubkey"`
		}
		if err := value.Decode(&aux); err != nil {
			return err
		}
		p.Addr = aux.Addr
		p.Pubkey = aux.Pubkey
		return nil
	default:
		return fmt.Errorf("peer: want an address string or {addr, pubkey}")
	}
}

// Load reads and validates a node YAML config, resolving relative paths.
func Load(path string) (*File, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var raw rawFile
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	base := filepath.Dir(abs)
	out := &File{
		Identity:  resolve(base, raw.Identity),
		CA:        resolve(base, raw.CA),
		Cert:      resolve(base, raw.Cert),
		Control:   resolve(base, raw.Control),
		Listen:    append([]string(nil), raw.Listen...),
		Tun:       raw.Tun,
		Userspace: raw.Userspace,
		Socks:     raw.Socks,
		Gateway:   true,
	}
	if raw.Gateway != nil {
		out.Gateway = *raw.Gateway
	}
	if out.Identity == "" || out.CA == "" || out.Cert == "" {
		return nil, fmt.Errorf("%s: identity, ca, and cert are required", path)
	}
	for i, rp := range raw.Peers {
		p, err := parsePeer(rp)
		if err != nil {
			return nil, fmt.Errorf("%s: peers[%d]: %w", path, i, err)
		}
		out.Peers = append(out.Peers, p)
	}
	if len(out.Listen) == 0 && len(out.Peers) == 0 {
		return nil, fmt.Errorf("%s: listen or peers required", path)
	}
	return out, nil
}

// parsePeer converts a raw YAML peer into a canonical peers.Peer.
func parsePeer(rp rawPeer) (peers.Peer, error) {
	var p peers.Peer
	if rp.Addr == "" {
		return p, fmt.Errorf("missing addr")
	}
	ep, err := endpoint.Parse(rp.Addr, "udp")
	if err != nil {
		return p, err
	}
	p.Addr = ep.String()
	if rp.Pubkey != "" {
		pub, err := identity.ParsePublicKey(rp.Pubkey)
		if err != nil {
			return p, err
		}
		p.Pub = pub
	}
	return p, nil
}

// resolve joins a relative path with base, leaving absolute paths unchanged.
func resolve(base, p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Clean(filepath.Join(base, p))
}
