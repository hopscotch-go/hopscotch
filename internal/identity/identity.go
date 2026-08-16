package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
)

const ALPN = "hopscotch"

// NodeID is SHA-256(ed25519 public key). That is the mesh name: a
// 32-byte identifier anyone can recompute from the key, unlike
// Tailscale overlay IPs which a directory assigns.
type NodeID [32]byte

// IDFromPublic derives a NodeID as SHA-256 of an ed25519 public key.
func IDFromPublic(pub ed25519.PublicKey) NodeID {
	return sha256.Sum256(pub)
}

// Short returns the first four bytes of the NodeID as hex.
func (id NodeID) Short() string {
	return fmt.Sprintf("%x", id[:4])
}

// Hex returns the full NodeID as lowercase hex.
func (id NodeID) Hex() string {
	return fmt.Sprintf("%x", id[:])
}

// ParsePublicKey decodes a 64-character hex ed25519 public key.
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key must be 64 hex chars")
	}
	return ed25519.PublicKey(b), nil
}

// PublicHex encodes an ed25519 public key as lowercase hex.
func PublicHex(pub ed25519.PublicKey) string {
	return hex.EncodeToString(pub)
}

// ULA is an RFC 4193 unique-local IPv6 address derived from NodeID.
// This is the Yggdrasil-style mapping (key → address). Overlay TUN
// traffic uses these addresses; the mapping is many-to-one (104 bits
// of the 256-bit NodeID), so routing matches known session ULAs rather
// than inverting the address back to a key.
func (id NodeID) ULA() net.IP {
	ip := make(net.IP, 16)
	ip[0] = 0xfd
	copy(ip[1:6], id[:5])   // 40-bit Global ID
	copy(ip[8:16], id[24:]) // interface ID
	return ip
}

// IsMeshULA reports whether ip is in fd00::/8 (the overlay route).
func IsMeshULA(ip net.IP) bool {
	ip = ip.To16()
	return ip != nil && ip.To4() == nil && ip[0] == 0xfd
}

// ResolverULA is the overlay nameserver (fd00::53). It is in fd00::/8
// so the host route delivers queries to the TUN, but it is not a node
// ULA. Queries are answered in-process and not forwarded.
func ResolverULA() net.IP {
	ip := make(net.IP, 16)
	ip[0] = 0xfd
	ip[15] = 0x53
	return ip
}

// IsResolverULA reports whether ip is the overlay nameserver address.
func IsResolverULA(ip net.IP) bool {
	got := ip.To16()
	return got != nil && got.Equal(ResolverULA())
}

// LoadOrCreate returns an ed25519 key from path, creating one if needed.
func LoadOrCreate(path string) (ed25519.PrivateKey, error) {
	if path == "" {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, err
	}
	if fileExists(path) {
		return LoadKey(path)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := writeKey(path, priv); err != nil {
		return nil, err
	}
	return priv, nil
}

// PublicFromCerts returns the ed25519 public key from the leaf certificate.
func PublicFromCerts(certs []*x509.Certificate) (ed25519.PublicKey, error) {
	if len(certs) == 0 {
		return nil, fmt.Errorf("peer sent no certificate")
	}
	pub, ok := certs[0].PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("peer certificate is not ed25519")
	}
	return pub, nil
}
