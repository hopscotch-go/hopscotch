package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"time"
)

const ALPN = "hopscotch"

// NodeID is SHA-256(ed25519 public key). That is the mesh name: a
// 32-byte identifier anyone can recompute from the key, unlike
// Tailscale overlay IPs which a directory assigns.
type NodeID [32]byte

func IDFromPublic(pub ed25519.PublicKey) NodeID {
	return sha256.Sum256(pub)
}

func (id NodeID) Short() string {
	return fmt.Sprintf("%x", id[:4])
}

func (id NodeID) Hex() string {
	return fmt.Sprintf("%x", id[:])
}

func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key must be 64 hex chars")
	}
	return ed25519.PublicKey(b), nil
}

func PublicHex(pub ed25519.PublicKey) string {
	return hex.EncodeToString(pub)
}

func ParseHex(s string) (NodeID, error) {
	var id NodeID
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return id, fmt.Errorf("node id must be 64 hex chars")
	}
	copy(id[:], b)
	return id, nil
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

func IsResolverULA(ip net.IP) bool {
	got := ip.To16()
	return got != nil && got.Equal(ResolverULA())
}

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

func TLSCert(priv ed25519.PrivateKey) (tls.Certificate, error) {
	pub := priv.Public().(ed25519.PublicKey)
	serial, err := randomSerial()
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}, nil
}

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
