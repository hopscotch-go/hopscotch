package identity

import (
	"crypto/x509"
	"fmt"
	"net/url"
	"strings"
)

const NameURIScheme = "hopscotch"

// ParseName validates and lowercases a hopscotch node name.
func ParseName(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "", fmt.Errorf("empty name")
	}
	if len(s) > 63 {
		return "", fmt.Errorf("name %q too long (max 63)", s)
	}
	if s[0] < 'a' || s[0] > 'z' {
		return "", fmt.Errorf("name %q must start with a letter", s)
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' {
			continue
		}
		return "", fmt.Errorf("name %q: only letters, digits, and hyphen", s)
	}
	return s, nil
}

// NormalizeNames parses names and returns unique values in first-seen order.
func NormalizeNames(names []string) ([]string, error) {
	seen := make(map[string]bool)
	var out []string
	for _, raw := range names {
		n, err := ParseName(raw)
		if err != nil {
			return nil, err
		}
		if seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out, nil
}

// NameURI builds a hopscotch:name URI for certificate SANs.
func NameURI(name string) *url.URL {
	return &url.URL{Scheme: NameURIScheme, Opaque: name}
}

// NamesFromCert extracts hopscotch URI names from a certificate's SANs.
func NamesFromCert(cert *x509.Certificate) []string {
	if cert == nil {
		return nil
	}
	seen := make(map[string]bool)
	var out []string
	add := func(raw string) {
		n, err := ParseName(raw)
		if err != nil || seen[n] {
			return
		}
		seen[n] = true
		out = append(out, n)
	}
	for _, u := range cert.URIs {
		if u == nil || u.Scheme != NameURIScheme {
			continue
		}
		if u.Opaque != "" {
			add(u.Opaque)
		} else if u.Host != "" {
			add(u.Host)
		}
	}
	return out
}
