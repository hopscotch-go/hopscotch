//go:build darwin

package tun

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/hopscotch-go/hopscotch/internal/identity"
)

const resolverHeader = "# hopscotch\n"

var resolverDir = "/etc/resolver"

func InstallDNS(ifName string, dnsPort int) (func() error, error) {
	if err := os.MkdirAll(resolverDir, 0o755); err != nil {
		return nil, err
	}
	ns := "127.0.0.1"
	zone := identity.NameURIScheme
	match := resolverHeader + "nameserver " + ns + "\n"
	if dnsPort > 0 && dnsPort != 53 {
		match += fmt.Sprintf("port %d\n", dnsPort)
	}
	search := resolverHeader + "search " + zone + "\n"
	matchPath := filepath.Join(resolverDir, zone)
	searchPath := filepath.Join(resolverDir, "search."+zone)
	if err := os.WriteFile(matchPath, []byte(match), 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(searchPath, []byte(search), 0o644); err != nil {
		_ = os.Remove(matchPath)
		return nil, err
	}
	return func() error {
		var first error
		for _, p := range []string{matchPath, searchPath} {
			if err := removeResolverFile(p); err != nil && first == nil {
				first = err
			}
		}
		return first
	}, nil
}

func removeResolverFile(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if !hasResolverHeader(string(b)) {
		return fmt.Errorf("tun: %s is not a hopscotch resolver file", path)
	}
	return os.Remove(path)
}

func hasResolverHeader(s string) bool {
	return len(s) >= len(resolverHeader) && s[:len(resolverHeader)] == resolverHeader
}
