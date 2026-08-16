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
	matchPath := filepath.Join(resolverDir, zone)
	// Older builds wrote /etc/resolver/search.hopscotch, which macOS
	// treats as a global search domain. Unqualified names (tot, etc.)
	// then go to the hopscotch stub and hang if it is down — and steal
	// short names from Tailscale MagicDNS while it is up.
	_ = removeResolverFile(filepath.Join(resolverDir, "search."+zone))
	if err := os.WriteFile(matchPath, []byte(match), 0o644); err != nil {
		return nil, err
	}
	return func() error {
		return removeResolverFile(matchPath)
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
