//go:build darwin

package tun

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hopscotch-go/hopscotch/internal/identity"
)

func TestInstallDNSResolverFiles(t *testing.T) {
	dir := t.TempDir()
	orig := resolverDir
	resolverDir = dir
	defer func() { resolverDir = orig }()

	revert, err := InstallDNS("utun9", 49152)
	if err != nil {
		t.Fatal(err)
	}
	match, err := os.ReadFile(filepath.Join(dir, identity.NameURIScheme))
	if err != nil {
		t.Fatal(err)
	}
	got := string(match)
	if !strings.Contains(got, "nameserver 127.0.0.1") || !strings.Contains(got, "port 49152") {
		t.Fatalf("%s", match)
	}
	search, err := os.ReadFile(filepath.Join(dir, "search."+identity.NameURIScheme))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(search), "search "+identity.NameURIScheme) {
		t.Fatalf("%s", search)
	}
	if err := revert(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, identity.NameURIScheme)); !os.IsNotExist(err) {
		t.Fatalf("match file left: %v", err)
	}
}
