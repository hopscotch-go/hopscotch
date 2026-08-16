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

	legacy := filepath.Join(dir, "search."+identity.NameURIScheme)
	if err := os.WriteFile(legacy, []byte("# hopscotch\nsearch hopscotch\n"), 0o644); err != nil {
		t.Fatal(err)
	}

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
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatal("legacy search file should be removed")
	}
	if err := revert(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, identity.NameURIScheme)); !os.IsNotExist(err) {
		t.Fatalf("match file left: %v", err)
	}
}
