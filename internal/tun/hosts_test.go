package tun

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStripHostsBlock(t *testing.T) {
	existing := "127.0.0.1 localhost\n# hopscotch BEGIN\nold ::1\n# hopscotch END\n"
	got := stripHostsBlock(existing)
	if !strings.Contains(got, "127.0.0.1 localhost") {
		t.Fatal(got)
	}
	if strings.Contains(got, "old") || strings.Contains(got, "hopscotch BEGIN") {
		t.Fatal("old block left")
	}
}

func TestParseHostsFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts")
	if err := os.WriteFile(path, []byte("# hopscotch overlay names → ULA\nfd00::aa foo\n100.64.1.2 foo\nfe80::1 skip\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	hs, err := ParseHostsFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(hs) != 1 || hs[0].Name != "foo" || hs[0].IP == nil {
		t.Fatalf("%v", hs)
	}
}

func TestParseHostsFileMissing(t *testing.T) {
	if _, err := ParseHostsFile(filepath.Join(t.TempDir(), "nope")); !os.IsNotExist(err) {
		t.Fatalf("err %v", err)
	}
}

func TestStripHostsBlockNoop(t *testing.T) {
	in := "127.0.0.1 localhost\n"
	if got := stripHostsBlock(in); got != in {
		t.Fatalf("%q", got)
	}
}
