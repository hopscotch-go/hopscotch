package tun

import (
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

func TestStripHostsBlockNoop(t *testing.T) {
	in := "127.0.0.1 localhost\n"
	if got := stripHostsBlock(in); got != in {
		t.Fatalf("%q", got)
	}
}
