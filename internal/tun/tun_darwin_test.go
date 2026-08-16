//go:build darwin

package tun

import (
	"testing"
	"unsafe"
)

func TestIn6AliasReqSize(t *testing.T) {
	if n := unsafe.Sizeof(in6AliasReq{}); n != 128 {
		t.Fatalf("in6AliasReq size %d want 128", n)
	}
}
