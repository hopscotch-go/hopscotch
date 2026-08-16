//go:build !linux

package tun

// gatewayNetFilter is a no-op off Linux (firewalld is not used).
func gatewayNetFilter(string) func() error { return nil }
