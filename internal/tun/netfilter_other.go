//go:build !linux

package tun

func gatewayNetFilter(string) func() error { return nil }
