//go:build darwin

package tun

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

const sioCAIFADDR = unix.SIOCAIFADDR

type ifAliasReq struct {
	name      [16]byte
	addr      unix.RawSockaddrInet4
	broadaddr unix.RawSockaddrInet4
	mask      unix.RawSockaddrInet4
}

var routeSeq atomic.Uintptr

func nextRouteSeq() int {
	return int(routeSeq.Add(1))
}

func writeRoute(rtm *route.RouteMessage) error {
	if rtm.Version == 0 {
		rtm.Version = unix.RTM_VERSION
	}
	if rtm.ID == 0 {
		rtm.ID = uintptr(os.Getpid())
	}
	if rtm.Seq == 0 {
		rtm.Seq = nextRouteSeq()
	}
	b, err := rtm.Marshal()
	if err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	unix.CloseOnExec(fd)
	_, err = unix.Write(fd, b)
	if err == nil {
		return nil
	}
	if errors.Is(err, unix.EEXIST) && rtm.Type == unix.RTM_ADD {
		return nil
	}
	if errors.Is(err, unix.ENOENT) && rtm.Type == unix.RTM_DELETE {
		return nil
	}
	return err
}

func routeHostAdd(inet6 bool, host, gw net.IP) error {
	return routeHost(unix.RTM_ADD, inet6, host, gw)
}

func routeHostDel(inet6 bool, host net.IP) error {
	return routeHost(unix.RTM_DELETE, inet6, host, nil)
}

func routeHost(op int, inet6 bool, host, gw net.IP) error {
	flags := unix.RTF_UP | unix.RTF_STATIC
	if op == unix.RTM_DELETE {
		flags = 0
	}
	rtm := &route.RouteMessage{Type: op, Flags: flags}
	if inet6 {
		ip6 := host.To16()
		if ip6 == nil {
			return fmt.Errorf("tun: bad ipv6 route")
		}
		var hip, mask [16]byte
		copy(hip[:], ip6)
		for i := 0; i < 128; i++ {
			mask[i/8] |= 1 << (7 - uint(i%8))
		}
		addrs := []route.Addr{
			unix.RTAX_DST:     &route.Inet6Addr{IP: hip},
			unix.RTAX_NETMASK: &route.Inet6Addr{IP: mask},
		}
		if op == unix.RTM_ADD {
			gw6 := gw.To16()
			if gw6 == nil {
				return fmt.Errorf("tun: bad ipv6 gateway")
			}
			var hgw [16]byte
			copy(hgw[:], gw6)
			addrs[unix.RTAX_GATEWAY] = &route.Inet6Addr{IP: hgw}
		}
		rtm.Addrs = addrs
		return writeRoute(rtm)
	}
	ip4 := host.To4()
	if ip4 == nil {
		return fmt.Errorf("tun: bad ipv4 route")
	}
	var hip, mask [4]byte
	copy(hip[:], ip4)
	mask = [4]byte{255, 255, 255, 255}
	addrs := []route.Addr{
		unix.RTAX_DST:     &route.Inet4Addr{IP: hip},
		unix.RTAX_NETMASK: &route.Inet4Addr{IP: mask},
	}
	if op == unix.RTM_ADD {
		gw4 := gw.To4()
		if gw4 == nil {
			return fmt.Errorf("tun: bad ipv4 gateway")
		}
		var hgw [4]byte
		copy(hgw[:], gw4)
		addrs[unix.RTAX_GATEWAY] = &route.Inet4Addr{IP: hgw}
	}
	rtm.Addrs = addrs
	return writeRoute(rtm)
}

func routePrefixIf(op int, inet6 bool, dst net.IP, ones int, ifName string) error {
	ifi, err := net.InterfaceByName(ifName)
	if err != nil {
		return err
	}
	flags := unix.RTF_UP | unix.RTF_STATIC
	if op == unix.RTM_DELETE {
		flags = 0
	}
	rtm := &route.RouteMessage{
		Type:  op,
		Flags: flags,
		Index: ifi.Index,
	}
	if inet6 {
		ip6 := dst.To16()
		if ip6 == nil {
			return fmt.Errorf("tun: bad ipv6 prefix")
		}
		var dip, mask [16]byte
		copy(dip[:], ip6)
		for i := 0; i < ones; i++ {
			mask[i/8] |= 1 << (7 - uint(i%8))
		}
		rtm.Addrs = []route.Addr{
			unix.RTAX_DST:     &route.Inet6Addr{IP: dip},
			unix.RTAX_GATEWAY: &route.LinkAddr{Index: ifi.Index},
			unix.RTAX_NETMASK: &route.Inet6Addr{IP: mask},
		}
		return writeRoute(rtm)
	}
	ip4 := dst.To4()
	if ip4 == nil {
		return fmt.Errorf("tun: bad ipv4 prefix")
	}
	var dip, mask [4]byte
	copy(dip[:], ip4)
	for i := 0; i < ones; i++ {
		mask[i/8] |= 1 << (7 - uint(i%8))
	}
	rtm.Addrs = []route.Addr{
		unix.RTAX_DST:     &route.Inet4Addr{IP: dip},
		unix.RTAX_GATEWAY: &route.LinkAddr{Index: ifi.Index},
		unix.RTAX_NETMASK: &route.Inet4Addr{IP: mask},
	}
	return writeRoute(rtm)
}

type darwinRoutePin struct {
	inet6 bool
	host  net.IP
}

type darwinRouteSplit struct {
	inet6 bool
	dst   net.IP
	ones  int
}

func physicalGatewayFromRIB(inet6 bool) net.IP {
	rib, err := route.FetchRIB(syscall.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		return nil
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil
	}
	var fallback net.IP
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok || !isDefaultRoute(rm, inet6) {
			continue
		}
		gw := routeGateway(rm, inet6)
		if gw == nil {
			continue
		}
		if ifi := routeIface(rm); ifi != nil && skipTunnelDev(ifi.Name) {
			continue
		}
		return gw
	}
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok || !isDefaultRoute(rm, inet6) {
			continue
		}
		if gw := routeGateway(rm, inet6); gw != nil {
			fallback = gw
		}
	}
	return fallback
}

func isDefaultRoute(rm *route.RouteMessage, inet6 bool) bool {
	if len(rm.Addrs) <= unix.RTAX_DST {
		return false
	}
	if inet6 {
		dst, ok := rm.Addrs[unix.RTAX_DST].(*route.Inet6Addr)
		if !ok {
			return false
		}
		var zero [16]byte
		return dst.IP == zero
	}
	dst, ok := rm.Addrs[unix.RTAX_DST].(*route.Inet4Addr)
	if !ok {
		return false
	}
	return dst.IP == [4]byte{}
}

func routeGateway(rm *route.RouteMessage, inet6 bool) net.IP {
	if len(rm.Addrs) <= unix.RTAX_GATEWAY {
		return nil
	}
	if inet6 {
		gw, ok := rm.Addrs[unix.RTAX_GATEWAY].(*route.Inet6Addr)
		if !ok {
			return nil
		}
		return net.IP(gw.IP[:])
	}
	gw, ok := rm.Addrs[unix.RTAX_GATEWAY].(*route.Inet4Addr)
	if !ok {
		return nil
	}
	return net.IP(gw.IP[:])
}

func routeIface(rm *route.RouteMessage) *net.Interface {
	if len(rm.Addrs) > unix.RTAX_GATEWAY {
		if la, ok := rm.Addrs[unix.RTAX_GATEWAY].(*route.LinkAddr); ok && la.Index > 0 {
			ifi, err := net.InterfaceByIndex(la.Index)
			if err == nil {
				return ifi
			}
		}
	}
	if rm.Index > 0 {
		ifi, err := net.InterfaceByIndex(rm.Index)
		if err == nil {
			return ifi
		}
	}
	return nil
}

func sock4(ip net.IP) unix.RawSockaddrInet4 {
	var sa unix.RawSockaddrInet4
	sa.Len = uint8(unix.SizeofSockaddrInet4)
	sa.Family = unix.AF_INET
	copy(sa.Addr[:], ip.To4())
	return sa
}

func addInet4Alias(name string, ip net.IP) error {
	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("not ipv4")
	}
	var req ifAliasReq
	copy(req.name[:], name)
	req.addr = sock4(ip4)
	req.broadaddr = sock4(ip4)
	// Point-to-point utun: leave ifra_mask zero (same as ifconfig inet x x alias).
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), sioCAIFADDR, uintptr(unsafe.Pointer(&req)))
	if errno == 0 || errno == unix.EEXIST {
		return nil
	}
	return errno
}

func addInet4RouteCGNAT(name string) error {
	return routePrefixIf(unix.RTM_ADD, false, net.IPv4(100, 64, 0, 0), 10, name)
}
