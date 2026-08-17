//go:build darwin

package tun

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"unsafe"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

const (
	utunControlName = "com.apple.net.utun_control"
	sysprotoControl = 2 // SYSPROTO_CONTROL
	utunOptIfName   = 2 // UTUN_OPT_IFNAME
)

type device struct {
	f    *os.File
	name string
}

// Open creates a macOS utun interface for overlay IPv6 traffic.
func Open() (Device, error) {
	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, sysprotoControl)
	if err != nil {
		return nil, err
	}
	unix.CloseOnExec(fd)

	ctl := &unix.CtlInfo{}
	copy(ctl.Name[:], utunControlName)
	if err := unix.IoctlCtlInfo(fd, ctl); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("utun control: %w", err)
	}

	if err := unix.Connect(fd, &unix.SockaddrCtl{ID: ctl.Id, Unit: 0}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("utun connect: %w", err)
	}

	name, err := unix.GetsockoptString(fd, sysprotoControl, utunOptIfName)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("utun name: %w", err)
	}

	_ = setMTU(name, MTU)

	return &device{f: os.NewFile(uintptr(fd), name), name: name}, nil
}

// Name returns the kernel-assigned utun interface name.
func (d *device) Name() string { return d.name }

// ReadPacket reads the next IPv4 or IPv6 packet from the utun device.
func (d *device) ReadPacket() ([]byte, error) {
	buf := make([]byte, 4+MTU)
	for {
		n, err := d.f.Read(buf)
		if err != nil {
			return nil, err
		}
		if n < 4 {
			return nil, fmt.Errorf("utun short read")
		}
		fam := binary.BigEndian.Uint32(buf[:4])
		if fam != unix.AF_INET6 && fam != unix.AF_INET {
			continue
		}
		pkt := make([]byte, n-4)
		copy(pkt, buf[4:n])
		return pkt, nil
	}
}

// WritePacket writes an IPv4 or IPv6 packet to the utun device.
func (d *device) WritePacket(pkt []byte) error {
	if len(pkt) == 0 {
		return nil
	}
	fam := uint32(unix.AF_INET6)
	if pkt[0]>>4 == 4 {
		fam = unix.AF_INET
	}
	buf := make([]byte, 4+len(pkt))
	binary.BigEndian.PutUint32(buf[:4], fam)
	copy(buf[4:], pkt)
	_, err := d.f.Write(buf)
	return err
}

// Close releases the utun file descriptor.
func (d *device) Close() error { return d.f.Close() }

const (
	sioCAIfAddrIN6 = 0x8080691a // SIOCAIFADDR_IN6
	nd6Infinite    = 0xffffffff
)

type in6AliasReq struct {
	name      [16]byte
	addr      unix.RawSockaddrInet6
	dst       unix.RawSockaddrInet6
	mask      unix.RawSockaddrInet6
	flags     int32
	expire    int64
	preferred int64
	vltime    uint32
	pltime    uint32
}

// Configure assigns the ULA address and, for gateways, an fd00::/8 route on macOS.
func Configure(d Device, opts Opts) error {
	ip := opts.IP.To16()
	if ip == nil {
		return fmt.Errorf("tun: need IPv6 ULA")
	}
	name := d.Name()
	if !safeIfName(name) {
		return fmt.Errorf("tun: bad interface name %q", name)
	}
	_ = setMTU(name, MTU)
	if err := addInet6(name, ip, 128); err != nil {
		return err
	}
	if pl := opts.PlumbingIP.To4(); pl != nil {
		if err := addInet4Alias(name, pl); err != nil {
			return fmt.Errorf("tun plumbing ipv4: %w", err)
		}
	}
	if !opts.Gateway {
		return nil
	}
	dst := make(net.IP, 16)
	dst[0] = 0xfd
	if err := addInet6Route(name, dst, 8); err != nil {
		return err
	}
	if opts.Exit {
		if err := addInet4RouteCGNAT(name); err != nil {
			return fmt.Errorf("tun exit cgnat: %w", err)
		}
	}
	return nil
}

// installDefaultRoutes installs more-specific /1+/1 defaults via ifName so they
// beat the Wi‑Fi default without relying on an interface-scoped 0.0.0.0/0
// (which Darwin marks IFSCOPE and ignores for global traffic). Underlay peer
// /32 and /128 routes are pinned via the previous default gateway first.
func installDefaultRoutes(ifName string, pins []PinRoute) (func() error, error) {
	if !safeIfName(ifName) {
		return nil, fmt.Errorf("tun: bad interface name %q", ifName)
	}
	gw4 := physicalGateway(false)
	gw6 := physicalGateway(true)
	// Clear stale loopback host pins from earlier buggy installs.
	_ = routeCmd("delete", "-inet", "-host", "127.0.0.1")
	_ = routeCmd("delete", "-inet6", "-host", "::1")
	var pinned []string // args after "route -n delete"
	for _, p := range pins {
		dst := p.Dst
		if dst == nil || isLoopbackIP(dst) {
			// 127/8 must stay on lo0. Pinning 127.0.0.1 via Wi‑Fi yields
			// "can't assign requested address" for local UDP peers.
			continue
		}
		if ip4 := dst.To4(); ip4 != nil {
			gw := p.Gateway
			if gw == nil || gw.To4() == nil {
				gw = gw4
			}
			if gw == nil || gw.To4() == nil {
				continue
			}
			if err := routeCmd("add", "-inet", "-host", ip4.String(), gw.To4().String()); err != nil {
				_ = revertRoutePins(pinned)
				return nil, fmt.Errorf("tun pin %s: %w", ip4, err)
			}
			pinned = append(pinned, "-inet", "-host", ip4.String())
			continue
		}
		ip6 := dst.To16()
		if ip6 == nil {
			continue
		}
		gw := p.Gateway
		if gw == nil || gw.To4() != nil || gw.To16() == nil {
			gw = gw6
		}
		if gw == nil || gw.To16() == nil || gw.To4() != nil {
			continue
		}
		if err := routeCmd("add", "-inet6", "-host", ip6.String(), gw.String()); err != nil {
			_ = revertRoutePins(pinned)
			return nil, fmt.Errorf("tun pin %s: %w", ip6, err)
		}
		pinned = append(pinned, "-inet6", "-host", ip6.String())
	}
	splits := [][]string{
		// Darwin stores these as 0/1 and 128.0/1; use the same names on
		// delete so Close/revert actually removes them.
		{"-inet", "0/1", "-interface", ifName},
		{"-inet", "128.0/1", "-interface", ifName},
		{"-inet6", "::/1", "-interface", ifName},
		{"-inet6", "8000::/1", "-interface", ifName},
	}
	var added [][]string
	for _, args := range splits {
		_ = routeCmd(append([]string{"delete"}, args[:2]...)...) // dest only; ignore missing
		if err := routeCmd(append([]string{"add"}, args...)...); err != nil {
			_ = revertSplitDefaults(added)
			_ = revertRoutePins(pinned)
			return nil, fmt.Errorf("tun default %s: %w", args[1], err)
		}
		added = append(added, args)
	}
	return func() error {
		_ = revertSplitDefaults(added)
		return revertRoutePins(pinned)
	}, nil
}

func routeCmd(args ...string) error {
	out, err := exec.Command("route", append([]string{"-n"}, args...)...).CombinedOutput()
	if err != nil {
		if bytes.Contains(out, []byte("File exists")) {
			return nil
		}
		return fmt.Errorf("%w: %s", err, bytes.TrimSpace(out))
	}
	return nil
}

func revertSplitDefaults(added [][]string) error {
	var first error
	for i := len(added) - 1; i >= 0; i-- {
		if err := routeCmd(append([]string{"delete"}, added[i]...)...); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func revertRoutePins(pinned []string) error {
	// pinned is flat: -inet -host ip | -inet6 -host ip
	var first error
	for i := 0; i+2 < len(pinned); i += 3 {
		if err := routeCmd(append([]string{"delete"}, pinned[i:i+3]...)...); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func currentDefaultGateway(inet6 bool) net.IP {
	return physicalGateway(inet6)
}

// physicalGateway prefers a default route with an IP next hop (en0/Wi‑Fi),
// not link#utun / IFSCOPE defaults from hopscotch or other VPNs.
func physicalGateway(inet6 bool) net.IP {
	fam := "inet"
	if inet6 {
		fam = "inet6"
	}
	out, err := exec.Command("netstat", "-rn", "-f", fam).CombinedOutput()
	if err != nil {
		return gatewayFromRouteGet(inet6)
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "default" {
			continue
		}
		gw := net.ParseIP(fields[1])
		if gw == nil {
			continue // link#N — skip interface-scoped / VPN defaults
		}
		if inet6 && gw.To4() != nil {
			continue
		}
		if !inet6 && gw.To4() == nil {
			continue
		}
		return gw
	}
	return gatewayFromRouteGet(inet6)
}

func gatewayFromRouteGet(inet6 bool) net.IP {
	args := []string{"-n", "get"}
	if inet6 {
		args = append(args, "-inet6")
	}
	args = append(args, "default")
	out, err := exec.Command("route", args...).CombinedOutput()
	if err != nil {
		return nil
	}
	for _, line := range bytes.Split(out, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if !bytes.HasPrefix(line, []byte("gateway:")) {
			continue
		}
		s := strings.TrimSpace(string(bytes.TrimPrefix(line, []byte("gateway:"))))
		ip := net.ParseIP(s)
		if ip == nil {
			return nil
		}
		return ip
	}
	return nil
}

func pinHost(dst net.IP) (func() error, error) {
	if ip4 := dst.To4(); ip4 != nil {
		gw := physicalGateway(false)
		if gw == nil || gw.To4() == nil {
			return nil, fmt.Errorf("tun pin %s: no physical ipv4 gateway", ip4)
		}
		if err := routeCmd("add", "-inet", "-host", ip4.String(), gw.To4().String()); err != nil {
			return nil, err
		}
		return func() error {
			return routeCmd("delete", "-inet", "-host", ip4.String())
		}, nil
	}
	ip6 := dst.To16()
	if ip6 == nil {
		return nil, fmt.Errorf("tun pin: bad address")
	}
	gw := physicalGateway(true)
	if gw == nil || gw.To4() != nil {
		return nil, fmt.Errorf("tun pin %s: no physical ipv6 gateway", ip6)
	}
	if err := routeCmd("add", "-inet6", "-host", ip6.String(), gw.String()); err != nil {
		return nil, err
	}
	return func() error {
		return routeCmd("delete", "-inet6", "-host", ip6.String())
	}, nil
}

// sock6 builds a RawSockaddrInet6 for the given IPv6 address.
func sock6(ip net.IP) unix.RawSockaddrInet6 {
	var sa unix.RawSockaddrInet6
	sa.Len = uint8(unix.SizeofSockaddrInet6)
	sa.Family = unix.AF_INET6
	copy(sa.Addr[:], ip.To16())
	return sa
}

// prefixMask6 returns a sockaddr mask with the given prefix length in bits.
func prefixMask6(ones int) unix.RawSockaddrInet6 {
	mask := make(net.IP, 16)
	for i := 0; i < ones; i++ {
		mask[i/8] |= 1 << (7 - uint(i%8))
	}
	return sock6(mask)
}

// addInet6 adds an IPv6 address to the named interface via SIOCAIFADDR_IN6.
func addInet6(name string, ip net.IP, ones int) error {
	var req in6AliasReq
	copy(req.name[:], name)
	req.addr = sock6(ip)
	req.dst = sock6(ip)
	req.mask = prefixMask6(ones)
	req.vltime = nd6Infinite
	req.pltime = nd6Infinite
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), sioCAIfAddrIN6, uintptr(unsafe.Pointer(&req)))
	if errno == 0 || errno == unix.EEXIST {
		return nil
	}
	return errno
}

// addInet6Route installs a static IPv6 route out the named interface.
func addInet6Route(name string, dst net.IP, ones int) error {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return err
	}
	var dip, mask [16]byte
	copy(dip[:], dst.To16())
	for i := 0; i < ones; i++ {
		mask[i/8] |= 1 << (7 - uint(i%8))
	}
	rtm := &route.RouteMessage{
		Version: unix.RTM_VERSION,
		Type:    unix.RTM_ADD,
		Flags:   unix.RTF_UP | unix.RTF_STATIC,
		Index:   ifi.Index,
		ID:      uintptr(os.Getpid()),
		Seq:     1,
		Addrs: []route.Addr{
			unix.RTAX_DST:     &route.Inet6Addr{IP: dip},
			unix.RTAX_GATEWAY: &route.LinkAddr{Index: ifi.Index},
			unix.RTAX_NETMASK: &route.Inet6Addr{IP: mask},
		},
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
	if errors.Is(err, unix.EEXIST) {
		return nil
	}
	return err
}

// setMTU sets the interface MTU via SIOCSIFMTU.
func setMTU(name string, mtu int) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	ifr := unix.IfreqMTU{MTU: int32(mtu)}
	copy(ifr.Name[:], name)
	return unix.IoctlSetIfreqMTU(fd, &ifr)
}

func addInet4Alias(name string, ip net.IP) error {
	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("not ipv4")
	}
	out, err := exec.Command("ifconfig", name, "inet", ip4.String(), ip4.String(), "alias").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, out)
	}
	return nil
}

func addInet4RouteCGNAT(name string) error {
	out, err := exec.Command("route", "-n", "add", "-inet", "100.64.0.0/10", "-interface", name).CombinedOutput()
	if err != nil {
		if bytes.Contains(out, []byte("File exists")) {
			return nil
		}
		return fmt.Errorf("%w: %s", err, out)
	}
	return nil
}
