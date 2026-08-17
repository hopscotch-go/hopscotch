//go:build linux

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
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	ifaAddress      = 1
	ifaLocal        = 2
	rtaDst          = 1
	rtaOif          = 4
	rtnUnicast      = 1
	rtTableMain     = 254
	rtScopeUniverse = 0
)

type device struct {
	f    *os.File
	name string
}

// Open creates a Linux TUN device named hopscotch0 for overlay IPv6 traffic.
func Open() (Device, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	ifr, err := unix.NewIfreq("hopscotch0")
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("TUNSETIFF: %w", err)
	}
	name := ifr.Name()
	return &device{f: os.NewFile(uintptr(fd), name), name: name}, nil
}

// Name returns the TUN interface name.
func (d *device) Name() string { return d.name }

// ReadPacket reads the next raw IP packet from the TUN device.
func (d *device) ReadPacket() ([]byte, error) {
	buf := make([]byte, 2048)
	n, err := d.f.Read(buf)
	if err != nil {
		return nil, err
	}
	pkt := make([]byte, n)
	copy(pkt, buf[:n])
	return pkt, nil
}

// WritePacket writes a raw IP packet to the TUN device.
func (d *device) WritePacket(pkt []byte) error {
	_, err := d.f.Write(pkt)
	return err
}

// Close releases the TUN file descriptor.
func (d *device) Close() error { return d.f.Close() }

// Configure assigns the ULA address and, for gateways, an fd00::/8 route on Linux.
func Configure(d Device, opts Opts) error {
	ip := opts.IP.To16()
	if ip == nil {
		return fmt.Errorf("tun: need IPv6 ULA")
	}
	name := d.Name()
	if !safeIfName(name) {
		return fmt.Errorf("tun: bad interface name %q", name)
	}
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return err
	}
	if err := linkUpMTU(name); err != nil {
		return err
	}
	idx := uint32(ifi.Index)
	if err := nlAddrAdd(idx, unix.AF_INET6, ip, 128); err != nil {
		return err
	}
	if pl := opts.PlumbingIP.To4(); pl != nil {
		if err := nlAddrAdd(idx, unix.AF_INET, pl, 32); err != nil {
			return fmt.Errorf("tun plumbing ipv4: %w", err)
		}
	}
	if !opts.Gateway {
		return nil
	}
	dst := make(net.IP, 16)
	dst[0] = 0xfd
	if err := nlRouteAdd(idx, unix.AF_INET6, dst, 8); err != nil {
		return err
	}
	if opts.Exit {
		cgnat := net.IPv4(100, 64, 0, 0)
		if err := nlRouteAdd(idx, unix.AF_INET, cgnat, 10); err != nil {
			return fmt.Errorf("tun exit cgnat: %w", err)
		}
	}
	return nil
}

// installDefaultRoutes installs /1+/1 defaults via ifName (more specific than
// 0.0.0.0/0 / ::/0) and pins underlay peers via the previous default gateway.
func installDefaultRoutes(ifName string, pins []PinRoute) (func() error, error) {
	if !safeIfName(ifName) {
		return nil, fmt.Errorf("tun: bad interface name %q", ifName)
	}
	gw4 := physicalGateway(false)
	gw6 := physicalGateway(true)
	_ = ipCmd("route", "del", "127.0.0.1/32")
	_ = ipCmd("-6", "route", "del", "::1/128")

	var pinned [][]string // ip args after "route del" / "-6 route del"
	for _, p := range pins {
		dst := p.Dst
		if dst == nil || isLoopbackIP(dst) {
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
			args := []string{"route", "replace", ip4.String() + "/32", "via", gw.To4().String()}
			if err := ipCmd(args...); err != nil {
				_ = revertIPRoutes(pinned)
				return nil, fmt.Errorf("tun pin %s: %w", ip4, err)
			}
			pinned = append(pinned, []string{"route", "del", ip4.String() + "/32"})
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
		args := []string{"-6", "route", "replace", ip6.String() + "/128", "via", gw.String()}
		if err := ipCmd(args...); err != nil {
			_ = revertIPRoutes(pinned)
			return nil, fmt.Errorf("tun pin %s: %w", ip6, err)
		}
		pinned = append(pinned, []string{"-6", "route", "del", ip6.String() + "/128"})
	}

	splits := [][]string{
		{"route", "replace", "0.0.0.0/1", "dev", ifName},
		{"route", "replace", "128.0.0.0/1", "dev", ifName},
		{"-6", "route", "replace", "::/1", "dev", ifName},
		{"-6", "route", "replace", "8000::/1", "dev", ifName},
	}
	var added [][]string
	for _, args := range splits {
		if err := ipCmd(args...); err != nil {
			_ = revertIPRoutes(added)
			_ = revertIPRoutes(pinned)
			return nil, fmt.Errorf("tun default %v: %w", args, err)
		}
		del := append([]string{}, args...)
		for i, a := range del {
			if a == "replace" {
				del[i] = "del"
				break
			}
		}
		added = append(added, del)
	}
	return func() error {
		_ = revertIPRoutes(added)
		return revertIPRoutes(pinned)
	}, nil
}

func ipCmd(args ...string) error {
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, bytes.TrimSpace(out))
	}
	return nil
}

func revertIPRoutes(cmds [][]string) error {
	var first error
	for i := len(cmds) - 1; i >= 0; i-- {
		if err := ipCmd(cmds[i]...); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func linuxDefaultGateway(inet6 bool) net.IP {
	return physicalGateway(inet6)
}

func physicalGateway(inet6 bool) net.IP {
	args := []string{"route", "show", "default"}
	if inet6 {
		args = []string{"-6", "route", "show", "default"}
	}
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		return nil
	}
	// Prefer a default with via <IP> on a non-hopscotch / non-tun device.
	var fallback net.IP
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		var via net.IP
		dev := ""
		for i := 0; i+1 < len(fields); i++ {
			switch fields[i] {
			case "via":
				via = net.ParseIP(fields[i+1])
			case "dev":
				dev = fields[i+1]
			}
		}
		if via == nil {
			continue
		}
		if strings.Contains(dev, "hopscotch") || strings.HasPrefix(dev, "tun") || strings.HasPrefix(dev, "utun") {
			continue
		}
		return via
	}
	// Fall back to first via if every default looked like a tunnel.
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		for i := 0; i+1 < len(fields); i++ {
			if fields[i] == "via" {
				if ip := net.ParseIP(fields[i+1]); ip != nil {
					return ip
				}
			}
		}
	}
	return fallback
}

func pinHost(dst net.IP) (func() error, error) {
	if ip4 := dst.To4(); ip4 != nil {
		gw := physicalGateway(false)
		if gw == nil || gw.To4() == nil {
			return nil, fmt.Errorf("tun pin %s: no physical ipv4 gateway", ip4)
		}
		args := []string{"route", "replace", ip4.String() + "/32", "via", gw.To4().String()}
		if err := ipCmd(args...); err != nil {
			return nil, err
		}
		return func() error {
			return ipCmd("route", "del", ip4.String()+"/32")
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
	if err := ipCmd("-6", "route", "replace", ip6.String()+"/128", "via", gw.String()); err != nil {
		return nil, err
	}
	return func() error {
		return ipCmd("-6", "route", "del", ip6.String()+"/128")
	}, nil
}

// linkUpMTU brings the interface up and sets its MTU.
func linkUpMTU(name string) error {
	s, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(s)
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(s, unix.SIOCGIFFLAGS, ifr); err != nil {
		return err
	}
	ifr.SetUint16(ifr.Uint16() | uint16(unix.IFF_UP) | uint16(unix.IFF_RUNNING))
	if err := unix.IoctlIfreq(s, unix.SIOCSIFFLAGS, ifr); err != nil {
		return err
	}
	ifr.SetUint32(uint32(MTU))
	return unix.IoctlIfreq(s, unix.SIOCSIFMTU, ifr)
}

// nlAddrAdd adds an address to an interface via RTM_NEWADDR.
func nlAddrAdd(index uint32, family uint8, ip net.IP, ones int) error {
	ifa := unix.IfAddrmsg{
		Family:    family,
		Prefixlen: uint8(ones),
		Flags:     uint8(unix.IFA_F_PERMANENT),
		Scope:     rtScopeUniverse,
		Index:     index,
	}
	if family == unix.AF_INET6 {
		ifa.Flags |= uint8(unix.IFA_F_NODAD)
	}
	addr := ip.To4()
	if family == unix.AF_INET6 {
		addr = ip.To16()
	}
	payload := append(structBytes(&ifa), nla(ifaAddress, addr)...)
	payload = append(payload, nla(ifaLocal, addr)...)
	return nlReq(unix.RTM_NEWADDR, unix.NLM_F_REQUEST|unix.NLM_F_ACK|unix.NLM_F_CREATE|unix.NLM_F_REPLACE, payload)
}

// nlRouteAdd installs a route via RTM_NEWROUTE.
func nlRouteAdd(index uint32, family uint8, dst net.IP, ones int) error {
	rt := unix.RtMsg{
		Family:   family,
		Dst_len:  uint8(ones),
		Table:    rtTableMain,
		Protocol: unix.RTPROT_BOOT,
		Scope:    rtScopeUniverse,
		Type:     rtnUnicast,
	}
	addr := dst.To4()
	if family == unix.AF_INET6 {
		addr = dst.To16()
	}
	payload := append(structBytes(&rt), nla(rtaDst, addr)...)
	payload = append(payload, nlaU32(rtaOif, index)...)
	return nlReq(unix.RTM_NEWROUTE, unix.NLM_F_REQUEST|unix.NLM_F_ACK|unix.NLM_F_CREATE|unix.NLM_F_REPLACE, payload)
}

// nlReq sends a netlink request and checks the NLMSG_ERROR acknowledgment.
func nlReq(typ, flags uint16, payload []byte) error {
	h := unix.NlMsghdr{
		Len:   uint32(unix.SizeofNlMsghdr + len(payload)),
		Type:  typ,
		Flags: flags,
		Seq:   1,
		Pid:   uint32(os.Getpid()),
	}
	msg := append(structBytes(&h), payload...)
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	if err := unix.Sendto(fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	buf := make([]byte, 2048)
	n, _, err := unix.Recvfrom(fd, buf, 0)
	if err != nil {
		return err
	}
	if n < unix.SizeofNlMsghdr+unix.SizeofNlMsgerr {
		return fmt.Errorf("tun: short netlink reply")
	}
	var hdr unix.NlMsghdr
	copy(structBytes(&hdr), buf[:unix.SizeofNlMsghdr])
	if hdr.Type != unix.NLMSG_ERROR {
		return nil
	}
	var nlerr unix.NlMsgerr
	copy(structBytes(&nlerr), buf[unix.SizeofNlMsghdr:unix.SizeofNlMsghdr+unix.SizeofNlMsgerr])
	if nlerr.Error == 0 {
		return nil
	}
	errno := syscall.Errno(-nlerr.Error)
	if errors.Is(errno, unix.EEXIST) {
		return nil
	}
	return errno
}

// nla encodes a netlink attribute with the given type and payload.
func nla(typ uint16, data []byte) []byte {
	l := unix.SizeofRtAttr + len(data)
	pad := (l + 3) &^ 3
	b := make([]byte, pad)
	binary.NativeEndian.PutUint16(b[0:2], uint16(l))
	binary.NativeEndian.PutUint16(b[2:4], typ)
	copy(b[4:], data)
	return b
}

// nlaU32 encodes a uint32 netlink attribute.
func nlaU32(typ uint16, v uint32) []byte {
	var d [4]byte
	binary.NativeEndian.PutUint32(d[:], v)
	return nla(typ, d[:])
}

// structBytes returns a byte view of the in-memory representation of p.
func structBytes[T any](p *T) []byte {
	n := unsafe.Sizeof(*p)
	return unsafe.Slice((*byte)(unsafe.Pointer(p)), n)
}
