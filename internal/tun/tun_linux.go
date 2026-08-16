//go:build linux

package tun

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
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
	if err := nlAddrAdd(uint32(ifi.Index), unix.AF_INET6, ip, 128); err != nil {
		return err
	}
	if !opts.Gateway {
		return nil
	}
	dst := make(net.IP, 16)
	dst[0] = 0xfd
	return nlRouteAdd(uint32(ifi.Index), unix.AF_INET6, dst, 8)
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
