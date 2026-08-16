//go:build darwin

package tun

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
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

func (d *device) Name() string { return d.name }

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
		if fam != unix.AF_INET6 {
			continue
		}
		pkt := make([]byte, n-4)
		copy(pkt, buf[4:n])
		return pkt, nil
	}
}

func (d *device) WritePacket(pkt []byte) error {
	buf := make([]byte, 4+len(pkt))
	binary.BigEndian.PutUint32(buf[:4], unix.AF_INET6)
	copy(buf[4:], pkt)
	_, err := d.f.Write(buf)
	return err
}

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
	if !opts.Gateway {
		return nil
	}
	dst := make(net.IP, 16)
	dst[0] = 0xfd
	return addInet6Route(name, dst, 8)
}

func sock6(ip net.IP) unix.RawSockaddrInet6 {
	var sa unix.RawSockaddrInet6
	sa.Len = uint8(unix.SizeofSockaddrInet6)
	sa.Family = unix.AF_INET6
	copy(sa.Addr[:], ip.To16())
	return sa
}

func prefixMask6(ones int) unix.RawSockaddrInet6 {
	mask := make(net.IP, 16)
	for i := 0; i < ones; i++ {
		mask[i/8] |= 1 << (7 - uint(i%8))
	}
	return sock6(mask)
}

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
