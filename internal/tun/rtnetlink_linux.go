//go:build linux

package tun

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

const rtaGateway = 5

type routeSpec struct {
	family uint8
	dst    net.IP
	ones   int
	oif    uint32
	gw     net.IP
}

type routeEntry struct {
	family uint8
	dstLen uint8
	gw     net.IP
	oif    uint32
}

func nlRouteReplace(spec routeSpec) error {
	flags := uint16(unix.NLM_F_REQUEST | unix.NLM_F_ACK | unix.NLM_F_CREATE | unix.NLM_F_REPLACE)
	return nlRouteMsg(unix.RTM_NEWROUTE, flags, spec)
}

func nlRouteDelete(spec routeSpec) error {
	flags := uint16(unix.NLM_F_REQUEST | unix.NLM_F_ACK)
	err := nlRouteMsg(unix.RTM_DELROUTE, flags, spec)
	if err == nil || errors.Is(err, unix.ESRCH) || errors.Is(err, unix.ENOENT) {
		return nil
	}
	return err
}

func nlRouteMsg(typ, flags uint16, spec routeSpec) error {
	rt := unix.RtMsg{
		Family:   spec.family,
		Dst_len:  uint8(spec.ones),
		Table:    rtTableMain,
		Protocol: unix.RTPROT_BOOT,
		Scope:    rtScopeUniverse,
		Type:     rtnUnicast,
	}
	addr := spec.dst.To4()
	if spec.family == unix.AF_INET6 {
		addr = spec.dst.To16()
	}
	payload := append(structBytes(&rt), nla(rtaDst, addr)...)
	if spec.gw != nil {
		gw := spec.gw.To4()
		if spec.family == unix.AF_INET6 {
			gw = spec.gw.To16()
		}
		payload = append(payload, nla(rtaGateway, gw)...)
	}
	if spec.oif != 0 {
		payload = append(payload, nlaU32(rtaOif, spec.oif)...)
	}
	return nlReq(typ, flags, payload)
}

func nlRoutesDump() ([]routeEntry, error) {
	rt := unix.RtMsg{Family: unix.AF_UNSPEC, Table: rtTableMain}
	payloads, err := nlDump(unix.RTM_GETROUTE, structBytes(&rt))
	if err != nil {
		return nil, err
	}
	var out []routeEntry
	for _, p := range payloads {
		if len(p) < unix.SizeofRtMsg {
			continue
		}
		var rt unix.RtMsg
		copy(structBytes(&rt), p[:unix.SizeofRtMsg])
		attrs := parseRtAttrs(p[unix.SizeofRtMsg:])
		var gw net.IP
		if b, ok := attrs[rtaGateway]; ok {
			if rt.Family == unix.AF_INET && len(b) >= 4 {
				gw = net.IP(append([]byte(nil), b[:4]...))
			}
			if rt.Family == unix.AF_INET6 && len(b) >= 16 {
				gw = net.IP(append([]byte(nil), b[:16]...))
			}
		}
		var oif uint32
		if b, ok := attrs[rtaOif]; ok && len(b) >= 4 {
			oif = binary.NativeEndian.Uint32(b[:4])
		}
		out = append(out, routeEntry{
			family: rt.Family,
			dstLen: rt.Dst_len,
			gw:     gw,
			oif:    oif,
		})
	}
	return out, nil
}

func nlDump(typ uint16, payload []byte) ([][]byte, error) {
	h := unix.NlMsghdr{
		Len:   uint32(unix.SizeofNlMsghdr + len(payload)),
		Type:  typ,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_DUMP,
		Seq:   1,
		Pid:   uint32(os.Getpid()),
	}
	msg := append(structBytes(&h), payload...)
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	if err := unix.Sendto(fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	var payloads [][]byte
	buf := make([]byte, 8192)
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			return nil, err
		}
		if n < unix.SizeofNlMsghdr {
			return nil, fmt.Errorf("tun: short netlink dump")
		}
		off := 0
		for off+unix.SizeofNlMsghdr <= n {
			var hdr unix.NlMsghdr
			copy(structBytes(&hdr), buf[off:off+unix.SizeofNlMsghdr])
			if int(hdr.Len) < unix.SizeofNlMsghdr || off+int(hdr.Len) > n {
				break
			}
			body := buf[off+unix.SizeofNlMsghdr : off+int(hdr.Len)]
			switch hdr.Type {
			case unix.NLMSG_DONE:
				return payloads, nil
			case unix.NLMSG_ERROR:
				if len(body) < unix.SizeofNlMsgerr {
					return nil, fmt.Errorf("tun: short netlink error")
				}
				var nlerr unix.NlMsgerr
				copy(structBytes(&nlerr), body[:unix.SizeofNlMsgerr])
				if nlerr.Error == 0 {
					return payloads, nil
				}
				return nil, unix.Errno(-nlerr.Error)
			default:
				if hdr.Type == unix.RTM_NEWROUTE {
					payloads = append(payloads, append([]byte(nil), body...))
				}
			}
			off += int(hdr.Len)
		}
	}
}

func parseRtAttrs(b []byte) map[uint16][]byte {
	attrs := make(map[uint16][]byte)
	for len(b) >= unix.SizeofRtAttr {
		l := int(binary.NativeEndian.Uint16(b[0:2]))
		if l < unix.SizeofRtAttr {
			break
		}
		typ := binary.NativeEndian.Uint16(b[2:4])
		end := l - unix.SizeofRtAttr
		if end > 0 && unix.SizeofRtAttr+end <= len(b) {
			attrs[typ] = append([]byte(nil), b[unix.SizeofRtAttr:unix.SizeofRtAttr+end]...)
		}
		pad := (l + 3) &^ 3
		if pad > len(b) {
			break
		}
		b = b[pad:]
	}
	return attrs
}

func ifIndex(name string) (uint32, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	return uint32(ifi.Index), nil
}

func physicalGatewayFromNetlink(inet6 bool) net.IP {
	routes, err := nlRoutesDump()
	if err != nil {
		return nil
	}
	want := uint8(unix.AF_INET)
	if inet6 {
		want = unix.AF_INET6
	}
	var fallback net.IP
	for _, r := range routes {
		if r.family != want || r.dstLen != 0 || r.gw == nil {
			continue
		}
		if inet6 && r.gw.To4() != nil {
			continue
		}
		if !inet6 && r.gw.To4() == nil {
			continue
		}
		if r.oif != 0 {
			ifi, err := net.InterfaceByIndex(int(r.oif))
			if err == nil && skipTunnelDev(ifi.Name) {
				continue
			}
		}
		return r.gw
	}
	for _, r := range routes {
		if r.family != want || r.dstLen != 0 || r.gw == nil {
			continue
		}
		if inet6 && r.gw.To4() != nil {
			continue
		}
		if !inet6 && r.gw.To4() == nil {
			continue
		}
		fallback = r.gw
	}
	return fallback
}
