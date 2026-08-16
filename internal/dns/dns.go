package dns

import (
	"net"
	"strings"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/hopscotch-go/hopscotch/internal/identity"
)

const ttl = 30

// Record is the overlay address for a mesh name.
type Record struct {
	AAAA net.IP
}

// ShortName maps a DNS question to a mesh node name.
// inZone is true for single-label names (search domain) and *.hopscotch.
func ShortName(qname string) (short string, inZone bool) {
	n := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(qname), "."))
	if n == "" || n == identity.NameURIScheme {
		return "", true
	}
	if suf := "." + identity.NameURIScheme; strings.HasSuffix(n, suf) {
		return strings.TrimSuffix(n, suf), true
	}
	if !strings.Contains(n, ".") {
		return n, true
	}
	return "", false
}

// Reply is a DNS response payload (no IP/UDP) for query.
func Reply(query []byte, lookup func(string) Record) []byte {
	var p dnsmessage.Parser
	hdr, err := p.Start(query)
	if err != nil {
		return nil
	}
	q, err := p.Question()
	if err != nil {
		return nil
	}
	var rec Record
	short, inZone := ShortName(q.Name.String())
	if inZone && short != "" && lookup != nil {
		rec = lookup(short)
	}
	known := rec.AAAA != nil
	out := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 hdr.ID,
			Response:           true,
			OpCode:             hdr.OpCode,
			Authoritative:      true,
			RecursionDesired:   hdr.RecursionDesired,
			RecursionAvailable: false,
			RCode:              dnsmessage.RCodeSuccess,
		},
		Questions: []dnsmessage.Question{q},
	}
	switch {
	case !inZone:
		out.Header.RCode = dnsmessage.RCodeRefused
	case q.Class != dnsmessage.ClassINET:
		out.Header.RCode = dnsmessage.RCodeNotImplemented
	case !known:
		out.Header.RCode = dnsmessage.RCodeNameError
	case q.Type == dnsmessage.TypeAAAA || q.Type == dnsmessage.TypeALL:
		if rec.AAAA != nil {
			var aaaa [16]byte
			copy(aaaa[:], rec.AAAA.To16())
			out.Answers = append(out.Answers, dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{
					Name:  q.Name,
					Type:  dnsmessage.TypeAAAA,
					Class: dnsmessage.ClassINET,
					TTL:   ttl,
				},
				Body: &dnsmessage.AAAAResource{AAAA: aaaa},
			})
		}
	default:
		// NODATA for A and other types of a known name
	}
	packed, err := out.Pack()
	if err != nil {
		return nil
	}
	return packed
}
