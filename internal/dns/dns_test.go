package dns

import (
	"net"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/hopscotch-go/hopscotch/internal/identity"
)

func TestShortName(t *testing.T) {
	cases := []struct {
		in     string
		short  string
		inZone bool
	}{
		{"baz.hopscotch.", "baz", true},
		{"BAZ.HOPSCOTCH", "baz", true},
		{"baz.", "baz", true},
		{"dns.hopscotch.", "dns", true},
		{"example.com.", "", false},
		{"foo.bar.hopscotch.", "foo.bar", true},
	}
	for _, c := range cases {
		short, inZone := ShortName(c.in)
		if short != c.short || inZone != c.inZone {
			t.Fatalf("%q: got %q %v", c.in, short, inZone)
		}
	}
}

func TestReplyAAAA(t *testing.T) {
	want := net.ParseIP("fd00::aa").To16()
	q := mustQuery(t, "baz.hopscotch.", dnsmessage.TypeAAAA)
	raw := Reply(q, func(name string) Record {
		if name != "baz" {
			t.Fatalf("lookup %q", name)
		}
		return Record{AAAA: want}
	})
	ip := parseAAAA(t, raw)
	if !ip.Equal(want) {
		t.Fatalf("got %s", ip)
	}
}

func TestReplyAIsNODATA(t *testing.T) {
	q := mustQuery(t, "baz.hopscotch.", dnsmessage.TypeA)
	raw := Reply(q, func(string) Record { return Record{AAAA: net.ParseIP("fd00::aa")} })
	hdr, answers := parseMsg(t, raw)
	if hdr.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("rcode %v", hdr.RCode)
	}
	if answers != 0 {
		t.Fatalf("answers %d", answers)
	}
}

func TestReplyUnknownNXDOMAIN(t *testing.T) {
	q := mustQuery(t, "nope.hopscotch.", dnsmessage.TypeAAAA)
	raw := Reply(q, func(string) Record { return Record{} })
	hdr, _ := parseMsg(t, raw)
	if hdr.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("rcode %v", hdr.RCode)
	}
}

func TestReplyOutsideZoneRefused(t *testing.T) {
	q := mustQuery(t, "example.com.", dnsmessage.TypeAAAA)
	raw := Reply(q, func(string) Record { t.Fatal("lookup"); return Record{} })
	hdr, _ := parseMsg(t, raw)
	if hdr.RCode != dnsmessage.RCodeRefused {
		t.Fatalf("rcode %v", hdr.RCode)
	}
}

func TestReplyDNSName(t *testing.T) {
	q := mustQuery(t, "dns.hopscotch.", dnsmessage.TypeAAAA)
	raw := Reply(q, func(name string) Record {
		if name != "dns" {
			t.Fatalf("lookup %q", name)
		}
		return Record{AAAA: identity.ResolverULA()}
	})
	ip := parseAAAA(t, raw)
	if !ip.Equal(identity.ResolverULA()) {
		t.Fatalf("got %s", ip)
	}
}

func mustQuery(t *testing.T, name string, typ dnsmessage.Type) []byte {
	t.Helper()
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{ID: 7, RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name:  dnsmessage.MustNewName(name),
			Type:  typ,
			Class: dnsmessage.ClassINET,
		}},
	}
	b, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func parseMsg(t *testing.T, raw []byte) (dnsmessage.Header, int) {
	t.Helper()
	var p dnsmessage.Parser
	hdr, err := p.Start(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.SkipAllQuestions(); err != nil {
		t.Fatal(err)
	}
	n := 0
	for {
		_, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		n++
		if err := p.SkipAnswer(); err != nil {
			t.Fatal(err)
		}
	}
	return hdr, n
}

func parseAAAA(t *testing.T, raw []byte) net.IP {
	t.Helper()
	var p dnsmessage.Parser
	if _, err := p.Start(raw); err != nil {
		t.Fatal(err)
	}
	if err := p.SkipAllQuestions(); err != nil {
		t.Fatal(err)
	}
	h, err := p.AnswerHeader()
	if err != nil {
		t.Fatal(err)
	}
	if h.Type != dnsmessage.TypeAAAA {
		t.Fatalf("type %v", h.Type)
	}
	rr, err := p.AAAAResource()
	if err != nil {
		t.Fatal(err)
	}
	return net.IP(rr.AAAA[:])
}
