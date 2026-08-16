package peers

import "testing"

func TestParseAddrOnly(t *testing.T) {
	got, err := Parse("127.0.0.1:4433\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Addr != "udp:127.0.0.1:4433" || got[0].Pub != nil {
		t.Fatalf("%+v", got)
	}
}

func TestParsePubkeyAndComment(t *testing.T) {
	text := `
# seed
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  10.0.0.1:4433
`
	got, err := Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Addr != "udp:10.0.0.1:4433" || len(got[0].Pub) != 32 {
		t.Fatalf("%+v", got)
	}
}

func TestParseTCPPrefix(t *testing.T) {
	got, err := Parse("tcp:127.0.0.1:9\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Addr != "tcp:127.0.0.1:9" {
		t.Fatalf("%+v", got)
	}
}

func TestParseRejectsBadLine(t *testing.T) {
	if _, err := Parse("not-an-addr\n"); err == nil {
		t.Fatal("expected error")
	}
}
