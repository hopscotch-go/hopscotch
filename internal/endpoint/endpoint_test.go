package endpoint

import "testing"

func TestParseDefaultUDP(t *testing.T) {
	e, err := Parse("127.0.0.1:4433", "")
	if err != nil {
		t.Fatal(err)
	}
	if e.String() != "udp:127.0.0.1:4433" {
		t.Fatalf("%s", e)
	}
}

func TestParseTCP(t *testing.T) {
	e, err := Parse("tcp:[::1]:9", "udp")
	if err != nil {
		t.Fatal(err)
	}
	if e.Network != "tcp" || e.Addr != "[::1]:9" {
		t.Fatalf("%+v", e)
	}
}

func TestParseRejectsBareHost(t *testing.T) {
	if _, err := Parse("localhost", "udp"); err == nil {
		t.Fatal("expected error")
	}
}
