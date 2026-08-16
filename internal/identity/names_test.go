package identity

import (
	"crypto/x509"
	"net/url"
	"testing"
)

func TestParseName(t *testing.T) {
	n, err := ParseName("Foo")
	if err != nil || n != "foo" {
		t.Fatalf("%q %v", n, err)
	}
	if _, err := ParseName("1foo"); err == nil {
		t.Fatal("expected error")
	}
	if _, err := ParseName("foo_bar"); err == nil {
		t.Fatal("expected error")
	}
}

func TestNamesFromCertURI(t *testing.T) {
	cert := &x509.Certificate{
		URIs: []*url.URL{NameURI("foo"), NameURI("bar"), {Scheme: "https", Host: "ignore"}},
	}
	got := NamesFromCert(cert)
	if len(got) != 2 || got[0] != "foo" || got[1] != "bar" {
		t.Fatalf("%v", got)
	}
}

func TestNormalizeNamesDedup(t *testing.T) {
	got, err := NormalizeNames([]string{"Foo", "foo", "bar"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "foo" || got[1] != "bar" {
		t.Fatalf("%v", got)
	}
}
