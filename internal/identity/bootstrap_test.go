package identity

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

func TestBootstrapDir(t *testing.T) {
	dir := t.TempDir()
	if err := BootstrapDir(dir, []string{"Foo", "bar"}); err != nil {
		t.Fatal(err)
	}
	ca, err := LoadCert(filepath.Join(dir, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	fooCert, err := LoadCert(filepath.Join(dir, "foo.crt"))
	if err != nil {
		t.Fatal(err)
	}
	got := NamesFromCert(fooCert)
	if len(got) != 1 || got[0] != "foo" {
		t.Fatalf("foo names %v", got)
	}
	if _, err := VerifyChain([][]byte{fooCert.Raw}, pool(ca)); err != nil {
		t.Fatal(err)
	}

	fooPEM, err := os.ReadFile(filepath.Join(dir, "foo.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if err := BootstrapDir(dir, []string{"foo", "bar"}); err != nil {
		t.Fatal(err)
	}
	again, err := os.ReadFile(filepath.Join(dir, "foo.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(fooPEM) != string(again) {
		t.Fatal("existing cert was rewritten")
	}
}

func TestBootstrapDirHalfCA(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ca.key"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := BootstrapDir(dir, []string{"foo"}); err == nil {
		t.Fatal("expected error when only ca.key exists")
	}
}

func pool(ca *x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca)
	return p
}
