package identity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"path/filepath"
	"testing"
)

func TestCASignsAndVerifies(t *testing.T) {
	ca, caKey, err := CreateCA()
	if err != nil {
		t.Fatal(err)
	}
	_, nodeKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := nodeKey.Public().(ed25519.PublicKey)
	cert, err := SignNode(ca, caKey, pub)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	leaf, err := VerifyChain([][]byte{cert.Raw}, roots)
	if err != nil {
		t.Fatal(err)
	}
	got := leaf.PublicKey.(ed25519.PublicKey)
	if !bytes.Equal(got, pub) {
		t.Fatal("leaf key mismatch")
	}
}

func TestSignNodeNames(t *testing.T) {
	ca, caKey, err := CreateCA()
	if err != nil {
		t.Fatal(err)
	}
	_, nodeKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := nodeKey.Public().(ed25519.PublicKey)
	cert, err := SignNode(ca, caKey, pub, "Foo", "laptop")
	if err != nil {
		t.Fatal(err)
	}
	got := NamesFromCert(cert)
	if len(got) != 2 || got[0] != "foo" || got[1] != "laptop" {
		t.Fatalf("names %v", got)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := VerifyChain([][]byte{cert.Raw}, roots); err != nil {
		t.Fatal(err)
	}
}

func TestCARejectsSelfSigned(t *testing.T) {
	ca, _, err := CreateCA()
	if err != nil {
		t.Fatal(err)
	}
	_, nodeKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	self, err := TLSCert(nodeKey)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := VerifyChain(self.Certificate, roots); err == nil {
		t.Fatal("self-signed cert should not verify against mesh CA")
	}
}

func TestInitCAFilesRefuseOverwrite(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "ca.key")
	cert := filepath.Join(dir, "ca.crt")
	if err := InitCAFiles(key, cert); err != nil {
		t.Fatal(err)
	}
	if err := InitCAFiles(key, cert); err == nil {
		t.Fatal("expected overwrite error")
	}
}

func TestSignNodeFiles(t *testing.T) {
	dir := t.TempDir()
	caKey := filepath.Join(dir, "ca.key")
	caCert := filepath.Join(dir, "ca.crt")
	idPath := filepath.Join(dir, "node.pem")
	out := filepath.Join(dir, "node.crt")
	if err := InitCAFiles(caKey, caCert); err != nil {
		t.Fatal(err)
	}
	if err := SignNodeFiles(caKey, caCert, idPath, out, "Foo", "laptop"); err != nil {
		t.Fatal(err)
	}
	priv, err := LoadKey(idPath)
	if err != nil {
		t.Fatal(err)
	}
	nodeCert, err := LoadCert(out)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := TLSCertFromSigned(priv, nodeCert); err != nil {
		t.Fatal(err)
	}
	got := NamesFromCert(nodeCert)
	if len(got) != 2 || got[0] != "foo" || got[1] != "laptop" {
		t.Fatalf("names %v", got)
	}
}
