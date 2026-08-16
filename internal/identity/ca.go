package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/big"
	"net/url"
	"time"
)

func CreateCA() (*x509.Certificate, ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pub := priv.Public().(ed25519.PublicKey)
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return cert, priv, nil
}

func SignNode(ca *x509.Certificate, caKey ed25519.PrivateKey, nodePub ed25519.PublicKey, names ...string) (*x509.Certificate, error) {
	names, err := NormalizeNames(names)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	var uris []*url.URL
	for _, n := range names {
		uris = append(uris, NameURI(n))
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		URIs:         uris,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, nodePub, caKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func InitCAFiles(keyPath, certPath string) error {
	if fileExists(keyPath) {
		return fmt.Errorf("%s already exists", keyPath)
	}
	if fileExists(certPath) {
		return fmt.Errorf("%s already exists", certPath)
	}
	cert, key, err := CreateCA()
	if err != nil {
		return err
	}
	if err := writeKey(keyPath, key); err != nil {
		return err
	}
	return WriteCert(certPath, cert)
}

func SignNodeFiles(caKeyPath, caCertPath, identityPath, outPath string, names ...string) error {
	caKey, err := LoadKey(caKeyPath)
	if err != nil {
		return err
	}
	caCert, err := LoadCert(caCertPath)
	if err != nil {
		return err
	}
	priv, err := LoadOrCreate(identityPath)
	if err != nil {
		return err
	}
	pub := priv.Public().(ed25519.PublicKey)
	cert, err := SignNode(caCert, caKey, pub, names...)
	if err != nil {
		return err
	}
	return WriteCert(outPath, cert)
}

func TLSCertFromSigned(priv ed25519.PrivateKey, nodeCert *x509.Certificate) (tls.Certificate, error) {
	pub := priv.Public().(ed25519.PublicKey)
	want, ok := nodeCert.PublicKey.(ed25519.PublicKey)
	if !ok || !pub.Equal(want) {
		return tls.Certificate{}, fmt.Errorf("node cert public key does not match identity key")
	}
	return tls.Certificate{
		Certificate: [][]byte{nodeCert.Raw},
		PrivateKey:  priv,
		Leaf:        nodeCert,
	}, nil
}

func VerifyChain(rawCerts [][]byte, roots *x509.CertPool) (*x509.Certificate, error) {
	if len(rawCerts) == 0 {
		return nil, fmt.Errorf("no peer certificate")
	}
	certs := make([]*x509.Certificate, len(rawCerts))
	for i, raw := range rawCerts {
		c, err := x509.ParseCertificate(raw)
		if err != nil {
			return nil, err
		}
		certs[i] = c
	}
	leaf := certs[0]
	if leaf.IsCA {
		return nil, fmt.Errorf("peer presented a CA certificate")
	}
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	if _, err := leaf.Verify(opts); err != nil {
		return nil, err
	}
	return leaf, nil
}

func randomSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}
