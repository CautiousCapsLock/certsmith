package certimport

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

type issued struct {
	cert *x509.Certificate
	key  crypto.Signer
}

func newKey(t *testing.T, kind string) crypto.Signer {
	t.Helper()
	switch kind {
	case "ec":
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	case "rsa1024":
		k, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			t.Fatal(err)
		}
		return k
	case "ed":
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

type spec struct {
	cn         string
	dns        []string
	ips        []net.IP
	isCA       bool
	notAfter   time.Time
	keyKind    string
	sigAlg     x509.SignatureAlgorithm
	noEKU      bool
	clientOnly bool // key usage: client authentication only
}

// sign creates a certificate under parent (nil parent: self-signed).
func sign(t *testing.T, s spec, parent *issued) issued {
	t.Helper()
	key := newKey(t, s.keyKind)
	if s.notAfter.IsZero() {
		s.notAfter = time.Now().AddDate(1, 0, 0)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<60))
	tpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: s.cn, Organization: []string{"Test"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: s.notAfter,
		DNSNames: s.dns, IPAddresses: s.ips, IsCA: s.isCA, BasicConstraintsValid: true,
		SignatureAlgorithm: s.sigAlg,
	}
	if s.isCA {
		tpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	} else {
		tpl.KeyUsage = x509.KeyUsageDigitalSignature
		switch {
		case s.clientOnly:
			tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		case !s.noEKU:
			tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		}
	}
	signerCert, signerKey := tpl, key
	if parent != nil {
		signerCert, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, signerCert, key.Public(), signerKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return issued{c, key}
}

func certPEM(cs ...*x509.Certificate) []byte {
	var b []byte
	for _, c := range cs {
		b = append(b, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return b
}

func keyPEM(t *testing.T, k crypto.Signer, format string) []byte {
	t.Helper()
	switch format {
	case "pkcs1":
		return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k.(*rsa.PrivateKey))})
	case "sec1":
		der, _ := x509.MarshalECPrivateKey(k.(*ecdsa.PrivateKey))
		return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// a three-level hierarchy: root > intermediate > leaf for two names
func hierarchy(t *testing.T, leafKind string) (root, inter, leaf issued) {
	t.Helper()
	root = sign(t, spec{cn: "Test Root CA", isCA: true, notAfter: time.Now().AddDate(10, 0, 0)}, nil)
	inter = sign(t, spec{cn: "Test Issuing CA", isCA: true, notAfter: time.Now().AddDate(5, 0, 0)}, &root)
	leaf = sign(t, spec{cn: "app.example.com", dns: []string{"app.example.com", "*.apps.example.com"}, ips: []net.IP{net.ParseIP("192.0.2.7")}, keyKind: leafKind}, &inter)
	return
}

func TestPEMWithTheChainInOneFile(t *testing.T) {
	root, inter, leaf := hierarchy(t, "rsa")
	r, err := Parse(Input{CertPEM: certPEM(leaf.cert, inter.cert, root.cert), KeyPEM: keyPEM(t, leaf.key, "pkcs1")}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(r.Domains, ","); got != "app.example.com,*.apps.example.com,192.0.2.7" {
		t.Errorf("names = %s", got)
	}
	if r.KeyType != "rsa2048" || r.Issuer != "Test Issuing CA" || r.Summary.ChainLength != 1 || !r.Summary.RootSupplied {
		t.Errorf("summary: %+v", r.Summary)
	}
	if len(r.Summary.Warnings) != 0 {
		t.Errorf("a complete chain should carry no warnings: %v", r.Summary.Warnings)
	}
	// the served chain is leaf + intermediate; the root is not sent
	certs, _ := parseCerts(r.Bundle.FullChain)
	if len(certs) != 2 || !sameCert(certs[1], inter.cert) {
		t.Errorf("full chain has %d certificates, want leaf + intermediate", len(certs))
	}
	if !strings.Contains(string(r.Bundle.KeyPEM), "RSA PRIVATE KEY") {
		t.Errorf("key not stored in the form the device plug-ins read: %.30s", r.Bundle.KeyPEM)
	}
}

func TestChainOrderInTheFilesDoesNotMatter(t *testing.T) {
	root, inter, leaf := hierarchy(t, "ec")
	// root first, then intermediate, then the leaf last, and the chain in a separate file
	r, err := Parse(Input{CertPEM: certPEM(leaf.cert), ChainPEM: certPEM(root.cert, inter.cert), KeyPEM: keyPEM(t, leaf.key, "sec1")}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if r.KeyType != "ec256" || r.Summary.ChainLength != 1 {
		t.Errorf("%+v", r.Summary)
	}
	// the leaf is identified by the key, even when it is not the first certificate
	r2, err := Parse(Input{CertPEM: certPEM(root.cert, inter.cert, leaf.cert), KeyPEM: keyPEM(t, leaf.key, "pkcs8")}, time.Now())
	if err != nil || r2.Domains[0] != "app.example.com" {
		t.Fatalf("leaf last: %v %+v", err, r2)
	}
}

func TestPKCS12ModernAndLegacy(t *testing.T) {
	root, inter, leaf := hierarchy(t, "rsa")
	for name, enc := range map[string]*pkcs12.Encoder{"modern": pkcs12.Modern, "legacy": pkcs12.Legacy} {
		t.Run(name, func(t *testing.T) {
			p12, err := enc.Encode(leaf.key, leaf.cert, []*x509.Certificate{inter.cert, root.cert}, "s3cret")
			if err != nil {
				t.Fatal(err)
			}
			r, err := Parse(Input{P12: p12, Password: "s3cret"}, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if r.Domains[0] != "app.example.com" || r.Summary.ChainLength != 1 {
				t.Errorf("%+v", r.Summary)
			}
			if _, err := Parse(Input{P12: p12, Password: "wrong"}, time.Now()); err == nil || !strings.Contains(err.Error(), "password") {
				t.Errorf("a wrong password must be reported as such: %v", err)
			}
		})
	}
	if _, err := Parse(Input{P12: []byte("this is not a pkcs12 file"), Password: "x"}, time.Now()); err == nil || !strings.Contains(err.Error(), "PKCS#12") {
		t.Errorf("garbage: %v", err)
	}
}

func TestMismatchedKeyIsRefused(t *testing.T) {
	_, inter, leaf := hierarchy(t, "rsa")
	other := newKey(t, "rsa")
	_, err := Parse(Input{CertPEM: certPEM(leaf.cert, inter.cert), KeyPEM: keyPEM(t, other, "pkcs1")}, time.Now())
	if err == nil || !strings.Contains(err.Error(), "does not belong") {
		t.Fatalf("got %v", err)
	}
}

func TestEncryptedKeysAreRefusedWithTheFix(t *testing.T) {
	_, _, leaf := hierarchy(t, "rsa")
	enc := pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte("x")})
	_, err := Parse(Input{CertPEM: certPEM(leaf.cert), KeyPEM: enc}, time.Now())
	if err == nil || !strings.Contains(err.Error(), "passphrase") || !strings.Contains(err.Error(), "openssl") {
		t.Fatalf("got %v", err)
	}
	legacy := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": "AES-128-CBC,00"}, Bytes: []byte("x")})
	if _, err := Parse(Input{CertPEM: certPEM(leaf.cert), KeyPEM: legacy}, time.Now()); err == nil || !strings.Contains(err.Error(), "passphrase") {
		t.Fatalf("legacy encrypted: %v", err)
	}
}

func TestUnusableCertificatesAreRefused(t *testing.T) {
	now := time.Now()
	ca := sign(t, spec{cn: "Only A CA", isCA: true, noEKU: true}, nil)
	expired := sign(t, spec{cn: "old.example.com", dns: []string{"old.example.com"}, notAfter: now.Add(-24 * time.Hour)}, nil)
	noNames := sign(t, spec{}, nil)
	weak := sign(t, spec{cn: "weak.example.com", dns: []string{"weak.example.com"}, keyKind: "rsa1024"}, nil)
	ed := sign(t, spec{cn: "ed.example.com", dns: []string{"ed.example.com"}, keyKind: "ed"}, nil)
	cases := []struct {
		name string
		in   issued
		fmt  string
		want string
	}{
		{"a CA certificate", ca, "pkcs8", "CA certificate"},
		{"expired", expired, "pkcs1", "expired on"},
		{"no names", noNames, "pkcs1", "no host names"},
		{"weak RSA", weak, "pkcs1", "too weak"},
		{"Ed25519", ed, "pkcs8", "not support"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Parse(Input{CertPEM: certPEM(c.in.cert), KeyPEM: keyPEM(t, c.in.key, c.fmt)}, now)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("got %v, want an error containing %q", err, c.want)
			}
		})
	}
}

func TestDoubtfulCertificatesAreAcceptedWithWarnings(t *testing.T) {
	now := time.Now()
	root, inter, leaf := hierarchy(t, "rsa")
	cases := []struct {
		name  string
		input func() Input
		want  string
	}{
		{"no issuing CA supplied", func() Input { return Input{CertPEM: certPEM(leaf.cert), KeyPEM: keyPEM(t, leaf.key, "pkcs1")} }, "No CA certificate that issued"},
		{"unrelated certificates", func() Input {
			stray := sign(t, spec{cn: "Stray CA", isCA: true}, nil)
			return Input{CertPEM: certPEM(leaf.cert, inter.cert, stray.cert), KeyPEM: keyPEM(t, leaf.key, "pkcs1")}
		}, "not part of this certificate's chain"},
		{"expires soon", func() Input {
			soon := sign(t, spec{cn: "soon.example.com", dns: []string{"soon.example.com"}, notAfter: now.Add(5 * 24 * time.Hour)}, &inter)
			return Input{CertPEM: certPEM(soon.cert, inter.cert), KeyPEM: keyPEM(t, soon.key, "pkcs1")}
		}, "expires in"},
		{"self-signed", func() Input {
			ss := sign(t, spec{cn: "ss.example.com", dns: []string{"ss.example.com"}}, nil)
			return Input{CertPEM: certPEM(ss.cert), KeyPEM: keyPEM(t, ss.key, "pkcs1")}
		}, "self-signed"},
		{"not for servers", func() Input {
			c := sign(t, spec{cn: "client.example.com", dns: []string{"client.example.com"}, clientOnly: true}, &inter)
			return Input{CertPEM: certPEM(c.cert), KeyPEM: keyPEM(t, c.key, "pkcs1"), ChainPEM: certPEM(inter.cert, root.cert)}
		}, "not marked for server authentication"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := Parse(c.input(), now)
			if err != nil {
				t.Fatalf("a doubtful certificate must still import: %v", err)
			}
			if c.want == "" {
				return
			}
			joined := strings.Join(r.Summary.Warnings, " | ")
			if !strings.Contains(joined, c.want) {
				t.Errorf("warnings %q do not mention %q", joined, c.want)
			}
		})
	}
}

func TestOversizedInputIsRefused(t *testing.T) {
	big := make([]byte, MaxBytes+1)
	if _, err := Parse(Input{P12: big}, time.Now()); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("got %v", err)
	}
	if _, err := Parse(Input{}, time.Now()); err == nil {
		t.Error("nothing supplied must be an error")
	}
}
