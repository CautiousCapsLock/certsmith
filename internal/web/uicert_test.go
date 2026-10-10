package web

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/CautiousCapsLock/certsmith/internal/plugin"
	"github.com/CautiousCapsLock/certsmith/internal/uitls"
)

func fetchUICert(t *testing.T, c interface{}, url string, do func() (int, string)) UICert {
	t.Helper()
	code, body := do()
	if code != 200 {
		t.Fatalf("state: %d %s", code, body)
	}
	var s struct {
		UICert UICert `json:"ui_cert"`
	}
	if err := json.Unmarshal([]byte(body), &s); err != nil {
		t.Fatal(err)
	}
	return s.UICert
}

func withUIDir(t *testing.T, dir string) {
	t.Helper()
	prev := plugin.GetOptions()
	plugin.SetOptions(plugin.Options{UITLSDir: dir, UIListen: prev.UIListen, AllowCommands: prev.AllowCommands})
	t.Cleanup(func() { plugin.SetOptions(prev) })
}

func TestTheStateSaysWhichCertificateThePageIsServedWith(t *testing.T) {
	ts, _ := newTestServer(t)
	c := setupAndLogin(t, ts)
	get := func() UICert {
		return fetchUICert(t, nil, "", func() (int, string) {
			code, body, _ := call(t, c, "GET", ts.URL+"/api/state", nil, false, nil)
			return code, body
		})
	}

	// behind a reverse proxy there is no certificate of its own
	withUIDir(t, "")
	if u := get(); u.TLS {
		t.Fatalf("plain HTTP behind a proxy must say so: %+v", u)
	}

	// the self-signed certificate CertSmith makes for itself
	dir := t.TempDir()
	if _, err := uitls.New(dir); err != nil {
		t.Fatal(err)
	}
	withUIDir(t, dir)
	u := get()
	if !u.TLS || !u.SelfSigned || !u.Bootstrap || u.Fingerprint == "" || len(u.Names) == 0 || u.NotAfter.Before(time.Now().AddDate(1, 0, 0)) {
		t.Fatalf("bootstrap certificate: %+v", u)
	}
	if u.Subject == "" {
		t.Fatalf("a subject is always shown: %+v", u)
	}
	first := u.Fingerprint

	// a certificate from a CA replaces it (what a deployment of the page's own target writes)
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Example Issuing CA"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().AddDate(5, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "certs.example.com"},
		DNSNames: []string{"certs.example.com", "*.example.com"}, IPAddresses: []net.IP{net.ParseIP("192.0.2.5")},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(0, 3, 0)}, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)
	if err := os.WriteFile(filepath.Join(dir, uitls.CertFile), chain, 0o644); err != nil {
		t.Fatal(err)
	}
	u = get()
	if !u.TLS || u.SelfSigned || u.Bootstrap || u.Issuer != "Example Issuing CA" || u.Subject != "certs.example.com" || u.Fingerprint == first {
		t.Fatalf("CA-issued certificate: %+v", u)
	}
	if len(u.Names) != 3 || u.Names[2] != "192.0.2.5" {
		t.Fatalf("names = %v", u.Names)
	}

	// a missing or broken file is reported, not hidden
	if err := os.WriteFile(filepath.Join(dir, uitls.CertFile), []byte("not a certificate"), 0o644); err != nil {
		t.Fatal(err)
	}
	if u = get(); !u.TLS || u.Error == "" {
		t.Fatalf("a broken file must be reported: %+v", u)
	}
}
