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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CautiousCapsLock/certsmith/internal/model"
	"github.com/CautiousCapsLock/certsmith/internal/uitls"
)

// writeSelfSigned puts a self-signed certificate and key into dir.
func writeSelfSigned(t *testing.T, dir, org string, notAfter time.Time) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<60))
	tpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "test.invalid", Organization: []string{org}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter, DNSNames: []string{"test.invalid"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, _ := x509.MarshalECPrivateKey(key)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, uitls.KeyFile), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, uitls.CertFile), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRegeneratingThePageCertificate(t *testing.T) {
	ts, ws := newTestServer(t)
	c := setupAndLogin(t, ts)
	dir := t.TempDir()
	writeSelfSigned(t, dir, uitls.BootstrapOrg, time.Now().AddDate(0, 6, 0))
	withUIDir(t, dir)
	beforeFP := uiCertInfo().Fingerprint

	// a wrong password changes nothing
	if code, _, _ := call(t, c, "POST", ts.URL+"/api/ui-cert/regenerate", map[string]string{"confirm": "not-the-password"}, false, nil); code != 403 {
		t.Fatalf("wrong password: %d, want 403", code)
	}
	if uiCertInfo().Fingerprint != beforeFP {
		t.Fatal("the certificate changed although the password was wrong")
	}

	code, body, _ := call(t, c, "POST", ts.URL+"/api/ui-cert/regenerate", map[string]string{"confirm": pw1}, false, nil)
	if code != 200 {
		t.Fatalf("regenerate: %d %s", code, body)
	}
	var out struct {
		UICert UICert `json:"ui_cert"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	if out.UICert.Fingerprint == "" || out.UICert.Fingerprint == beforeFP || !out.UICert.Bootstrap {
		t.Errorf("the answer must carry the new certificate: %+v", out.UICert)
	}
	if time.Until(out.UICert.NotAfter) < 4*365*24*time.Hour {
		t.Errorf("valid until %v", out.UICert.NotAfter)
	}

	// it is in the audit log and the event list, by the person who did it
	var audited bool
	ws.St.View(func(db *model.DB) {
		for _, a := range db.Audit {
			if a.Action == "ui_cert.regenerate" && a.User == "admin" && strings.Contains(a.Detail, "SHA-256") {
				audited = true
			}
		}
	})
	if !audited {
		t.Error("the regeneration is not in the audit log")
	}
}

func TestOnlyCertSmithsOwnCertificateCanBeRegenerated(t *testing.T) {
	ts, _ := newTestServer(t)
	c := setupAndLogin(t, ts)

	// a certificate someone supplied
	dir := t.TempDir()
	writeSelfSigned(t, dir, "Somebody Else Ltd", time.Now().AddDate(1, 0, 0))
	withUIDir(t, dir)
	before, _ := os.ReadFile(filepath.Join(dir, uitls.CertFile))
	code, body, _ := call(t, c, "POST", ts.URL+"/api/ui-cert/regenerate", map[string]string{"confirm": pw1}, false, nil)
	if code != 409 {
		t.Fatalf("a certificate that is not CertSmith's own: %d %s, want 409", code, body)
	}
	after, _ := os.ReadFile(filepath.Join(dir, uitls.CertFile))
	if string(before) != string(after) {
		t.Fatal("a certificate that is not CertSmith's own was overwritten")
	}

	// behind a reverse proxy there is nothing to regenerate
	withUIDir(t, "")
	if code, _, _ := call(t, c, "POST", ts.URL+"/api/ui-cert/regenerate", map[string]string{"confirm": pw1}, false, nil); code != 400 {
		t.Errorf("without TLS: %d, want 400", code)
	}

	// and it needs a session
	if code, _, _ := call(t, newClient(), "POST", ts.URL+"/api/ui-cert/regenerate", map[string]string{"confirm": pw1}, false, nil); code == 200 {
		t.Error("an unauthenticated visitor regenerated the certificate")
	}
}

func TestTheAutomaticRenewalOnlyTouchesCertSmithsOwnCertificate(t *testing.T) {
	_, ws := newTestServer(t)
	now := time.Now()

	dir := t.TempDir()
	writeSelfSigned(t, dir, uitls.BootstrapOrg, now.Add(10*24*time.Hour))
	withUIDir(t, dir)
	before := uiCertInfo().Fingerprint
	if !ws.renewUICertOnce(now, uiCertRenewWithin) {
		t.Fatal("a certificate ten days from expiry was not renewed")
	}
	if uiCertInfo().Fingerprint == before {
		t.Error("the certificate did not change")
	}
	var logged bool
	ws.St.View(func(db *model.DB) {
		for _, a := range db.Audit {
			logged = logged || a.Action == "ui_cert.renew"
		}
	})
	if !logged {
		t.Error("the renewal is not in the audit log")
	}
	if ws.renewUICertOnce(now, uiCertRenewWithin) {
		t.Error("a freshly renewed certificate was renewed again")
	}

	// a certificate that is not CertSmith's own, even one about to expire
	foreign := t.TempDir()
	writeSelfSigned(t, foreign, "Somebody Else Ltd", now.Add(24*time.Hour))
	withUIDir(t, foreign)
	fp := uiCertInfo().Fingerprint
	if ws.renewUICertOnce(now, uiCertRenewWithin) || uiCertInfo().Fingerprint != fp {
		t.Error("a certificate that is not CertSmith's own was renewed")
	}

	// no TLS at all
	withUIDir(t, "")
	if ws.renewUICertOnce(now, uiCertRenewWithin) {
		t.Error("renewed a certificate although the page runs without TLS")
	}
}
