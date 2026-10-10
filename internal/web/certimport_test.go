package web

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"github.com/CautiousCapsLock/certsmith/internal/model"
)

type testPKI struct {
	leafPEM, chainPEM, keyPEM string
	leaf, inter               *x509.Certificate
	key                       *ecdsa.PrivateKey
}

func mkCert(t *testing.T, cn string, dns []string, isCA bool, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, notAfter time.Time) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<60))
	tpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: cn, Organization: []string{"Test PKI"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter, DNSNames: dns, IsCA: isCA, BasicConstraintsValid: true}
	if isCA {
		tpl.KeyUsage = x509.KeyUsageCertSign
	} else {
		tpl.KeyUsage, tpl.ExtKeyUsage = x509.KeyUsageDigitalSignature, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	signer, signerKey := tpl, k
	if parent != nil {
		signer, signerKey = parent, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, signer, &k.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c, k
}

func toPEM(c *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
}

func newPKI(t *testing.T, names ...string) testPKI {
	t.Helper()
	root, rootKey := mkCert(t, "Test Root", nil, true, nil, nil, time.Now().AddDate(10, 0, 0))
	inter, interKey := mkCert(t, "Test Issuing CA", nil, true, root, rootKey, time.Now().AddDate(5, 0, 0))
	leaf, key := mkCert(t, names[0], names, false, inter, interKey, time.Now().AddDate(1, 0, 0))
	der, _ := x509.MarshalECPrivateKey(key)
	return testPKI{
		leafPEM: toPEM(leaf), chainPEM: toPEM(inter) + toPEM(root), leaf: leaf, inter: inter, key: key,
		keyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})),
	}
}

func importBody(p testPKI, name string) map[string]any {
	return map[string]any{"name": name, "cert_pem": p.leafPEM, "chain_pem": p.chainPEM, "key_pem": p.keyPEM}
}

func certsOf(t *testing.T, ws *Server) []model.Certificate {
	var out []model.Certificate
	ws.St.View(func(db *model.DB) { out = append(out, db.Certificates...) })
	return out
}

func TestImportingAPEMCertificate(t *testing.T) {
	ts, ws := newTestServer(t)
	c := setupAndLogin(t, ts)
	p := newPKI(t, "app.example.com", "*.apps.example.com")

	code, body, _ := call(t, c, "POST", ts.URL+"/api/certs/import", importBody(p, "Corporate wildcard"), false, nil)
	if code != 200 {
		t.Fatalf("import: %d %s", code, body)
	}
	var out struct {
		ID      string
		Summary struct {
			Names       []string
			ChainLength int `json:"chain_length"`
			Warnings    []string
		}
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil || out.ID == "" {
		t.Fatalf("%v %s", err, body)
	}
	if out.Summary.ChainLength != 1 || len(out.Summary.Warnings) != 0 {
		t.Errorf("summary %+v", out.Summary)
	}

	certs := certsOf(t, ws)
	if len(certs) != 1 {
		t.Fatalf("%d certificates", len(certs))
	}
	got := certs[0]
	if got.Source != model.SourceImport || got.Name != "Corporate wildcard" || !got.Enabled || got.AutoRenew || got.DNSID != "" {
		t.Errorf("stored as %+v", got)
	}
	if got.Serial == "" || got.Issuer != "Test Issuing CA" || got.NotAfter.IsZero() || got.ImportedAt.IsZero() ||
		strings.Join(got.Domains, ",") != "app.example.com,*.apps.example.com" {
		t.Errorf("details %+v", got)
	}
	// stored where deployments read it from, with the key private
	dir := filepath.Join(ws.DataDir, "certs", out.ID)
	if st, err := os.Stat(filepath.Join(dir, "key.pem")); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("key file: %v %v", err, st)
	}
	full, _ := os.ReadFile(filepath.Join(dir, "fullchain.pem"))
	if strings.Count(string(full), "BEGIN CERTIFICATE") != 2 {
		t.Errorf("the served chain must be the certificate and its issuing CA, not the root:\n%s", full)
	}

	// the private key is never in what the browser is given back
	_, state, _ := call(t, c, "GET", ts.URL+"/api/state", nil, false, nil)
	if strings.Contains(state, "PRIVATE KEY") || strings.Contains(state, p.keyPEM[:40]) {
		t.Fatal("the private key leaked into /api/state")
	}
	// and the audit log has it, by name
	var audited bool
	ws.St.View(func(db *model.DB) {
		for _, a := range db.Audit {
			audited = audited || (a.Action == "cert.import" && a.Subject == "Corporate wildcard")
		}
	})
	if !audited {
		t.Error("the import is not in the audit log")
	}
}

func TestImportingAPKCS12(t *testing.T) {
	ts, ws := newTestServer(t)
	c := setupAndLogin(t, ts)
	p := newPKI(t, "pfx.example.com")
	p12, err := pkcs12.Modern.Encode(p.key, p.leaf, []*x509.Certificate{p.inter}, "hunter2hunter2")
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.StdEncoding.EncodeToString(p12)

	if code, body, _ := call(t, c, "POST", ts.URL+"/api/certs/import", map[string]any{"name": "pfx", "p12": enc, "password": "wrong"}, false, nil); code != 400 || !strings.Contains(body, "password") {
		t.Fatalf("wrong password: %d %s", code, body)
	}
	if len(certsOf(t, ws)) != 0 {
		t.Fatal("a failed import left a certificate behind")
	}
	if code, body, _ := call(t, c, "POST", ts.URL+"/api/certs/import", map[string]any{"name": "pfx", "p12": enc, "password": "hunter2hunter2"}, false, nil); code != 200 {
		t.Fatalf("import: %d %s", code, body)
	}
	if got := certsOf(t, ws); len(got) != 1 || got[0].Domains[0] != "pfx.example.com" {
		t.Errorf("%+v", got)
	}
	// the password is not kept anywhere
	if b, _ := json.Marshal(ws.St.Snapshot()); strings.Contains(string(b), "hunter2hunter2") {
		t.Fatal("the PKCS#12 password was stored")
	}
}

func TestCheckingAnUploadStoresNothing(t *testing.T) {
	ts, ws := newTestServer(t)
	c := setupAndLogin(t, ts)
	p := newPKI(t, "check.example.com")
	code, body, _ := call(t, c, "POST", ts.URL+"/api/certs/import/check", importBody(p, ""), false, nil)
	if code != 200 || !strings.Contains(body, "check.example.com") {
		t.Fatalf("%d %s", code, body)
	}
	if len(certsOf(t, ws)) != 0 {
		t.Error("a check stored a certificate")
	}
	if entries, _ := os.ReadDir(filepath.Join(ws.DataDir, "certs")); len(entries) != 0 {
		t.Error("a check wrote files")
	}
	// problems are explained
	other := newPKI(t, "other.example.com")
	bad := importBody(p, "")
	bad["key_pem"] = other.keyPEM
	if code, body, _ := call(t, c, "POST", ts.URL+"/api/certs/import/check", bad, false, nil); code != 400 || !strings.Contains(body, "does not belong") {
		t.Errorf("mismatched key: %d %s", code, body)
	}
}

func TestAnImportedCertificateIsNeverRenewedAndOnlyItsLabelCanBeEdited(t *testing.T) {
	ts, ws := newTestServer(t)
	c := setupAndLogin(t, ts)
	p := newPKI(t, "keep.example.com")
	_, body, _ := call(t, c, "POST", ts.URL+"/api/certs/import", importBody(p, "keep"), false, nil)
	var out struct{ ID string }
	_ = json.Unmarshal([]byte(body), &out)

	if code, body, _ := call(t, c, "POST", ts.URL+"/api/certs/"+out.ID+"/renew", nil, false, nil); code != http.StatusConflict || !strings.Contains(body, "replaced, not renewed") {
		t.Errorf("renew: %d %s", code, body)
	}
	// the names come from the certificate: an edit cannot rewrite them or attach a provider
	code, _, _ := call(t, c, "PUT", ts.URL+"/api/certs/"+out.ID,
		map[string]any{"name": "renamed", "enabled": false, "domains": []string{"evil.example.com"}, "dns_id": "x", "auto_renew": true}, false, nil)
	if code != 200 {
		t.Fatalf("edit: %d", code)
	}
	got := certsOf(t, ws)[0]
	if got.Name != "renamed" || got.Enabled || strings.Join(got.Domains, ",") != "keep.example.com" || got.DNSID != "" || got.AutoRenew {
		t.Errorf("edit changed more than the label and the switch: %+v", got)
	}
}

func TestReplacingAnImportedCertificate(t *testing.T) {
	ts, ws := newTestServer(t)
	c := setupAndLogin(t, ts)
	first := newPKI(t, "rotate.example.com")
	_, body, _ := call(t, c, "POST", ts.URL+"/api/certs/import", importBody(first, "rotate"), false, nil)
	var out struct{ ID string }
	_ = json.Unmarshal([]byte(body), &out)
	before := certsOf(t, ws)[0]

	second := newPKI(t, "rotate.example.com", "www.rotate.example.com")
	code, body, _ := call(t, c, "POST", ts.URL+"/api/certs/"+out.ID+"/import", importBody(second, ""), false, nil)
	if code != 200 {
		t.Fatalf("replace: %d %s", code, body)
	}
	after := certsOf(t, ws)[0]
	if after.ID != before.ID || after.Name != "rotate" || after.Serial == before.Serial || len(after.Domains) != 2 {
		t.Errorf("before %+v\nafter  %+v", before, after)
	}
	if !after.ImportedAt.After(before.ImportedAt) && !after.ImportedAt.Equal(before.ImportedAt) {
		t.Error("ImportedAt went backwards")
	}

	// only an imported certificate can be replaced this way; unknown ids are not found
	_ = ws.St.Update(func(db *model.DB) error {
		db.Certificates = append(db.Certificates, model.Certificate{ID: "acme1", Name: "issued", Domains: []string{"a.example"}})
		return nil
	})
	if code, _, _ := call(t, c, "POST", ts.URL+"/api/certs/acme1/import", importBody(second, ""), false, nil); code != http.StatusConflict {
		t.Errorf("an ACME certificate: %d, want 409", code)
	}
	if code, _, _ := call(t, c, "POST", ts.URL+"/api/certs/nope/import", importBody(second, ""), false, nil); code != http.StatusNotFound {
		t.Errorf("unknown id: %d, want 404", code)
	}
}

func TestImportEndpointsNeedASessionAndRefuseHugeBodies(t *testing.T) {
	ts, ws := newTestServer(t)
	p := newPKI(t, "auth.example.com")
	for _, path := range []string{"/api/certs/import", "/api/certs/import/check", "/api/certs/x/import"} {
		if code, _, _ := call(t, newClient(), "POST", ts.URL+path, importBody(p, "x"), false, nil); code == 200 {
			t.Errorf("%s answered an unauthenticated visitor", path)
		}
	}
	if len(certsOf(t, ws)) != 0 {
		t.Fatal("an unauthenticated import stored a certificate")
	}
	c := setupAndLogin(t, ts)
	huge := importBody(p, "huge")
	huge["cert_pem"] = strings.Repeat("A", 6<<20)
	if code, _, _ := call(t, c, "POST", ts.URL+"/api/certs/import", huge, false, nil); code == 200 {
		t.Error("a 6 MB body was accepted")
	}
	if len(certsOf(t, ws)) != 0 {
		t.Error("an oversized import stored a certificate")
	}
}
