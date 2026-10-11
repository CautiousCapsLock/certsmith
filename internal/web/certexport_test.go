package web

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"github.com/CautiousCapsLock/certsmith/internal/model"
)

// importedID imports a certificate and returns its id.
func importedID(t *testing.T, ts string, c *http.Client, name string) (string, testPKI) {
	t.Helper()
	p := newPKI(t, "ems.example.com", "*.example.com")
	code, body, _ := call(t, c, "POST", ts+"/api/certs/import", importBody(p, name), false, nil)
	if code != 200 {
		t.Fatalf("import: %d %s", code, body)
	}
	var out struct{ ID string }
	_ = json.Unmarshal([]byte(body), &out)
	return out.ID, p
}

func TestDownloadingACertificateAsPKCS12(t *testing.T) {
	ts, ws := newTestServer(t)
	c := setupAndLogin(t, ts)
	id, p := importedID(t, ts.URL, c, "EMS server")

	req := map[string]any{"format": "p12", "password": "a file password", "confirm": pw1}
	code, body, hdr := call(t, c, "POST", ts.URL+"/api/certs/"+id+"/export", req, false, nil)
	if code != 200 {
		t.Fatalf("export: %d %s", code, body)
	}
	if got := hdr.Get("Content-Disposition"); got != `attachment; filename="EMS-server.p12"` {
		t.Errorf("Content-Disposition = %q", got)
	}
	if hdr.Get("Cache-Control") != "no-store" {
		t.Errorf("a file with a private key must not be cached: %q", hdr.Get("Cache-Control"))
	}
	key, leaf, cas, err := pkcs12.DecodeChain([]byte(body), "a file password")
	if err != nil {
		t.Fatalf("the file does not open with its password: %v", err)
	}
	if leaf.Subject.CommonName != "ems.example.com" || len(cas) != 1 || key == nil {
		t.Errorf("content: leaf %q, %d CA certificates, key %v (the self-signed root is not part of the chain)", leaf.Subject.CommonName, len(cas), key != nil)
	}
	if _, _, _, err := pkcs12.DecodeChain([]byte(body), "not the password"); err == nil {
		t.Error("the file opened with a wrong password")
	}
	_ = p
	// the audit log says what happened, to what, and never the password
	var found bool
	ws.St.View(func(db *model.DB) {
		for _, a := range db.Audit {
			if a.Action == "cert.export" {
				found = true
				if a.Subject != "EMS server" || a.User == "" || strings.Contains(a.Detail+a.Subject, "a file password") || !strings.Contains(a.Detail, "PKCS#12") {
					t.Errorf("audit entry = %+v", a)
				}
			}
		}
	})
	if !found {
		t.Error("the download was not written to the audit log")
	}
}

func TestDownloadingACertificateAsPEMFiles(t *testing.T) {
	ts, _ := newTestServer(t)
	c := setupAndLogin(t, ts)
	id, _ := importedID(t, ts.URL, c, "EMS server")
	code, body, hdr := call(t, c, "POST", ts.URL+"/api/certs/"+id+"/export", map[string]any{"format": "pem", "confirm": pw1}, false, nil)
	if code != 200 || hdr.Get("Content-Type") != "application/zip" {
		t.Fatalf("export: %d %s %s", code, hdr.Get("Content-Type"), body[:min(60, len(body))])
	}
	zr, err := zip.NewReader(bytes.NewReader([]byte(body)), int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{}
	for _, f := range zr.File {
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		files[f.Name] = string(b)
	}
	for _, n := range []string{"cert.pem", "chain.pem", "fullchain.pem", "key.pem"} {
		if files[n] == "" {
			t.Errorf("%s missing from the archive (have %v)", n, keysOf(files))
		}
	}
	if !strings.Contains(files["key.pem"], "PRIVATE KEY") || strings.Contains(files["cert.pem"], "PRIVATE KEY") {
		t.Error("key.pem must hold the key and cert.pem must not")
	}
}

func keysOf(m map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestADownloadNeedsTheUsersOwnPasswordAndAGoodFilePassword(t *testing.T) {
	ts, ws := newTestServer(t)
	c := setupAndLogin(t, ts)
	id, _ := importedID(t, ts.URL, c, "EMS server")
	url := ts.URL + "/api/certs/" + id + "/export"

	for name, tc := range map[string]struct {
		body map[string]any
		code int
	}{
		"no confirmation":        {map[string]any{"format": "pem"}, 400},
		"wrong account password": {map[string]any{"format": "pem", "confirm": "not my password"}, 403},
		"short file password":    {map[string]any{"format": "p12", "password": "short", "confirm": pw1}, 400},
		"unknown format":         {map[string]any{"format": "jks", "confirm": pw1}, 400},
	} {
		code, body, _ := call(t, c, "POST", url, tc.body, false, nil)
		if code != tc.code {
			t.Errorf("%s: %d %s, want %d", name, code, body, tc.code)
		}
		if strings.Contains(body, "PRIVATE KEY") {
			t.Errorf("%s: key material in a refused response", name)
		}
	}
	// a stranger gets nothing, and an unknown certificate is not found
	if code, _, _ := call(t, newClient(), "POST", url, map[string]any{"format": "pem", "confirm": pw1}, false, nil); code == 200 {
		t.Error("an unauthenticated request must not return a certificate")
	}
	if code, _, _ := call(t, c, "POST", ts.URL+"/api/certs/nope/export", map[string]any{"format": "pem", "confirm": pw1}, false, nil); code != 404 {
		t.Errorf("unknown certificate = %d, want 404", code)
	}
	// no refused request was recorded as a download
	ws.St.View(func(db *model.DB) {
		for _, a := range db.Audit {
			if a.Action == "cert.export" {
				t.Errorf("a refused request was audited as a download: %+v", a)
			}
		}
	})
}

func TestACertificateNotYetIssuedCannotBeDownloaded(t *testing.T) {
	ts, ws := newTestServer(t)
	c := setupAndLogin(t, ts)
	_ = ws.St.Update(func(db *model.DB) error {
		db.Certificates = append(db.Certificates, model.Certificate{ID: "x1", Name: "pending", Domains: []string{"a.example.com"}})
		return nil
	})
	code, body, _ := call(t, c, "POST", ts.URL+"/api/certs/x1/export", map[string]any{"format": "pem", "confirm": pw1}, false, nil)
	if code != 409 || !strings.Contains(body, "no certificate has been issued") {
		t.Errorf("%d %s", code, body)
	}
}
