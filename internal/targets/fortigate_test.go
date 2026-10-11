package targets

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"github.com/CautiousCapsLock/certsmith/internal/acme"
	"github.com/CautiousCapsLock/certsmith/internal/model"
	"github.com/CautiousCapsLock/certsmith/internal/plugin"
)

// fakeFGT is a minimal FortiOS REST emulation: enough to exercise import,
// binding switches, rollback and pruning.
type fakeFGT struct {
	mu          sync.Mutex
	certs       map[string]int // name -> q_ref
	imported    map[string]map[string]any
	values      map[string]string // "path:field" -> value
	failPut     string            // path whose PUT fails
	failGet     string            // path whose GET returns 404
	cas         map[string]string // CA store: name -> PEM
	caImport    int               // how many CA imports were accepted
	failCA      bool              // make CA imports fail
	hideUserCAs bool              // the CA list does not show user-added CAs at all
	realCAs     bool              // behave like current FortiOS: the CA list has no certificate bodies, a duplicate import is error -328
	srv         *httptest.Server
}

func newFakeFGT(t *testing.T) *fakeFGT {
	f := &fakeFGT{cas: map[string]string{}, certs: map[string]int{}, imported: map[string]map[string]any{}, values: map[string]string{
		"system/global:admin-server-cert": "Fortinet_Factory",
		"vpn.ssl/settings:servercert":     "Fortinet_Factory",
	}}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeFGT) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer tok" {
		http.Error(w, `{"status":"error"}`, http.StatusUnauthorized)
		return
	}
	p := r.URL.Path
	reply := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	switch {
	case p == "/api/v2/monitor/system/status":
		reply(map[string]any{"version": "v7.6.1", "build": 3000, "serial": "FGVMTEST", "results": map[string]any{"hostname": "fake"}})
	case p == "/api/v2/monitor/vpn-certificate/local/import" && r.Method == http.MethodPost:
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		name := body["certname"].(string)
		f.imported[name] = body
		f.certs[name] = 0
		reply(map[string]any{"status": "success"})
	case p == "/api/v2/cmdb/vpn.certificate/ca" && r.Method == http.MethodGet:
		var res []map[string]any
		for n, pemText := range f.cas {
			if f.hideUserCAs {
				continue
			}
			if f.realCAs {
				res = append(res, map[string]any{"name": n, "source": "user", "ca": ""}) // the list leaves the body out
			} else {
				res = append(res, map[string]any{"name": n, "ca": pemText})
			}
		}
		// built-in CAs: listed, never CertSmith's
		res = append(res, map[string]any{"name": "Fortinet_CA", "source": "factory", "ca": ""})
		reply(map[string]any{"results": res})
	case strings.HasPrefix(p, "/api/v2/cmdb/vpn.certificate/ca/") && r.Method == http.MethodGet:
		name := strings.TrimPrefix(p, "/api/v2/cmdb/vpn.certificate/ca/")
		pemText, ok := f.cas[name]
		if !ok {
			http.Error(w, `{"status":"error"}`, http.StatusNotFound)
			return
		}
		reply(map[string]any{"results": []map[string]any{{"name": name, "ca": pemText}}})
	case p == "/api/v2/monitor/vpn-certificate/ca/import" && r.Method == http.MethodPost:
		if f.failCA {
			http.Error(w, `{"cli_error":"import refused"}`, http.StatusInternalServerError)
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		raw, _ := base64.StdEncoding.DecodeString(body["file_content"].(string))
		if f.realCAs {
			for _, have := range f.cas {
				if strings.TrimSpace(have) == strings.TrimSpace(string(raw)) {
					http.Error(w, `{"http_method":"POST","error":-328,"status":"error","http_status":500}`, http.StatusInternalServerError)
					return
				}
			}
		}
		f.cas["CA_Cert_"+strconv.Itoa(len(f.cas)+1)] = string(raw)
		f.caImport++
		reply(map[string]any{"status": "success"})
	case p == "/api/v2/cmdb/vpn.certificate/local" && r.Method == http.MethodGet:
		var res []map[string]any
		for n, ref := range f.certs {
			res = append(res, map[string]any{"name": n, "q_ref": ref})
		}
		reply(map[string]any{"results": res})
	case strings.HasPrefix(p, "/api/v2/cmdb/vpn.certificate/local/"):
		name := strings.TrimPrefix(p, "/api/v2/cmdb/vpn.certificate/local/")
		if _, ok := f.certs[name]; !ok {
			http.Error(w, `{"status":"error"}`, http.StatusNotFound)
			return
		}
		if r.Method == http.MethodDelete {
			delete(f.certs, name)
		}
		reply(map[string]any{"status": "success"})
	case strings.HasPrefix(p, "/api/v2/cmdb/"):
		path := strings.TrimPrefix(p, "/api/v2/cmdb/")
		field := map[string]string{"system/global": "admin-server-cert", "vpn.ssl/settings": "servercert"}[path]
		if r.Method == http.MethodGet && path == f.failGet {
			http.Error(w, `{"status":"error"}`, http.StatusNotFound)
			return
		}
		if r.Method == http.MethodPut {
			if path == f.failPut {
				http.Error(w, `{"cli_error":"boom"}`, http.StatusInternalServerError)
				return
			}
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			old := f.values[path+":"+field]
			f.values[path+":"+field] = body[field]
			if _, ok := f.certs[old]; ok {
				f.certs[old]--
			}
			if _, ok := f.certs[body[field]]; ok {
				f.certs[body[field]]++
			}
			reply(map[string]any{"status": "success"})
			return
		}
		reply(map[string]any{"results": map[string]any{field: f.values[path+":"+field]}})
	default:
		http.NotFound(w, r)
	}
}

func testBundle(t *testing.T) *plugin.Bundle {
	t.Helper()
	iss := &acme.Issuer{DataDir: t.TempDir()}
	b, err := iss.Issue(context.Background(), acme.Request{
		Name: "t", Domains: []string{"*.lab.example", "lab.example"}, KeyType: "rsa2048",
		Settings: model.Settings{ACMEDirectory: model.DirSelfSigned},
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func fgCfg(f *fakeFGT) map[string]string {
	return map[string]string{
		"host": strings.TrimPrefix(f.srv.URL, "https://"), "token": "tok", "insecure": "true",
		"cert_prefix": "certsmith", "bindings": "admin-gui\nssl-vpn", "keep_old": "0",
	}
}

func TestFortiGateDeploy(t *testing.T) {
	f := newFakeFGT(t)
	b := testBundle(t)
	cfg := fgCfg(f)

	msg, err := fortiGate{}.Deploy(context.Background(), cfg, b)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(msg)

	name := certName("certsmith", b, 35)
	imp := f.imported[name]
	if imp == nil {
		t.Fatalf("certificate %s not imported; have %v", name, f.imported)
	}
	if imp["type"] != "pkcs12" {
		t.Fatalf("type = %v", imp["type"])
	}
	raw, _ := base64.StdEncoding.DecodeString(imp["file_content"].(string))
	_, leaf, ca, err := pkcs12.DecodeChain(raw, imp["password"].(string))
	if err != nil {
		t.Fatalf("pkcs12 payload invalid: %v", err)
	}
	if acme.SerialHex(leaf) != b.Serial || len(ca) != 1 {
		t.Fatalf("pkcs12 content wrong: serial %s, %d CAs", acme.SerialHex(leaf), len(ca))
	}
	if f.values["system/global:admin-server-cert"] != name || f.values["vpn.ssl/settings:servercert"] != name {
		t.Fatalf("bindings not switched: %v", f.values)
	}

	// second deploy of the same bundle is a no-op
	if _, err := (fortiGate{}).Deploy(context.Background(), cfg, b); err != nil {
		t.Fatal(err)
	}
	if len(f.imported) != 1 {
		t.Fatalf("re-import happened: %d", len(f.imported))
	}
}

func TestFortiGateRenewPrunesOld(t *testing.T) {
	f := newFakeFGT(t)
	cfg := fgCfg(f)
	f.certs["certsmith-20200101-aaaa"] = 0 // stale, unreferenced
	f.certs["certsmith-20200202-bbbb"] = 1 // stale but still referenced: must survive
	if _, err := (fortiGate{}).Deploy(context.Background(), cfg, testBundle(t)); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.certs["certsmith-20200101-aaaa"]; ok {
		t.Error("unreferenced old cert should be pruned")
	}
	if _, ok := f.certs["certsmith-20200202-bbbb"]; !ok {
		t.Error("referenced cert must not be deleted")
	}
}

func TestFortiGateRollback(t *testing.T) {
	f := newFakeFGT(t)
	f.failPut = "system/global" // admin-gui is applied last, after ssl-vpn succeeded
	_, err := fortiGate{}.Deploy(context.Background(), fgCfg(f), testBundle(t))
	if err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("expected rollback error, got %v", err)
	}
	if f.values["vpn.ssl/settings:servercert"] != "Fortinet_Factory" {
		t.Fatalf("ssl-vpn not reverted: %v", f.values)
	}
}

func TestFortiGateBadToken(t *testing.T) {
	f := newFakeFGT(t)
	cfg := fgCfg(f)
	cfg["token"] = "wrong"
	if _, err := (fortiGate{}).Test(context.Background(), cfg); err == nil {
		t.Fatal("expected auth failure")
	}
}

func TestFortiGateTest(t *testing.T) {
	f := newFakeFGT(t)
	msg, err := fortiGate{}.Test(context.Background(), fgCfg(f))
	if err != nil || !strings.Contains(msg, "v7.6.1") {
		t.Fatalf("msg=%q err=%v", msg, err)
	}
}

// The number of certificates kept on a device is the Settings value (passed by the engine as
// "_keep_total"), the certificate just deployed included.
func TestFortiGateKeepsTheNumberOfCertificatesSetInSettings(t *testing.T) {
	for _, tc := range []struct {
		keepTotal string
		wantLeft  []string // old certificates that must remain
	}{
		{"3", []string{"certsmith-20200505-eeee", "certsmith-20200404-dddd"}}, // the new one plus the two newest old ones
		{"1", nil}, // only the one in use
		{"5", []string{"certsmith-20200505-eeee", "certsmith-20200404-dddd", "certsmith-20200303-cccc", "certsmith-20200202-bbbb"}},
	} {
		f := newFakeFGT(t)
		for _, n := range []string{"certsmith-20200101-aaaa", "certsmith-20200202-bbbb", "certsmith-20200303-cccc", "certsmith-20200404-dddd", "certsmith-20200505-eeee"} {
			f.certs[n] = 0
		}
		cfg := fgCfg(f)
		delete(cfg, "keep_old") // an old per-target value must not matter once Settings decides
		cfg["keep_old"] = "0"
		cfg["_keep_total"] = tc.keepTotal
		if _, err := (fortiGate{}).Deploy(context.Background(), cfg, testBundle(t)); err != nil {
			t.Fatal(err)
		}
		var left []string
		for n := range f.certs {
			if strings.HasPrefix(n, "certsmith-2020") {
				left = append(left, n)
			}
		}
		sort.Strings(left)
		sort.Strings(tc.wantLeft)
		if strings.Join(left, ",") != strings.Join(tc.wantLeft, ",") {
			t.Errorf("keep %s: old certificates left = %v, want %v", tc.keepTotal, left, tc.wantLeft)
		}
	}
}
