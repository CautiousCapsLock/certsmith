package web

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/CautiousCapsLock/certsmith/internal/model"

	_ "github.com/CautiousCapsLock/certsmith/internal/dns" // register the DNS provider plugins, as main does
	_ "github.com/CautiousCapsLock/certsmith/internal/targets"
)

// A fresh install has no providers, certificates or targets. They must reach the
// UI as empty lists: a JSON null made the "Add certificate" dialog throw, so the
// button looked dead.
func TestFreshInstallListsAreEmptyArraysNotNull(t *testing.T) {
	srv, _ := newTestServer(t)
	c := setupAndLogin(t, srv)
	_, body, _ := call(t, c, "GET", srv.URL+"/api/state", nil, false, nil)
	for _, k := range []string{"dns_providers", "certificates", "targets", "events"} {
		if strings.Contains(body, `"`+k+`":null`) {
			t.Errorf("%s encoded as null", k)
		}
	}
}

// The certificate dialog creates DNS credentials inline, then needs their id.
func TestCreatingDNSCredentialsReturnsID(t *testing.T) {
	srv, _ := newTestServer(t)
	c := setupAndLogin(t, srv)
	code, body, _ := call(t, c, "POST", srv.URL+"/api/dns", map[string]any{
		"name": "Cloudflare", "kind": "cloudflare", "config": map[string]string{"api_token": "tok"}}, false, nil)
	if code != 200 {
		t.Fatalf("create = %d %s", code, body)
	}
	var out struct{ ID string }
	_ = json.Unmarshal([]byte(body), &out)
	if out.ID == "" {
		t.Fatalf("no id in response: %s", body)
	}
	// and a certificate can reference it straight away
	code, body, _ = call(t, c, "POST", srv.URL+"/api/certs", map[string]any{
		"name": "wild", "domains": []string{"*.example.com", "example.com"}, "dns_id": out.ID,
		"key_type": "rsa2048", "enabled": true, "auto_renew": true, "propagation_seconds": 90}, false, nil)
	if code != 200 {
		t.Fatalf("cert create = %d %s", code, body)
	}
	_, state, _ := call(t, c, "GET", srv.URL+"/api/state", nil, false, nil)
	if !strings.Contains(state, `"propagation_seconds":90`) {
		t.Fatalf("propagation seconds not stored: %s", state)
	}
	// the stored token is masked in the API
	if strings.Contains(state, `"tok"`) || strings.Contains(state, "enc:v1:") {
		t.Fatalf("credential leaked into /api/state")
	}
}

func TestWildcardWithoutDNSIsRejected(t *testing.T) {
	srv, _ := newTestServer(t)
	c := setupAndLogin(t, srv)
	code, body, _ := call(t, c, "POST", srv.URL+"/api/certs", map[string]any{
		"name": "w", "domains": []string{"*.example.com"}, "dns_id": "", "key_type": "rsa2048", "enabled": true}, false, nil)
	if code != 400 || !strings.Contains(body, "wildcard") {
		t.Fatalf("got %d %s, want 400 mentioning wildcard", code, body)
	}
}

func bcryptHash(pw string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
	return string(h), err
}

func TestEditingATargetsSettingsMakesTheNextDeploymentManualAgain(t *testing.T) {
	srv, ws := newTestServer(t)
	c := setupAndLogin(t, srv)
	code, body, _ := call(t, c, "POST", srv.URL+"/api/targets", map[string]any{
		"name": "files", "kind": "files", "cert_id": "", "enabled": true, "config": map[string]string{"dir": t.TempDir()}}, false, nil)
	if code != 400 { // a deployable target needs a certificate
		t.Fatalf("got %d %s", code, body)
	}
	// seed an armed target directly, as if it had deployed once
	_ = ws.St.Update(func(db *model.DB) error {
		db.Certificates = append(db.Certificates, model.Certificate{ID: "c1", Name: "c", Domains: []string{"a.example"}, Enabled: true})
		db.Targets = append(db.Targets, model.Target{ID: "t1", Name: "files", Kind: "files", CertID: "c1", Enabled: true,
			Config: map[string]string{"dir": "/tmp/a"}, DeployedSerial: "abc", DeployedAt: time.Now(), AutoDeploy: true})
		return nil
	})
	armed := func() (a bool) { ws.St.View(func(db *model.DB) { a = db.Targets[0].AutoDeploy }); return }

	// renaming it changes nothing about where it deploys
	if code, _, _ := call(t, c, "PUT", srv.URL+"/api/targets/t1", map[string]any{
		"name": "renamed", "kind": "files", "cert_id": "c1", "enabled": true, "config": map[string]string{"dir": "/tmp/a"}}, false, nil); code != 200 {
		t.Fatal("rename failed")
	}
	if !armed() {
		t.Fatal("a rename must not disarm automatic deployment")
	}
	// pointing it somewhere else does
	if code, _, _ := call(t, c, "PUT", srv.URL+"/api/targets/t1", map[string]any{
		"name": "renamed", "kind": "files", "cert_id": "c1", "enabled": true, "config": map[string]string{"dir": "/tmp/elsewhere"}}, false, nil); code != 200 {
		t.Fatal("edit failed")
	}
	if armed() {
		t.Fatal("changing where it deploys must require a deliberate first deployment again")
	}
}

func TestPauseAndResumeATarget(t *testing.T) {
	srv, ws := newTestServer(t)
	c := setupAndLogin(t, srv)
	_ = ws.St.Update(func(db *model.DB) error {
		db.Certificates = append(db.Certificates, model.Certificate{ID: "c1", Name: "c", Domains: []string{"a.example"}, Enabled: true})
		db.Targets = append(db.Targets,
			model.Target{ID: "never", Name: "never deployed", Kind: "files", CertID: "c1", Enabled: true},
			model.Target{ID: "armed", Name: "deployed", Kind: "files", CertID: "c1", Enabled: true, AutoDeploy: true, DeployedSerial: "abc"})
		return nil
	})
	paused := func(id string) (p bool) {
		ws.St.View(func(db *model.DB) {
			for _, t := range db.Targets {
				if t.ID == id {
					p = t.Paused
				}
			}
		})
		return
	}
	if code, body, _ := call(t, c, "POST", srv.URL+"/api/targets/never/pause", nil, false, nil); code != 400 || !strings.Contains(body, "not been deployed") {
		t.Fatalf("a target never deployed to has nothing to pause: %d %s", code, body)
	}
	if code, _, _ := call(t, c, "POST", srv.URL+"/api/targets/armed/pause", nil, false, nil); code != 200 || !paused("armed") {
		t.Fatal("pausing a deployed target must work")
	}
	if code, _, _ := call(t, c, "POST", srv.URL+"/api/targets/armed/resume", nil, false, nil); code != 200 || paused("armed") {
		t.Fatal("resuming must work")
	}
	if code, _, _ := call(t, c, "POST", srv.URL+"/api/targets/ghost/pause", nil, false, nil); code != 400 {
		t.Fatalf("an unknown target: %d", code)
	}
}

func TestWebInterfaceTargetIsHiddenFromTheGeneralListAndTheServerNamesItself(t *testing.T) {
	srv, _ := newTestServer(t)
	c := setupAndLogin(t, srv)
	_, body, _ := call(t, c, "GET", srv.URL+"/api/schema", nil, false, nil)
	var sc struct {
		Hostname string
		Targets  []struct {
			Kind   string
			Hidden bool
		}
	}
	if err := json.Unmarshal([]byte(body), &sc); err != nil {
		t.Fatal(err)
	}
	if sc.Hostname == "" {
		t.Fatal("the schema must carry the server's hostname: it names the \"(This server)\" target")
	}
	hidden, visible := map[string]bool{}, 0
	for _, d := range sc.Targets {
		hidden[d.Kind] = d.Hidden
		if !d.Hidden {
			visible++
		}
	}
	if !hidden["selfui"] {
		t.Fatal("the web-interface target must not be offered in the general list of new targets")
	}
	if hidden["fortigate"] || hidden["pve"] || hidden["webhook"] || visible < 5 {
		t.Fatalf("the ordinary targets must stay visible: hidden=%v visible=%d", hidden, visible)
	}
}

func TestEveryCertificateNeedsDNSCredentialsWildcardOrNot(t *testing.T) {
	srv, _ := newTestServer(t) // production directory by default
	c := setupAndLogin(t, srv)
	for _, domains := range [][]string{{"fw.example.com"}, {"*.example.com"}, {"example.com", "*.example.com"}} {
		code, body, _ := call(t, c, "POST", srv.URL+"/api/certs", map[string]any{
			"name": "x", "domains": domains, "dns_id": "", "key_type": "rsa2048", "enabled": false}, false, nil)
		if code != 400 || !strings.Contains(body, "certificate provider") {
			t.Errorf("%v without a certificate provider must be refused with that reason, got %d %s", domains, code, body)
		}
	}
	_, schema, _ := call(t, c, "GET", srv.URL+"/api/schema", nil, false, nil)
	if strings.Contains(schema, "http01") {
		t.Error("HTTP-01 must not be offered anywhere")
	}
}

func TestTheBuiltInTestCANeedsNoCredentials(t *testing.T) {
	srv, ws := newTestServer(t)
	c := setupAndLogin(t, srv)
	_ = ws.St.Update(func(db *model.DB) error { db.Settings.ACMEDirectory = model.DirSelfSigned; return nil })
	code, body, _ := call(t, c, "POST", srv.URL+"/api/certs", map[string]any{
		"name": "demo", "domains": []string{"fw.example.com"}, "dns_id": "", "key_type": "rsa2048", "enabled": false}, false, nil)
	if code != 200 {
		t.Fatalf("the test CA validates nothing, so credentials are optional there: %d %s", code, body)
	}
}

func TestSettingsNormaliseAndValidateDNSResolvers(t *testing.T) {
	srv, ws := newTestServer(t)
	c := setupAndLogin(t, srv)
	put := func(resolvers []string, check string, wait int) (int, string) {
		st := ws.St.Snapshot().Settings
		st.ACMEEmail = "a@example.com"
		st.DNSResolvers, st.DNSCheck, st.DNSWaitSeconds = resolvers, check, wait
		code, body, _ := call(t, c, "PUT", srv.URL+"/api/settings", st, false, nil)
		return code, body
	}
	if code, body := put([]string{"1.1.1.1", " 8.8.8.8:5353 ", "2606:4700:4700::1111", "[2001:4860:4860::8888]:53", ""}, "auto", 25); code != 200 {
		t.Fatalf("valid resolvers rejected: %d %s", code, body)
	}
	got := ws.St.Snapshot().Settings.DNSResolvers
	want := []string{"1.1.1.1:53", "8.8.8.8:5353", "[2606:4700:4700::1111]:53", "[2001:4860:4860::8888]:53"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("resolvers stored as %v, want %v (53 when no port is given)", got, want)
	}
	for _, bad := range []string{"1.1.1.1:99999", "1.1.1.1:abc", "not a host!!", "1.1.1.1:0"} {
		if code, _ := put([]string{bad}, "auto", 25); code != 400 {
			t.Errorf("resolver %q should be refused, got %d", bad, code)
		}
	}
	if code, _ := put(nil, "sometimes", 25); code != 400 {
		t.Error("an unknown DNS check mode must be refused")
	}
	put(nil, "wait", 1) // clamped, not refused
	if got := ws.St.Snapshot().Settings.DNSWaitSeconds; got != 5 {
		t.Errorf("wait seconds clamped to %d, want the 5 s minimum", got)
	}
}

// With a DNS provider, a plain (non-wildcard) host name is fine, and does not depend on port 80.
func TestAPlainHostNameWithDNSCredentialsIsAccepted(t *testing.T) {
	srv, _ := newTestServer(t)
	c := setupAndLogin(t, srv)
	code, body, _ := call(t, c, "POST", srv.URL+"/api/dns", map[string]any{"name": "CF", "kind": "cloudflare", "config": map[string]string{"api_token": "t"}}, false, nil)
	if code != 200 {
		t.Fatalf("dns: %d %s", code, body)
	}
	var made struct{ ID string }
	_ = json.Unmarshal([]byte(body), &made)
	code, body, _ = call(t, c, "POST", srv.URL+"/api/certs", map[string]any{
		"name": "plain", "domains": []string{"fw.example.com"}, "dns_id": made.ID, "key_type": "rsa2048", "enabled": false}, false, nil)
	if code != 200 {
		t.Fatalf("a plain host name validated by DNS must be accepted whatever port 80 does: %d %s", code, body)
	}
}
