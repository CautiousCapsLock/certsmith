package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/CautiousCapsLock/certsmith/internal/model"
)

type stateView struct {
	DB struct {
		Events   []model.Event      `json:"events"`
		Audit    []model.AuditEntry `json:"audit"`
		Settings model.Settings     `json:"settings"`
	} `json:"db"`
}

func getState(t *testing.T, c *http.Client, url string) stateView {
	t.Helper()
	code, body, _ := call(t, c, "GET", url+"/api/state", nil, false, nil)
	if code != 200 {
		t.Fatalf("state: %d %s", code, body)
	}
	var s stateView
	if err := json.Unmarshal([]byte(body), &s); err != nil {
		t.Fatal(err)
	}
	return s
}

func hasAudit(a []model.AuditEntry, action, subject string) *model.AuditEntry {
	for i := range a {
		if a[i].Action == action && (subject == "" || a[i].Subject == subject) {
			return &a[i]
		}
	}
	return nil
}

func TestAdministrativeActionsGoToTheAuditLogAndNotTheCertificateEvents(t *testing.T) {
	ts, _ := newTestServer(t)
	c := setupAndLogin(t, ts)

	// a failed sign-in, a user, a provider with a secret, a changed setting
	loginAs(t, ts, "admin", "definitely not the password")
	call(t, c, "POST", ts.URL+"/api/users", map[string]any{"username": "bob", "password": "a long enough password 1", "confirm": pw1}, false, nil)
	call(t, c, "POST", ts.URL+"/api/dns", map[string]any{"name": "CF lab", "kind": "cloudflare",
		"config": map[string]string{"api_token": "SUPER-SECRET-TOKEN"}, "authority": "letsencrypt"}, false, nil)
	st := getState(t, c, ts.URL)
	set := st.DB.Settings
	set.ProbeMinutes = 30
	if code, body, _ := call(t, c, "PUT", ts.URL+"/api/settings", set, false, nil); code != 200 {
		t.Fatalf("settings: %d %s", code, body)
	}

	st = getState(t, c, ts.URL)
	a := st.DB.Audit
	for _, want := range []struct{ action, subject string }{
		{"user.setup", "admin"}, {"signin.failed", `"admin"`}, {"user.create", "bob"},
		{"provider.create", "CF lab"}, {"settings.update", ""},
	} {
		if hasAudit(a, want.action, want.subject) == nil {
			t.Errorf("audit log has no %s %q: %+v", want.action, want.subject, a)
		}
	}
	if e := hasAudit(a, "user.create", "bob"); e != nil && e.User != "admin" {
		t.Errorf("who created the user: %q", e.User)
	}
	if e := hasAudit(a, "settings.update", ""); e != nil && !strings.Contains(e.Detail, "probe_minutes") {
		t.Errorf("settings change should name the field that changed: %q", e.Detail)
	}
	for _, e := range a {
		if e.IP == "" && e.Action != "event" {
			t.Errorf("entry without an address: %+v", e)
		}
	}

	// secrets and passwords are never written
	raw, _ := json.Marshal(a)
	for _, secret := range []string{"SUPER-SECRET-TOKEN", "definitely not the password", "a long enough password 1", pw1} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("the audit log contains a secret: %s", secret)
		}
	}
	// and none of it is in the certificate events
	for _, e := range st.DB.Events {
		if e.Subject == "security" || strings.Contains(e.Message, "bob") {
			t.Errorf("administrative action in the certificate events: %+v", e)
		}
	}
}

func TestFailedRequestsAreNotAudited(t *testing.T) {
	ts, _ := newTestServer(t)
	c := setupAndLogin(t, ts)
	before := len(getState(t, c, ts.URL).DB.Audit)
	call(t, c, "POST", ts.URL+"/api/dns", map[string]any{"name": "", "kind": "cloudflare", "config": map[string]string{}}, false, nil) // refused: no name
	if got := len(getState(t, c, ts.URL).DB.Audit); got != before {
		t.Fatalf("a refused request left %d audit entries", got-before)
	}
}

func TestTheForwardedAddressIsShownButOnlyWhenItLooksLikeOne(t *testing.T) {
	ts, _ := newTestServer(t)
	c := setupAndLogin(t, ts)
	call(t, c, "POST", ts.URL+"/api/dns", map[string]any{"name": "P1", "kind": "cloudflare", "config": map[string]string{"api_token": "x"}}, false,
		func(r *http.Request) { r.Header.Set("X-Forwarded-For", "203.0.113.9, 10.0.0.1") })
	call(t, c, "POST", ts.URL+"/api/dns", map[string]any{"name": "P2", "kind": "cloudflare", "config": map[string]string{"api_token": "x"}}, false,
		func(r *http.Request) { r.Header.Set("X-Forwarded-For", "<script>alert(1)</script>") })
	a := getState(t, c, ts.URL).DB.Audit
	p1, p2 := hasAudit(a, "provider.create", "P1"), hasAudit(a, "provider.create", "P2")
	if p1 == nil || !strings.HasPrefix(p1.IP, "203.0.113.9 (via ") {
		t.Fatalf("P1: %+v", p1)
	}
	if p2 == nil || strings.Contains(p2.IP, "script") {
		t.Fatalf("a forged header must not be shown: %+v", p2)
	}
}

func TestAlertRoutingIsValidatedStoredAndTheTypesAreOffered(t *testing.T) {
	ts, _ := newTestServer(t)
	c := setupAndLogin(t, ts)
	_, schema, _ := call(t, c, "GET", ts.URL+"/api/schema", nil, false, nil)
	var sc struct {
		Types []struct{ ID, Group, Label string } `json:"alert_types"`
	}
	_ = json.Unmarshal([]byte(schema), &sc)
	have := map[string]bool{}
	groups := map[string]bool{}
	for _, t := range sc.Types {
		have[t.ID] = true
		groups[t.Group] = true
	}
	for _, id := range []string{"cert.issued", "cert.failed", "cert.expiring", "deploy.failed", "endpoint.down", "admin.user_created", "admin.settings_changed"} {
		if !have[id] {
			t.Errorf("alert type %s is not offered", id)
		}
	}
	if !groups["Certificates"] || !groups["Devices"] || !groups["Administration"] {
		t.Errorf("groups = %v", groups)
	}

	set := getState(t, c, ts.URL).DB.Settings
	set.AlertRouting = &model.AlertRouting{Email: []string{"cert.failed", "nonsense"}}
	if code, body, _ := call(t, c, "PUT", ts.URL+"/api/settings", set, false, nil); code != 400 || !strings.Contains(body, "unknown alert type") {
		t.Fatalf("an unknown type must be refused: %d %s", code, body)
	}
	set.AlertRouting = &model.AlertRouting{Email: []string{"cert.failed", "cert.failed", "admin.user_created"}, Webhook: []string{"cert.issued"}}
	if code, body, _ := call(t, c, "PUT", ts.URL+"/api/settings", set, false, nil); code != 200 {
		t.Fatalf("%d %s", code, body)
	}
	r := getState(t, c, ts.URL).DB.Settings.AlertRouting
	if r == nil || len(r.Email) != 2 || len(r.Webhook) != 1 || r.Webhook[0] != "cert.issued" {
		t.Fatalf("stored routing = %+v", r)
	}
}
