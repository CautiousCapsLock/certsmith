package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/CautiousCapsLock/certsmith/internal/model"
	"github.com/CautiousCapsLock/certsmith/internal/update"
)

// releaseHost is a stand-in for the release API that counts how often it is asked.
func releaseHost(t *testing.T, tag string, hits *int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/releases") { // the list of releases, asked for after an update is found
			http.NotFound(w, r) // the notes then come from the latest release itself
			return
		}
		atomic.AddInt32(hits, 1)
		_, _ = w.Write([]byte(`{"tag_name":"` + tag + `","html_url":"https://github.com/owner/name/releases/tag/` + tag + `"}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func withUpdates(t *testing.T, ws *Server, version, latest string, hits *int32) {
	t.Helper()
	host := releaseHost(t, latest, hits)
	c := update.New("owner/name", version)
	c.APIBase = host.URL
	ws.SetUpdates(version, c)
}

type versionStateJSON struct {
	Version string `json:"version"`
	Update  *struct {
		Current   string `json:"current"`
		Latest    string `json:"latest"`
		Available bool   `json:"available"`
		URL       string `json:"url"`
		Repo      string `json:"repo"`
		Error     string `json:"error"`
	} `json:"update"`
	DB struct {
		Settings struct {
			UpdateCheckDisabled bool `json:"update_check_disabled"`
		} `json:"settings"`
	} `json:"db"`
}

func versionState(t *testing.T, c *http.Client, base string) versionStateJSON {
	t.Helper()
	code, body, _ := call(t, c, "GET", base+"/api/state", nil, false, nil)
	if code != 200 {
		t.Fatalf("state: %d %s", code, body)
	}
	var s versionStateJSON
	if err := json.Unmarshal([]byte(body), &s); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestStateReportsTheVersionAndWhatIsKnownAboutUpdates(t *testing.T) {
	srv, ws := newTestServer(t)
	var hits int32
	withUpdates(t, ws, "0.12.1-dev+abc1234", "v0.13.0", &hits)
	c := setupAndLogin(t, srv)

	s := versionState(t, c, srv.URL)
	if s.Version != "0.12.1-dev+abc1234" {
		t.Errorf("version = %q", s.Version)
	}
	if s.Update == nil || s.Update.Latest != "" || s.Update.Available {
		t.Errorf("nothing has been checked yet, so nothing may be claimed: %+v", s.Update)
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Error("reading the state must never contact the release host")
	}

	code, body, _ := call(t, c, "POST", srv.URL+"/api/update/check", nil, false, nil)
	if code != 200 {
		t.Fatalf("check: %d %s", code, body)
	}
	s = versionState(t, c, srv.URL)
	if s.Update == nil || !s.Update.Available || s.Update.Latest != "v0.13.0" || s.Update.Repo != "owner/name" {
		t.Errorf("after a check: %+v", s.Update)
	}
	if !strings.HasPrefix(s.Update.URL, "https://") {
		t.Errorf("release page = %q", s.Update.URL)
	}
}

func TestCheckNowIsRateLimitedAndNeedsASession(t *testing.T) {
	srv, ws := newTestServer(t)
	var hits int32
	withUpdates(t, ws, "0.12.1", "v0.12.1", &hits)

	// without a session
	anon := newClient()
	if code, _, _ := call(t, anon, "POST", srv.URL+"/api/update/check", nil, false, nil); code == 200 {
		t.Fatal("an unauthenticated visitor must not be able to trigger a check")
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Fatal("the release host must not be contacted for an unauthenticated request")
	}

	c := setupAndLogin(t, srv)
	for i := 0; i < 5; i++ {
		if code, body, _ := call(t, c, "POST", srv.URL+"/api/update/check", nil, false, nil); code != 200 {
			t.Fatalf("check %d: %d %s", i, code, body)
		}
	}
	if n := atomic.LoadInt32(&hits); n != 1 {
		t.Errorf("five quick clicks reached the release host %d times, want 1", n)
	}
}

func TestAutomaticCheckHonoursTheSwitchAndTheSchedule(t *testing.T) {
	srv, ws := newTestServer(t)
	var hits int32
	withUpdates(t, ws, "0.12.1", "v0.13.0", &hits)
	c := setupAndLogin(t, srv)
	ctx := context.Background()

	ws.autoCheckOnce(ctx)
	if n := atomic.LoadInt32(&hits); n != 1 {
		t.Fatalf("first automatic check: %d requests, want 1", n)
	}
	ws.autoCheckOnce(ctx)
	if n := atomic.LoadInt32(&hits); n != 1 {
		t.Errorf("a second pass within a day asked again (%d requests)", n)
	}

	// switch it off in Settings: the saved value round-trips and nothing is asked
	var in map[string]any
	code, body, _ := call(t, c, "GET", srv.URL+"/api/state", nil, false, nil)
	if code != 200 {
		t.Fatal(body)
	}
	var st struct {
		DB map[string]any `json:"db"`
	}
	_ = json.Unmarshal([]byte(body), &st)
	in, _ = st.DB["settings"].(map[string]any)
	in["update_check_disabled"] = true
	if code, body, _ := call(t, c, "PUT", srv.URL+"/api/settings", in, false, nil); code != 200 {
		t.Fatalf("save settings: %d %s", code, body)
	}
	if !versionState(t, c, srv.URL).DB.Settings.UpdateCheckDisabled {
		t.Fatal("the switch was not saved")
	}
	fresh := update.New("owner/name", "0.12.1")
	fresh.APIBase = releaseHost(t, "v0.14.0", &hits).URL
	ws.SetUpdates("0.12.1", fresh)
	before := atomic.LoadInt32(&hits)
	ws.autoCheckOnce(ctx)
	if atomic.LoadInt32(&hits) != before {
		t.Error("the automatic check ran although it is switched off")
	}
	// ... but "Check now" still works, because the person asked
	if code, _, _ := call(t, c, "POST", srv.URL+"/api/update/check", nil, false, nil); code != 200 || atomic.LoadInt32(&hits) != before+1 {
		t.Errorf("an explicit check must work while the automatic one is off (code %d, hits %d)", code, atomic.LoadInt32(&hits))
	}
}

func TestStateWorksWithoutAnUpdateChecker(t *testing.T) {
	srv, _ := newTestServer(t) // SetUpdates never called
	c := setupAndLogin(t, srv)
	s := versionState(t, c, srv.URL)
	if s.Update != nil {
		t.Errorf("no checker, so no update block: %+v", s.Update)
	}
	if code, _, _ := call(t, c, "POST", srv.URL+"/api/update/check", nil, false, nil); code != http.StatusServiceUnavailable {
		t.Errorf("check without a checker = %d, want 503", code)
	}
}

// ---- update checks are written to the audit log ----

func auditActions(ws *Server, action string) []model.AuditEntry {
	var out []model.AuditEntry
	ws.St.View(func(db *model.DB) {
		for _, a := range db.Audit {
			if a.Action == action {
				out = append(out, a)
			}
		}
	})
	return out
}

func TestACheckNowIsWrittenToTheAuditLogWithTheUserAndTheOutcome(t *testing.T) {
	srv, ws := newTestServer(t)
	var hits int32
	withUpdates(t, ws, "0.12.1", "v0.13.0", &hits)
	c := setupAndLogin(t, srv)
	for i := 0; i < 3; i++ { // quick repeats are answered from memory and are not new checks
		if code, body, _ := call(t, c, "POST", srv.URL+"/api/update/check", nil, false, nil); code != 200 {
			t.Fatalf("check: %d %s", code, body)
		}
	}
	got := auditActions(ws, "update.check")
	if len(got) != 1 {
		t.Fatalf("audit entries = %d, want exactly one for the one real check: %+v", len(got), got)
	}
	e := got[0]
	if e.User == "" || e.Subject != "software" || !strings.Contains(e.Detail, "0.13.0 is available") || strings.HasPrefix(e.Detail, "automatic") {
		t.Errorf("entry = %+v", e)
	}
}

func TestAnAutomaticCheckIsWrittenToTheAuditLogWithNoUser(t *testing.T) {
	_, ws := newTestServer(t)
	var hits int32
	withUpdates(t, ws, "0.12.1", "v0.12.1", &hits)
	ws.autoCheckOnce(context.Background())
	got := auditActions(ws, "update.check")
	if len(got) != 1 || got[0].User != "" || !strings.HasPrefix(got[0].Detail, "automatic: up to date") {
		t.Fatalf("entries = %+v", got)
	}
}

func TestAnAutomaticCheckThatKeepsFailingIsNotRecordedEveryHour(t *testing.T) {
	_, ws := newTestServer(t)
	bad := update.Info{Error: "no published release was found"}
	ws.auditAutoCheck(bad)
	ws.auditAutoCheck(bad) // the hourly retry
	ws.auditAutoCheck(bad)
	if n := len(auditActions(ws, "update.check")); n != 1 {
		t.Fatalf("the same failure was recorded %d times, want once", n)
	}
	ws.auditAutoCheck(update.Info{Error: "the release host did not answer"}) // a different problem
	if n := len(auditActions(ws, "update.check")); n != 2 {
		t.Errorf("a different failure must be recorded: %d entries", n)
	}
	ws.autoAuditAt = time.Now().Add(-25 * time.Hour) // a day later the same failure is worth saying again
	ws.auditAutoCheck(update.Info{Error: "the release host did not answer"})
	if n := len(auditActions(ws, "update.check")); n != 3 {
		t.Errorf("after a day the failure must be recorded again: %d entries", n)
	}
	ws.auditAutoCheck(update.Info{Current: "0.12.1", Latest: "v0.12.1"}) // recovery is recorded, and resets the memory
	if n := len(auditActions(ws, "update.check")); n != 4 {
		t.Errorf("a success must be recorded: %d entries", n)
	}
}
