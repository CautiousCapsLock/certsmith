package update

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
		ok   bool
	}{
		{"v0.12.2", "0.12.1", 1, true},
		{"0.12.1", "0.12.1", 0, true},
		{"v0.12.0", "0.12.1", -1, true},
		{"1.0.0", "0.99.99", 1, true},
		{"0.10.0", "0.9.0", 1, true}, // numeric, not text, comparison
		// builds that carry their commit or a test label
		{"v0.12.1", "0.12.1-dev+56b8cb1", 1, true},    // the release is newer than its own dev build
		{"0.12.1-test+c204363", "0.12.1", -1, true},   // a pre-release is older than the release
		{"0.12.1-dev+aaa", "0.12.1-dev+bbb", 0, true}, // build metadata is ignored
		{"0.12.2", "0.12.1-dev+56b8cb1", 1, true},
		{"0.12.1-rc.2", "0.12.1-rc.10", -1, true},
		{"0.12.1-rc.1", "0.12.1-rc.1.1", -1, true},
		{"0.12.1-1", "0.12.1-alpha", -1, true}, // numeric identifiers rank lower
		{"v0.12.2", "dev", 0, false},
		{"v0.12", "0.12.1", 0, false},
		{"", "0.12.1", 0, false},
	}
	for _, c := range cases {
		got, ok := Compare(c.a, c.b)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("Compare(%q, %q) = %d, %v; want %d, %v", c.a, c.b, got, ok, c.want, c.ok)
		}
	}
}

func api(t *testing.T, status int, body string, seen *http.Header) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if seen != nil {
			*seen = r.Header.Clone()
		}
		if r.URL.Path != "/repos/owner/name/releases/latest" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

func checker(srv *httptest.Server, current string) *Checker {
	c := New("owner/name", current)
	c.APIBase = srv.URL
	return c
}

func TestCheckFindsANewerRelease(t *testing.T) {
	var h http.Header
	srv := api(t, 200, `{"tag_name":"v0.13.0","html_url":"https://github.com/owner/name/releases/tag/v0.13.0","published_at":"2026-10-20T10:00:00Z"}`, &h)
	defer srv.Close()
	got := checker(srv, "0.12.1+abc").Check(context.Background())
	if got.Error != "" || !got.Available || got.Latest != "v0.13.0" {
		t.Fatalf("unexpected result: %+v", got)
	}
	if got.URL != "https://github.com/owner/name/releases/tag/v0.13.0" || got.Published.IsZero() || got.CheckedAt.IsZero() {
		t.Errorf("details missing: %+v", got)
	}
	if ua := h.Get("User-Agent"); ua != "certsmith/0.12.1+abc" {
		t.Errorf("User-Agent = %q; nothing but the version may identify the installation", ua)
	}
	for _, name := range []string{"Authorization", "Cookie"} {
		if h.Get(name) != "" {
			t.Errorf("the request must not carry %s", name)
		}
	}
}

func TestCheckUpToDateAndNewerThanPublished(t *testing.T) {
	srv := api(t, 200, `{"tag_name":"v0.12.1","html_url":"https://github.com/owner/name/releases/tag/v0.12.1"}`, nil)
	defer srv.Close()
	if got := checker(srv, "0.12.1").Check(context.Background()); got.Available || got.Error != "" {
		t.Errorf("same version: %+v", got)
	}
	if got := checker(srv, "0.13.0-dev+x").Check(context.Background()); got.Available {
		t.Errorf("a build ahead of the latest release must not claim an update: %+v", got)
	}
	if got := checker(srv, "dev").Check(context.Background()); got.Available || got.Latest != "v0.12.1" {
		t.Errorf("a development build reports the latest but never claims an update: %+v", got)
	}
}

func TestCheckFailuresAreReportedPlainly(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"private or none", 404, `{"message":"Not Found"}`, "no published release"},
		{"rate limited", 403, `{"message":"rate limit exceeded"}`, "limiting requests"},
		{"server error", 500, `oops`, "HTTP 500"},
		{"not json", 200, `<html>`, "could not be read"},
		{"draft", 200, `{"tag_name":"v9.9.9","draft":true}`, "not a stable release"},
		{"prerelease", 200, `{"tag_name":"v9.9.9-rc1","prerelease":true}`, "not a stable release"},
		{"odd tag", 200, `{"tag_name":"latest-and-greatest"}`, "unexpected version"},
		{"script in tag", 200, `{"tag_name":"<script>alert(1)</script>"}`, "unexpected version"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := api(t, c.status, c.body, nil)
			defer srv.Close()
			got := checker(srv, "0.12.1").Check(context.Background())
			if !strings.Contains(got.Error, c.want) || got.Available {
				t.Errorf("got %+v, want an error containing %q", got, c.want)
			}
		})
	}
}

func TestAFailedCheckKeepsTheLastGoodAnswer(t *testing.T) {
	ok := api(t, 200, `{"tag_name":"v0.13.0","html_url":"https://github.com/owner/name/releases/tag/v0.13.0"}`, nil)
	c := checker(ok, "0.12.1")
	if got := c.Check(context.Background()); !got.Available {
		t.Fatalf("setup: %+v", got)
	}
	ok.Close()
	bad := api(t, 500, `oops`, nil)
	defer bad.Close()
	c.APIBase = bad.URL
	got := c.Check(context.Background())
	if got.Error == "" || got.Latest != "v0.13.0" || !got.Available {
		t.Errorf("a failure must report the error and keep what was known: %+v", got)
	}
	if last := c.Last(); last.Latest != "v0.13.0" || last.Error == "" {
		t.Errorf("Last() = %+v", last)
	}
}

func TestOnlyPlainHTTPSLinksAreKept(t *testing.T) {
	for _, u := range []string{"javascript:alert(1)", "http://github.com/x", `https://x/"onmouseover="a`, "https://x/a b", ""} {
		srv := api(t, 200, `{"tag_name":"v0.13.0","html_url":`+jsonString(u)+`}`, nil)
		got := checker(srv, "0.12.1").Check(context.Background())
		srv.Close()
		if got.URL != "" || !got.Available {
			t.Errorf("url %q: kept %q (available=%v)", u, got.URL, got.Available)
		}
	}
}

func jsonString(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return `"` + r.Replace(s) + `"`
}

func TestNewRejectsAnInvalidRepo(t *testing.T) {
	for _, r := range []string{"", "no-slash", "a/b/c", "a b/c", "a/b?x=1", "../etc/passwd"} {
		if got := New(r, "1.0.0").Repo; got != DefaultRepo {
			t.Errorf("repo %q accepted as %q", r, got)
		}
	}
	if got := New("someone/else", "1.0.0").Repo; got != "someone/else" {
		t.Errorf("a valid repo was replaced: %q", got)
	}
}

func TestDue(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		last Info
		want bool
	}{
		{"never checked", Info{}, true},
		{"checked an hour ago", Info{CheckedAt: now.Add(-time.Hour)}, false},
		{"checked a day ago", Info{CheckedAt: now.Add(-24 * time.Hour)}, true},
		{"failed ten minutes ago", Info{CheckedAt: now.Add(-10 * time.Minute), Error: "x"}, false},
		{"failed an hour ago", Info{CheckedAt: now.Add(-time.Hour), Error: "x"}, true},
	}
	for _, c := range cases {
		if got := Due(c.last, now); got != c.want {
			t.Errorf("%s: Due = %v, want %v", c.name, got, c.want)
		}
	}
}

// apiList serves both the latest release and the list of releases, and counts requests to the list.
func apiList(t *testing.T, latest, list string, listStatus int, listCalls *int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/owner/name/releases/latest":
			_, _ = w.Write([]byte(latest))
		case "/repos/owner/name/releases":
			if listCalls != nil {
				*listCalls++
			}
			w.WriteHeader(listStatus)
			_, _ = w.Write([]byte(list))
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestAnUpgradeBringsTheNotesOfEveryNewerRelease(t *testing.T) {
	latest := `{"tag_name":"v0.14.0","html_url":"https://github.com/owner/name/releases/tag/v0.14.0","body":"- C"}`
	list := `[
	  {"tag_name":"v0.15.0","draft":true,"body":"- never published"},
	  {"tag_name":"v0.14.0","html_url":"https://github.com/owner/name/releases/tag/v0.14.0","published_at":"2026-10-20T10:00:00Z","body":"- C"},
	  {"tag_name":"v0.13.1-rc1","prerelease":true,"body":"- candidate"},
	  {"tag_name":"v0.13.0","html_url":"http://insecure.example/x","body":"## New\n- B"},
	  {"tag_name":"v0.12.1","body":"- A, the running version"},
	  {"tag_name":"v0.12.0","body":"- older"}]`
	srv := apiList(t, latest, list, 200, nil)
	defer srv.Close()
	c := checker(srv, "0.12.1+abc")
	if got := c.Check(context.Background()); !got.Available {
		t.Fatalf("an update must be available: %+v", got)
	}
	up := c.Upcoming()
	if len(up) != 2 || up[0].Version != "v0.14.0" || up[1].Version != "v0.13.0" {
		t.Fatalf("upcoming = %+v, want v0.14.0 then v0.13.0 only", up)
	}
	if up[0].Notes != "- C" || up[0].URL == "" || up[0].Published.IsZero() {
		t.Errorf("details missing: %+v", up[0])
	}
	if up[1].URL != "" {
		t.Errorf("a link that is not https must be dropped: %q", up[1].URL)
	}
}

func TestNotesFallBackToTheLatestReleaseAndAreNotAskedForWhenUpToDate(t *testing.T) {
	latest := `{"tag_name":"v0.14.0","body":"- C"}`
	srv := apiList(t, latest, `oops`, 500, nil)
	defer srv.Close()
	c := checker(srv, "0.12.1")
	c.Check(context.Background())
	if up := c.Upcoming(); len(up) != 1 || up[0].Version != "v0.14.0" || up[0].Notes != "- C" {
		t.Errorf("with the list unavailable the newest release's own notes are used: %+v", up)
	}
	calls := 0
	srv2 := apiList(t, latest, `[]`, 200, &calls)
	defer srv2.Close()
	c2 := checker(srv2, "0.14.0")
	c2.Check(context.Background())
	if calls != 0 || len(c2.Upcoming()) != 0 {
		t.Errorf("up to date: the list must not be requested (%d calls) and there is nothing upcoming: %+v", calls, c2.Upcoming())
	}
}

func TestLongNotesAreClippedAndAFailedCheckKeepsTheLastNotes(t *testing.T) {
	long := strings.Repeat("é", maxNote) // two bytes each: the cut must not split one
	srv := apiList(t, `{"tag_name":"v0.14.0","body":"`+long+`"}`, `[]`, 200, nil)
	c := checker(srv, "0.12.1")
	c.Check(context.Background())
	up := c.Upcoming()
	if len(up) != 1 || len(up[0].Notes) > maxNote+8 || !strings.HasSuffix(up[0].Notes, "…") {
		t.Fatalf("notes must be clipped: %d bytes", len(up[0].Notes))
	}
	srv.Close() // the next check cannot reach the host
	if got := c.Check(context.Background()); got.Error == "" {
		t.Fatal("expected the check to fail")
	}
	if len(c.Upcoming()) != 1 {
		t.Error("a failed check must keep the notes of the last good one")
	}
}
