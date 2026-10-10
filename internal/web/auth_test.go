package web

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CautiousCapsLock/certsmith/internal/engine"
	"github.com/CautiousCapsLock/certsmith/internal/model"
	"github.com/CautiousCapsLock/certsmith/internal/secret"
	"github.com/CautiousCapsLock/certsmith/internal/store"
)

func newTestServer(t *testing.T) (*httptest.Server, *Server) {
	t.Helper()
	dir := t.TempDir()
	box, err := secret.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ws, err := New(st, box, engine.New(st, box, dir, log), dir, log)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(ws.Handler())
	t.Cleanup(srv.Close)
	return srv, ws
}

func newClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar}
}

// call sends a request with the anti-CSRF header (unless noCSRF) and returns status + body.
func call(t *testing.T, c *http.Client, method, url string, body any, noCSRF bool, mod func(*http.Request)) (int, string, http.Header) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, url, rdr)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if !noCSRF {
		req.Header.Set("X-Certsmith", "1")
	}
	if mod != nil {
		mod(req)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header
}

func sessionState(t *testing.T, c *http.Client, base string) string {
	_, body, _ := call(t, c, "GET", base+"/api/session", nil, false, nil)
	var s struct{ State string }
	_ = json.Unmarshal([]byte(body), &s)
	return s.State
}

const (
	pw1 = "correct horse battery"
	pw2 = "another long password"
)

type cred map[string]string

func creds(user, pw string) cred { return cred{"username": user, "password": pw} }

func TestFirstRunSetupThenLogin(t *testing.T) {
	srv, _ := newTestServer(t)
	c := newClient()

	if got := sessionState(t, c, srv.URL); got != "setup" {
		t.Fatalf("fresh install state = %q, want setup", got)
	}
	if code, _, _ := call(t, c, "GET", srv.URL+"/api/state", nil, false, nil); code != 403 {
		t.Fatalf("API before setup = %d, want 403", code)
	}
	if code, _, _ := call(t, c, "POST", srv.URL+"/api/setup", creds("admin", "short"), false, nil); code != 400 {
		t.Fatalf("short password = %d, want 400", code)
	}
	if code, _, _ := call(t, c, "POST", srv.URL+"/api/setup", creds("a b!", pw1), false, nil); code != 400 {
		t.Fatalf("bad username = %d, want 400", code)
	}
	if code, body, _ := call(t, c, "POST", srv.URL+"/api/setup", creds("Matt", pw1), false, nil); code != 200 {
		t.Fatalf("setup = %d %s", code, body)
	}
	if got := sessionState(t, c, srv.URL); got != "ok" {
		t.Fatalf("after setup state = %q, want ok (setup should sign in)", got)
	}
	if code, _, _ := call(t, c, "GET", srv.URL+"/api/state", nil, false, nil); code != 200 {
		t.Fatalf("API after setup = %d", code)
	}

	// setup is one-shot
	other := newClient()
	if code, _, _ := call(t, other, "POST", srv.URL+"/api/setup", creds("attacker", "attacker password 123"), false, nil); code != 409 {
		t.Fatalf("second setup = %d, want 409", code)
	}
	if got := sessionState(t, other, srv.URL); got != "login" {
		t.Fatalf("other browser state = %q, want login", got)
	}
}

// setupAndLogin creates the first user "admin" and returns a signed-in client.
func setupAndLogin(t *testing.T, srv *httptest.Server) *http.Client {
	t.Helper()
	c := newClient()
	if code, body, _ := call(t, c, "POST", srv.URL+"/api/setup", creds("admin", pw1), false, nil); code != 200 {
		t.Fatalf("setup: %d %s", code, body)
	}
	return c
}

func loginAs(t *testing.T, srv *httptest.Server, user, pw string) (*http.Client, int) {
	t.Helper()
	c := newClient()
	code, _, _ := call(t, c, "POST", srv.URL+"/api/login", creds(user, pw), false, nil)
	return c, code
}

func TestUnauthenticatedGets401WithoutBrowserPopup(t *testing.T) {
	srv, _ := newTestServer(t)
	setupAndLogin(t, srv)
	code, _, hdr := call(t, newClient(), "GET", srv.URL+"/api/state", nil, false, nil)
	if code != 401 {
		t.Fatalf("code = %d, want 401", code)
	}
	if hdr.Get("WWW-Authenticate") != "" {
		t.Fatal("must not send WWW-Authenticate: that triggers the browser's credentials pop-up")
	}
}

func TestLoginLogout(t *testing.T) {
	srv, _ := newTestServer(t)
	setupAndLogin(t, srv)

	if _, code := loginAs(t, srv, "admin", "wrong password!!"); code != 401 {
		t.Fatalf("wrong password = %d, want 401", code)
	}
	if _, code := loginAs(t, srv, "nobody", pw1); code != 401 {
		t.Fatalf("unknown user = %d, want 401", code)
	}
	c := newClient()
	code, _, hdr := call(t, c, "POST", srv.URL+"/api/login", creds("ADMIN", pw1), false, nil) // usernames are case-insensitive
	if code != 200 {
		t.Fatalf("login = %d", code)
	}
	if sc := hdr.Get("Set-Cookie"); !strings.Contains(sc, "HttpOnly") || !strings.Contains(sc, "SameSite=Strict") {
		t.Fatalf("cookie flags: %q", sc)
	}
	if code, _, _ := call(t, c, "GET", srv.URL+"/api/state", nil, false, nil); code != 200 {
		t.Fatalf("signed in = %d", code)
	}
	call(t, c, "POST", srv.URL+"/api/logout", nil, false, nil)
	if code, _, _ := call(t, c, "GET", srv.URL+"/api/state", nil, false, nil); code != 401 {
		t.Fatalf("after logout = %d, want 401", code)
	}
}

func TestWrongUsernameAndWrongPasswordLookTheSame(t *testing.T) {
	srv, _ := newTestServer(t)
	setupAndLogin(t, srv)
	_, b1, _ := call(t, newClient(), "POST", srv.URL+"/api/login", creds("admin", "not the password"), false, nil)
	_, b2, _ := call(t, newClient(), "POST", srv.URL+"/api/login", creds("ghost", "not the password"), false, nil)
	if b1 != b2 {
		t.Fatalf("responses differ and reveal which usernames exist:\n%s\n%s", b1, b2)
	}
}

func TestCSRFHeaderRequired(t *testing.T) {
	srv, _ := newTestServer(t)
	c := setupAndLogin(t, srv)
	if code, _, _ := call(t, c, "PUT", srv.URL+"/api/settings", map[string]any{}, true, nil); code != 403 {
		t.Fatalf("state-changing call without header = %d, want 403", code)
	}
}

func TestStaticAssetsPublic(t *testing.T) {
	srv, _ := newTestServer(t)
	for _, p := range []string{"/", "/app.js", "/style.css", "/favicon.svg"} {
		if code, _, _ := call(t, newClient(), "GET", srv.URL+p, nil, false, nil); code != 200 {
			t.Errorf("%s = %d, the login page must be able to load", p, code)
		}
	}
}

func TestBasicAuthForScriptsAndThrottle(t *testing.T) {
	srv, _ := newTestServer(t)
	setupAndLogin(t, srv)
	basic := func(user, pw string) func(*http.Request) {
		return func(r *http.Request) { r.SetBasicAuth(user, pw) }
	}
	if code, _, _ := call(t, newClient(), "GET", srv.URL+"/api/state", nil, false, basic("admin", pw1)); code != 200 {
		t.Fatalf("basic auth with right password = %d", code)
	}
	for i := 0; i < maxFailures; i++ {
		call(t, newClient(), "GET", srv.URL+"/api/state", nil, false, basic("admin", "nope nope nope"))
	}
	// now even the right password is refused until the window passes
	if code, _, _ := call(t, newClient(), "GET", srv.URL+"/api/state", nil, false, basic("admin", pw1)); code != 401 {
		t.Fatalf("after %d failures right password = %d, want 401 (throttled)", maxFailures, code)
	}
	if _, code := loginAs(t, srv, "admin", pw1); code != 429 {
		t.Fatalf("login while throttled = %d, want 429", code)
	}
}

func TestPasswordChangeSignsOutOnlyThatUsersOtherSessions(t *testing.T) {
	srv, _ := newTestServer(t)
	a := setupAndLogin(t, srv)            // admin, browser A
	b, _ := loginAs(t, srv, "admin", pw1) // admin, browser B

	if code, _, _ := call(t, a, "POST", srv.URL+"/api/users", map[string]string{"username": "sam", "password": pw2, "confirm": pw1}, false, nil); code != 200 {
		t.Fatalf("create user = %d", code)
	}
	sam, code := loginAs(t, srv, "sam", pw2)
	if code != 200 {
		t.Fatalf("sam login = %d", code)
	}

	change := func(cur, next string) int {
		code, _, _ := call(t, a, "POST", srv.URL+"/api/password", map[string]string{"current": cur, "password": next}, false, nil)
		return code
	}
	if c := change("not the password", "yet another password"); c != 403 {
		t.Fatalf("change with wrong current = %d, want 403", c)
	}
	if c := change(pw1, "tiny"); c != 400 {
		t.Fatalf("change to short password = %d, want 400", c)
	}
	if c := change(pw1, "yet another password"); c != 200 {
		t.Fatalf("change = %d", c)
	}

	if code, _, _ := call(t, a, "GET", srv.URL+"/api/state", nil, false, nil); code != 200 {
		t.Fatalf("the browser that changed it should stay signed in, got %d", code)
	}
	if code, _, _ := call(t, b, "GET", srv.URL+"/api/state", nil, false, nil); code != 401 {
		t.Fatalf("admin's other browser should be signed out, got %d", code)
	}
	if code, _, _ := call(t, sam, "GET", srv.URL+"/api/state", nil, false, nil); code != 200 {
		t.Fatalf("sam must be unaffected by admin's password change, got %d", code)
	}
	if _, code := loginAs(t, srv, "admin", pw1); code != 401 {
		t.Fatalf("old password must stop working, got %d", code)
	}
}

func TestForgedCookieRejected(t *testing.T) {
	srv, _ := newTestServer(t)
	setupAndLogin(t, srv)
	forge := func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: cookieName, Value: "9999999999.61646d696e.deadbeef"}) // "admin" in hex
	}
	if code, _, _ := call(t, newClient(), "GET", srv.URL+"/api/state", nil, false, forge); code != 401 {
		t.Fatalf("forged cookie = %d, want 401", code)
	}
}

func TestManagingUsers(t *testing.T) {
	srv, _ := newTestServer(t)
	a := setupAndLogin(t, srv)
	do := func(method, path string, body any) (int, string) {
		code, b, _ := call(t, a, method, srv.URL+path, body, false, nil)
		return code, b
	}

	if code, _ := do("POST", "/api/users", map[string]string{"username": "sam", "password": pw2, "confirm": "wrong"}); code != 403 {
		t.Fatalf("creating a user must need your own password, got %d", code)
	}
	if code, _ := do("POST", "/api/users", map[string]string{"username": "sam", "password": "short", "confirm": pw1}); code != 400 {
		t.Fatalf("short password for new user = %d, want 400", code)
	}
	if code, _ := do("POST", "/api/users", map[string]string{"username": "sam", "password": pw2, "confirm": pw1}); code != 200 {
		t.Fatalf("create = %d", code)
	}
	if code, _ := do("POST", "/api/users", map[string]string{"username": "SAM", "password": pw2, "confirm": pw1}); code != 400 {
		t.Fatalf("duplicate username (case-insensitive) = %d, want 400", code)
	}

	// the list never contains password hashes
	_, state := do("GET", "/api/state", nil)
	if strings.Contains(state, "$2a$") || strings.Contains(state, `"hash"`) {
		t.Fatalf("password hash leaked into /api/state: %s", state)
	}
	var st struct {
		Me    string
		Users []struct{ Name string }
	}
	_ = json.Unmarshal([]byte(state), &st)
	if st.Me != "admin" || len(st.Users) != 2 {
		t.Fatalf("me=%q users=%+v", st.Me, st.Users)
	}

	if code, _ := do("POST", "/api/users/sam/password", map[string]string{"password": "reset by admin 1", "confirm": pw1}); code != 200 {
		t.Fatalf("reset = %d", code)
	}
	if _, code := loginAs(t, srv, "sam", pw2); code != 401 {
		t.Fatalf("sam's old password must stop working, got %d", code)
	}
	if _, code := loginAs(t, srv, "sam", "reset by admin 1"); code != 200 {
		t.Fatalf("sam's reset password should work, got %d", code)
	}

	if code, _ := do("DELETE", "/api/users/admin", map[string]string{"confirm": pw1}); code != 400 {
		t.Fatalf("deleting yourself = %d, want 400", code)
	}
	if code, _ := do("DELETE", "/api/users/sam", map[string]string{"confirm": pw1}); code != 200 {
		t.Fatalf("delete = %d", code)
	}
	if _, code := loginAs(t, srv, "sam", "reset by admin 1"); code != 401 {
		t.Fatalf("a deleted user cannot sign in, got %d", code)
	}
}

func TestMigratesTheOldSinglePassword(t *testing.T) {
	dir := t.TempDir()
	// a database written by an earlier version: one shared password hash, no users
	hash, _ := bcryptHash(pw1)
	old := `{"settings":{"acme_directory":"staging"},"admin_hash":"` + hash + `","dns_providers":null,"certificates":null,"targets":null,"events":null,"alerts":{}}`
	if err := os.WriteFile(filepath.Join(dir, "db.json"), []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	var users []model.User
	st.View(func(db *model.DB) { users = append(users, db.Users...) })
	if len(users) != 1 || users[0].Name != "admin" || users[0].Hash != hash {
		t.Fatalf("migration produced %+v", users)
	}
}

func TestResetPasswordAndWipe(t *testing.T) {
	srv, ws := newTestServer(t)
	setupAndLogin(t, srv)
	if _, code := loginAs(t, srv, "admin", pw1); code != 200 {
		t.Fatal("precondition: login works")
	}
	if _, err := os.Stat(filepath.Join(ws.DataDir, "session.key")); err != nil {
		t.Fatal("session key should exist after sign-in")
	}

	// the real command runs with the service stopped; run it over the same files
	name, pw, err := ResetPassword(ws.DataDir, "")
	if err != nil || name != "admin" || len(pw) < 16 {
		t.Fatalf("ResetPassword = %q %q %v", name, pw, err)
	}
	st, _ := store.Open(ws.DataDir)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ws2, _ := New(st, ws.Box, engine.New(st, ws.Box, ws.DataDir, log), ws.DataDir, log)
	srv2 := httptest.NewServer(ws2.Handler())
	defer srv2.Close()
	if _, code := loginAs(t, srv2, "admin", pw1); code != 401 {
		t.Fatalf("the old password must not work after a reset, got %d", code)
	}
	if _, code := loginAs(t, srv2, "admin", pw); code != 200 {
		t.Fatalf("the new random password must work, got %d", code)
	}

	if err := WipeUsers(ws.DataDir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(ws.DataDir, "session.key")); err == nil {
		t.Fatal("session key must be removed so old cookies die")
	}
	st3, _ := store.Open(ws.DataDir)
	ws3, _ := New(st3, ws.Box, engine.New(st3, ws.Box, ws.DataDir, log), ws.DataDir, log)
	srv3 := httptest.NewServer(ws3.Handler())
	defer srv3.Close()
	if got := sessionState(t, newClient(), srv3.URL); got != "setup" {
		t.Fatalf("after wipe state = %q, want setup", got)
	}
}

func TestChangePasswordErrorsSayWhatIsWrong(t *testing.T) {
	srv, _ := newTestServer(t)
	c := setupAndLogin(t, srv)
	post := func(cur, next string) (int, string) {
		code, body, _ := call(t, c, "POST", srv.URL+"/api/password", map[string]string{"current": cur, "password": next}, false, nil)
		return code, body
	}
	// left the "current password" box empty: say so, do not call it incorrect
	if code, body := post("", pw2); code != 400 || !strings.Contains(body, "enter your current password") {
		t.Fatalf("empty current password: %d %s", code, body)
	}
	// typed something that is not the current password
	if code, body := post("not my password", pw2); code != 403 || !strings.Contains(body, "current password is incorrect") {
		t.Fatalf("wrong current password: %d %s", code, body)
	}
	// and the real flow works: the new password is accepted once the current one is right
	if code, body := post(pw1, pw2); code != 200 {
		t.Fatalf("change: %d %s", code, body)
	}
	if _, code := loginAs(t, srv, "admin", pw2); code != 200 {
		t.Fatalf("the new password must work, got %d", code)
	}
}

func TestYouCannotResetYourOwnPasswordThatWay(t *testing.T) {
	srv, _ := newTestServer(t)
	a := setupAndLogin(t, srv) // admin
	code, body, _ := call(t, a, "POST", srv.URL+"/api/users/admin/password", map[string]string{"password": pw2, "confirm": pw1}, false, nil)
	if code != 400 || !strings.Contains(body, "Your password") {
		t.Fatalf("resetting your own password through the user list must be refused and point to the right place, got %d %s", code, body)
	}
	code, _, _ = call(t, a, "POST", srv.URL+"/api/users/ADMIN/password", map[string]string{"password": pw2, "confirm": pw1}, false, nil)
	if code != 400 {
		t.Fatalf("the name check must ignore case, got %d", code)
	}
	if _, c := loginAs(t, srv, "admin", pw1); c != 200 {
		t.Fatalf("the refused request must not have changed the password, got %d", c)
	}
	// resetting someone else is unchanged
	call(t, a, "POST", srv.URL+"/api/users", map[string]string{"username": "sam", "password": pw2, "confirm": pw1}, false, nil)
	if code, _, _ := call(t, a, "POST", srv.URL+"/api/users/sam/password", map[string]string{"password": "reset by admin 1", "confirm": pw1}, false, nil); code != 200 {
		t.Fatalf("resetting another user must still work, got %d", code)
	}
}
