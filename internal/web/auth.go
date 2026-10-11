package web

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/CautiousCapsLock/certsmith/internal/model"
	"github.com/CautiousCapsLock/certsmith/internal/notify"
	"github.com/CautiousCapsLock/certsmith/internal/store"
)

const (
	cookieName    = "certsmith_session"
	sessionTTL    = 12 * time.Hour
	minPassword   = 12
	maxFailures   = 8
	failureWindow = 10 * time.Minute
)

// ---- users ----------------------------------------------------------------------------

var userRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,31}$`)

func normUser(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if !userRe.MatchString(s) {
		return "", errors.New("username must be 2-32 characters: letters, digits, dot, dash or underscore")
	}
	return s, nil
}

func (s *Server) findUser(name string) (u model.User, ok bool) {
	s.St.View(func(db *model.DB) {
		for _, x := range db.Users {
			if x.Name == name {
				u, ok = x, true
			}
		}
	})
	return
}

func (s *Server) hasUsers() (has bool) {
	s.St.View(func(db *model.DB) { has = len(db.Users) > 0 })
	return
}

func checkNewPassword(pw string) error {
	if len(pw) < minPassword {
		return fmt.Errorf("password must be at least %d characters", minPassword)
	}
	if len(pw) > 72 { // bcrypt ignores everything past 72 bytes
		return errors.New("password must be at most 72 characters")
	}
	return nil
}

// ---- session cookie -----------------------------------------------------------------
//
// The cookie is "<expiry>.<hex username>.<hmac>". The MAC covers the expiry, the
// username and that user's current password hash. Sessions therefore survive a
// restart, and changing a password signs that user out everywhere else.

func loadSessionKey(dataDir string) ([]byte, error) {
	path := filepath.Join(dataDir, "session.key")
	b, err := os.ReadFile(path)
	if err == nil && len(b) >= 32 {
		return b, nil
	}
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, os.WriteFile(path, key, 0o600)
}

func (s *Server) mac(exp int64, name, hash string) string {
	m := hmac.New(sha256.New, s.sessionKey)
	fmt.Fprintf(m, "v2|%d|%s|%s", exp, name, hash)
	return hex.EncodeToString(m.Sum(nil))
}

func (s *Server) issue(w http.ResponseWriter, r *http.Request, u model.User) {
	now := time.Now()
	if now.Before(u.SessionsFrom) { // signed in again within a second of signing out: not before the sign-out
		now = u.SessionsFrom
	}
	exp := now.Add(sessionTTL).Unix()
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: fmt.Sprintf("%d.%s.%s", exp, hex.EncodeToString([]byte(u.Name)), s.mac(exp, u.Name, u.Hash)),
		Path: "/", MaxAge: int(sessionTTL.Seconds()),
		HttpOnly: true, Secure: s.secure(r), SameSite: http.SameSiteStrictMode,
	})
}

// secure reports whether the browser reached this server over HTTPS: the connection is TLS, or it comes
// from a trusted proxy (Settings) that says it received the request over HTTPS. It decides the Secure flag
// of the session cookie and the Strict-Transport-Security header, so a server behind a proxy that ends
// TLS, run with -no-tls, still marks its cookie Secure.
func (s *Server) secure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if !strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https") {
		return false
	}
	c, err := netip.ParseAddr(connHost(r))
	return err == nil && inPrefixes(c, s.trustedProxies())
}

// cookieUser returns the signed-in user for a valid session cookie.
func (s *Server) cookieUser(r *http.Request) (model.User, bool) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return model.User{}, false
	}
	parts := strings.Split(c.Value, ".")
	if len(parts) != 3 {
		return model.User{}, false
	}
	exp, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return model.User{}, false
	}
	nameBytes, err := hex.DecodeString(parts[1])
	if err != nil {
		return model.User{}, false
	}
	u, ok := s.findUser(string(nameBytes))
	if !ok || !hmac.Equal([]byte(parts[2]), []byte(s.mac(exp, u.Name, u.Hash))) {
		return model.User{}, false
	}
	// the cookie expires sessionTTL after it was issued: a session from before the last sign-out is over
	if issued := exp - int64(sessionTTL.Seconds()); !u.SessionsFrom.IsZero() && issued < u.SessionsFrom.Unix() {
		return model.User{}, false
	}
	return u, true
}

type ctxKey struct{}

func userFrom(r *http.Request) string {
	n, _ := r.Context().Value(ctxKey{}).(string)
	return n
}

// ---- brute-force limiter ------------------------------------------------------------

type limiter struct {
	mu    sync.Mutex
	fails map[string][]time.Time
	noted map[string]time.Time // when a lockout was last written to the audit log, per key
}

func newLimiter() *limiter {
	return &limiter{fails: map[string][]time.Time{}, noted: map[string]time.Time{}}
}

// noteDue reports whether a lockout for key should be written to the audit log now: the first
// refusal in each window is, the rest are not.
func (l *limiter) noteDue(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if t, ok := l.noted[key]; ok && time.Since(t) < failureWindow {
		return false
	}
	l.noted[key] = time.Now()
	return true
}

func (l *limiter) prune(key string) []time.Time {
	cut := time.Now().Add(-failureWindow)
	var keep []time.Time
	for _, t := range l.fails[key] {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	if len(keep) == 0 {
		delete(l.fails, key)
	} else {
		l.fails[key] = keep
	}
	return keep
}

func (l *limiter) blocked(keys ...string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, k := range keys {
		if len(l.prune(k)) >= maxFailures {
			return true
		}
	}
	return false
}

func (l *limiter) fail(keys ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, k := range keys {
		l.prune(k)
		l.fails[k] = append(l.fails[k], time.Now())
	}
}

func (l *limiter) reset(keys ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, k := range keys {
		delete(l.fails, k)
	}
}

// failure keys: the caller's address (behind a reverse proxy that is the proxy,
// so effectively global, and safe against spoofed X-Forwarded-For) and the
// targeted account (so guessing at one account cannot lock out the others).
func (s *Server) limitKeys(r *http.Request, user string) []string {
	ip, _ := s.clientIP(r)
	return []string{"ip:" + ip, "user:" + strings.ToLower(user)}
}

// noteBlocked records in the audit log that a sign-in was refused because of the throttle. A lockout
// is recorded once per window and address, not once per refused attempt, so an attacker cannot fill
// the log with it.
func (s *Server) noteBlocked(r *http.Request, name string, keys []string) {
	if !s.lim.noteDue(keys[0]) {
		return
	}
	s.auditAs(r, "", "signin.blocked", strconv.Quote(name), "refused: too many failed attempts from this address or for this account")
}

// ---- middleware ---------------------------------------------------------------------

func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "+
			"base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Cache-Control", "no-store")
		if s.secure(r) {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}

		// the page, its script and its stylesheet carry no secrets: they must load
		// before the user can sign in
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		// A cross-site request cannot add a custom header without a CORS preflight,
		// which this server never approves.
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Header.Get("X-Certsmith") != "1" {
			fail(w, http.StatusForbidden, "missing X-Certsmith header")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

		switch r.URL.Path {
		case "/api/session", "/api/setup", "/api/login", "/api/logout":
			next.ServeHTTP(w, r)
			return
		}

		if !s.hasUsers() {
			fail(w, http.StatusForbidden, "setup required: open the web UI to create the first user")
			return
		}
		if u, ok := s.cookieUser(r); ok {
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, u.Name)))
			return
		}
		if u, ok := s.basicUser(r); ok {
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, u.Name)))
			return
		}
		fail(w, http.StatusUnauthorized, "sign in required")
	})
}

// basicUser lets scripts authenticate with HTTP Basic. No challenge header is
// ever sent, so browsers never show a credentials pop-up.
func (s *Server) basicUser(r *http.Request) (model.User, bool) {
	name, pass, ok := r.BasicAuth()
	if !ok {
		return model.User{}, false
	}
	name = strings.ToLower(name)
	keys := s.limitKeys(r, name)
	if s.lim.blocked(keys...) {
		s.noteBlocked(r, name, keys)
		return model.User{}, false
	}
	u, found := s.findUser(name)
	hash := u.Hash
	if !found {
		hash = dummyHash // keep the timing the same whether or not the account exists
	}
	good := bcrypt.CompareHashAndPassword([]byte(hash), []byte(pass)) == nil
	if found && good && subtle.ConstantTimeCompare([]byte(u.Name), []byte(name)) == 1 {
		return u, true
	}
	s.lim.fail(keys...)
	return model.User{}, false
}

var dummyHash = func() string {
	h, _ := bcrypt.GenerateFromPassword([]byte("certsmith-timing-equaliser"), bcrypt.DefaultCost)
	return string(h)
}()

// ---- session / sign-in handlers ----------------------------------------------------

func (s *Server) session(w http.ResponseWriter, r *http.Request) {
	out := map[string]string{"state": "login"}
	switch u, ok := s.cookieUser(r); {
	case !s.hasUsers():
		out["state"] = "setup"
	case ok:
		out["state"], out["user"] = "ok", u.Name
	}
	writeJSON(w, out)
}

// setup creates the first user. It works exactly once: the check and the write
// happen under the store lock, so two racing requests cannot both win.
func (s *Server) setup(w http.ResponseWriter, r *http.Request) {
	var in struct{ Username, Password string }
	if !decode(w, r, &in) {
		return
	}
	name, err := normUser(in.Username)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	if err := checkNewPassword(in.Password); err != nil {
		fail(w, 400, err.Error())
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	u := model.User{Name: name, Hash: string(hash), Created: time.Now()}
	errDone := errors.New("setup already completed")
	err = s.St.Update(func(db *model.DB) error {
		if len(db.Users) > 0 {
			return errDone
		}
		db.Users = []model.User{u}
		return nil
	})
	if errors.Is(err, errDone) {
		fail(w, http.StatusConflict, err.Error())
		return
	}
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	s.auditAs(r, name, "user.setup", name, "first user created through the setup wizard")
	s.recordLogin(r, name)
	s.issue(w, r, u)
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var in struct{ Username, Password string }
	if !decode(w, r, &in) {
		return
	}
	name := strings.ToLower(strings.TrimSpace(in.Username))
	keys := s.limitKeys(r, name)
	if s.lim.blocked(keys...) {
		s.noteBlocked(r, name, keys)
		fail(w, http.StatusTooManyRequests, "too many failed attempts - try again in a few minutes")
		return
	}
	if !s.hasUsers() {
		fail(w, http.StatusForbidden, "setup required")
		return
	}
	u, found := s.findUser(name)
	hash := u.Hash
	if !found {
		hash = dummyHash
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(in.Password)) != nil || !found {
		s.lim.fail(keys...)
		time.Sleep(400 * time.Millisecond)
		s.auditAs(r, "", "signin.failed", strconv.Quote(name), "")
		fail(w, http.StatusUnauthorized, "incorrect username or password") // never reveal which one
		return
	}
	s.lim.reset(keys...)
	s.auditAs(r, u.Name, "signin", u.Name, "")
	s.recordLogin(r, u.Name)
	s.issue(w, r, u)
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if u, ok := s.cookieUser(r); ok {
		// a cookie copied before signing out must not keep working until it expires
		_ = s.St.Update(func(db *model.DB) error {
			for i := range db.Users {
				if db.Users[i].Name == u.Name {
					// the next whole second: a cookie is dated to the second, so one issued in the second of
					// the sign-out is still before this
					db.Users[i].SessionsFrom = time.Now().Truncate(time.Second).Add(time.Second)
				}
			}
			return nil
		})
		s.auditAs(r, u.Name, "signout", u.Name, "")
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: s.secure(r), SameSite: http.SameSiteStrictMode})
	writeJSON(w, map[string]bool{"ok": true})
}

// confirmSelf checks the signed-in user's own password. Changing credentials and
// managing users require it even with a valid session, so a hijacked session
// cannot lock the owner out or add a back door silently.
func (s *Server) confirmSelf(w http.ResponseWriter, r *http.Request, password string) (model.User, bool) {
	me, ok := s.findUser(userFrom(r))
	keys := s.limitKeys(r, userFrom(r))
	if !ok {
		fail(w, http.StatusUnauthorized, "sign in required")
		return model.User{}, false
	}
	if password == "" {
		fail(w, http.StatusBadRequest, "enter your current password to confirm")
		return model.User{}, false
	}
	if s.lim.blocked(keys...) {
		fail(w, http.StatusTooManyRequests, "too many failed attempts - try again in a few minutes")
		return model.User{}, false
	}
	if bcrypt.CompareHashAndPassword([]byte(me.Hash), []byte(password)) != nil {
		s.lim.fail(keys...)
		time.Sleep(400 * time.Millisecond)
		fail(w, http.StatusForbidden, "your current password is incorrect")
		return model.User{}, false
	}
	return me, true
}

// setPassword changes the signed-in user's own password.
func (s *Server) setPassword(w http.ResponseWriter, r *http.Request) {
	var in struct{ Current, Password string }
	if !decode(w, r, &in) {
		return
	}
	me, ok := s.confirmSelf(w, r, in.Current)
	if !ok {
		return
	}
	if err := checkNewPassword(in.Password); err != nil {
		fail(w, 400, err.Error())
		return
	}
	updated, err := s.setUserPassword(me.Name, in.Password)
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	s.auditAs(r, me.Name, "user.password_change", me.Name, "own password; their other sessions were signed out")
	s.notifyAdmin(notify.PasswordChanged, "[CertSmith] password changed", me.Name+" changed their own password.")
	s.issue(w, r, updated) // this browser stays signed in; every other session of this user is now invalid
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) setUserPassword(name, password string) (model.User, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return model.User{}, err
	}
	var out model.User
	err = s.St.Update(func(db *model.DB) error {
		for i := range db.Users {
			if db.Users[i].Name == name {
				db.Users[i].Hash = string(hash)
				out = db.Users[i]
				return nil
			}
		}
		return errors.New("user not found")
	})
	return out, err
}

// ---- user management (no roles: every user may manage users) -------------------------------

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var in struct{ Username, Password, Confirm string }
	if !decode(w, r, &in) {
		return
	}
	me, ok := s.confirmSelf(w, r, in.Confirm)
	if !ok {
		return
	}
	name, err := normUser(in.Username)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	if err := checkNewPassword(in.Password); err != nil {
		fail(w, 400, err.Error())
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	err = s.St.Update(func(db *model.DB) error {
		for _, u := range db.Users {
			if u.Name == name {
				return errors.New("that username already exists")
			}
		}
		db.Users = append(db.Users, model.User{Name: name, Hash: string(hash), Created: time.Now()})
		return nil
	})
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	s.auditAs(r, me.Name, "user.create", name, "")
	s.notifyAdmin(notify.UserCreated, "[CertSmith] user created", me.Name+" created the user "+name+".")
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	var in struct{ Confirm string }
	if !decode(w, r, &in) {
		return
	}
	me, ok := s.confirmSelf(w, r, in.Confirm)
	if !ok {
		return
	}
	name := strings.ToLower(r.PathValue("name"))
	if name == me.Name {
		fail(w, 400, "you cannot delete the account you are signed in with")
		return
	}
	err := s.St.Update(func(db *model.DB) error {
		for i := range db.Users {
			if db.Users[i].Name == name {
				db.Users = append(db.Users[:i], db.Users[i+1:]...)
				return nil
			}
		}
		return errors.New("user not found")
	})
	if err != nil {
		fail(w, 404, err.Error())
		return
	}
	s.auditAs(r, me.Name, "user.delete", name, "")
	s.notifyAdmin(notify.UserDeleted, "[CertSmith] user deleted", me.Name+" deleted the user "+name+".")
	writeJSON(w, map[string]bool{"ok": true})
}

// resetUserPassword sets another user's password (their sessions end). Your own
// password is changed with the "Your password" form, which asks for the current one.
func (s *Server) resetUserPassword(w http.ResponseWriter, r *http.Request) {
	var in struct{ Password, Confirm string }
	if !decode(w, r, &in) {
		return
	}
	if strings.EqualFold(r.PathValue("name"), userFrom(r)) {
		fail(w, http.StatusBadRequest, `change your own password with the "Your password" box in Settings`)
		return
	}
	me, ok := s.confirmSelf(w, r, in.Confirm)
	if !ok {
		return
	}
	if err := checkNewPassword(in.Password); err != nil {
		fail(w, 400, err.Error())
		return
	}
	name := strings.ToLower(r.PathValue("name"))
	if _, err := s.setUserPassword(name, in.Password); err != nil {
		fail(w, 404, err.Error())
		return
	}
	s.auditAs(r, me.Name, "user.password_reset", name, "their sessions were signed out")
	s.notifyAdmin(notify.PasswordChanged, "[CertSmith] password reset", me.Name+" reset the password of "+name+".")
	writeJSON(w, map[string]bool{"ok": true})
}

// recordLogin remembers when and from where a user last signed in, for the user list.
func (s *Server) recordLogin(r *http.Request, name string) {
	from := s.clientAddr(r)
	_ = s.St.Update(func(db *model.DB) error {
		for i := range db.Users {
			if strings.EqualFold(db.Users[i].Name, name) {
				db.Users[i].LastLogin, db.Users[i].LastLoginFrom = time.Now(), from
			}
		}
		return nil
	})
}

// publicUsers is the user list without password hashes, with each user's latest sign-in. A user who
// last signed in before CertSmith kept that on the user itself is read from the audit log, as far
// back as it goes.
func publicUsers(db *model.DB) []map[string]any {
	out := []map[string]any{}
	for _, u := range db.Users {
		last, from := u.LastLogin, u.LastLoginFrom
		if last.IsZero() {
			for _, a := range db.Audit {
				if a.Action == "signin" && strings.EqualFold(a.User, u.Name) && a.Time.After(last) {
					last, from = a.Time, a.IP
				}
			}
		}
		m := map[string]any{"name": u.Name, "created": u.Created}
		if !last.IsZero() {
			m["last_login"], m["last_login_from"] = last, from
		}
		out = append(out, m)
	}
	return out
}

// ---- offline helpers used by the command line ---------------------------------------------

// SeedAdmin creates the first user from the environment (for automated installs).
// Without it the first browser visit runs the setup wizard.
func SeedAdmin(st *store.Store, user, password string) error {
	if password == "" {
		return nil
	}
	if user == "" {
		user = "admin"
	}
	name, err := normUser(user)
	if err != nil {
		return fmt.Errorf("CERTSMITH_ADMIN_USER: %w", err)
	}
	if err := checkNewPassword(password); err != nil {
		return fmt.Errorf("CERTSMITH_ADMIN_PASSWORD: %w", err)
	}
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	return st.Update(func(db *model.DB) error {
		if len(db.Users) == 0 {
			db.Users = []model.User{{Name: name, Hash: string(h), Created: time.Now()}}
		}
		return nil
	})
}

// ResetPassword gives a user a new random password and returns it. Run it with
// the service stopped. All of that user's sessions end.
func ResetPassword(dataDir, user string) (name, password string, err error) {
	st, err := store.Open(dataDir)
	if err != nil {
		return "", "", err
	}
	var users []model.User
	st.View(func(db *model.DB) { users = append(users, db.Users...) })
	switch {
	case len(users) == 0:
		return "", "", errors.New("there are no users yet: open the web UI to run the setup wizard")
	case user == "" && len(users) == 1:
		name = users[0].Name
	case user == "":
		var names []string
		for _, u := range users {
			names = append(names, u.Name)
		}
		return "", "", fmt.Errorf("several users exist (%s): choose one with -user", strings.Join(names, ", "))
	default:
		name = strings.ToLower(user)
	}
	raw := make([]byte, 15)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	password = base64.RawURLEncoding.EncodeToString(raw)
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", "", err
	}
	err = st.Update(func(db *model.DB) error {
		for i := range db.Users {
			if db.Users[i].Name == name {
				db.Users[i].Hash = string(hash)
				return nil
			}
		}
		return fmt.Errorf("no such user %q", name)
	})
	return name, password, err
}

// WipeUsers removes every user so the next visit runs the setup wizard again.
func WipeUsers(dataDir string) error {
	st, err := store.Open(dataDir)
	if err != nil {
		return err
	}
	if err := st.Update(func(db *model.DB) error { db.Users, db.AdminHash = nil, ""; return nil }); err != nil {
		return err
	}
	for _, f := range []string{"session.key", "initial-admin-password.txt"} {
		if err := os.Remove(filepath.Join(dataDir, f)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}
