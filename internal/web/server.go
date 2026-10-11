// Package web serves the management API and the embedded single-page UI.
package web

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/CautiousCapsLock/certsmith/internal/acme"
	"github.com/CautiousCapsLock/certsmith/internal/engine"
	"github.com/CautiousCapsLock/certsmith/internal/model"
	"github.com/CautiousCapsLock/certsmith/internal/notify"
	"github.com/CautiousCapsLock/certsmith/internal/plugin"
	"github.com/CautiousCapsLock/certsmith/internal/secret"
	"github.com/CautiousCapsLock/certsmith/internal/store"
	"github.com/CautiousCapsLock/certsmith/internal/update"
)

//go:embed static
var staticFS embed.FS

type Server struct {
	St      *store.Store
	Box     *secret.Box
	Eng     *engine.Engine
	DataDir string
	Log     *slog.Logger

	// Version is the running build; Updates asks the release host about newer ones. Both are set by
	// SetUpdates after New and are optional (tests, and builds with no release host).
	Version string
	Updates *update.Checker

	autoAuditErr string    // the last failure of the automatic update check that was written to the audit log
	autoAuditAt  time.Time // and when

	sessionKey []byte
	lim        *limiter
}

// New builds the server and loads (or creates) the session-signing key.
func New(st *store.Store, box *secret.Box, eng *engine.Engine, dataDir string, log *slog.Logger) (*Server, error) {
	key, err := loadSessionKey(dataDir)
	if err != nil {
		return nil, err
	}
	return &Server{St: st, Box: box, Eng: eng, DataDir: dataDir, Log: log, sessionKey: key, lim: newLimiter()}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	sub, _ := fs.Sub(staticFS, "static")
	mux.Handle("GET /", http.FileServer(http.FS(sub)))

	mux.HandleFunc("GET /api/session", s.session)
	mux.HandleFunc("POST /api/setup", s.setup)
	mux.HandleFunc("POST /api/login", s.login)
	mux.HandleFunc("POST /api/logout", s.logout)
	mux.HandleFunc("GET /api/state", s.state)
	mux.HandleFunc("POST /api/update/check", s.checkUpdate)
	mux.HandleFunc("POST /api/ui-cert/regenerate", s.regenerateUICert)
	mux.HandleFunc("GET /api/schema", s.schema)
	mux.HandleFunc("PUT /api/settings", s.putSettings)
	mux.HandleFunc("POST /api/settings/test-alert", s.testAlert)
	mux.HandleFunc("POST /api/password", s.setPassword)
	mux.HandleFunc("POST /api/users", s.createUser)
	mux.HandleFunc("DELETE /api/users/{name}", s.deleteUser)
	mux.HandleFunc("POST /api/users/{name}/password", s.resetUserPassword)

	mux.HandleFunc("POST /api/dns", s.audited("provider.create", "provider", s.saveDNS))
	mux.HandleFunc("PUT /api/dns/{id}", s.audited("provider.update", "provider", s.saveDNS))
	mux.HandleFunc("DELETE /api/dns/{id}", s.audited("provider.delete", "provider", s.deleteDNS))
	mux.HandleFunc("POST /api/dns/test", s.audited("provider.dns_test", "provider", s.testDNS))
	mux.HandleFunc("POST /api/dns/check-account", s.audited("provider.check_account", "provider", s.checkAccount))
	mux.HandleFunc("POST /api/dns/pending/{id}/dismiss", s.dismissPendingDNS)

	mux.HandleFunc("POST /api/certs", s.audited("cert.create", "cert", s.saveCert))
	mux.HandleFunc("POST /api/certs/import/check", s.importCheck)
	mux.HandleFunc("POST /api/certs/import", s.audited("cert.import", "cert", s.importCert))
	mux.HandleFunc("POST /api/certs/{id}/import", s.audited("cert.replace", "cert", s.replaceCert))
	mux.HandleFunc("POST /api/certs/{id}/export", s.exportCert)
	mux.HandleFunc("PUT /api/certs/{id}", s.audited("cert.update", "cert", s.saveCert))
	mux.HandleFunc("DELETE /api/certs/{id}", s.audited("cert.delete", "cert", s.deleteCert))
	mux.HandleFunc("POST /api/certs/{id}/renew", s.audited("cert.issue", "cert", s.renewCert))
	mux.HandleFunc("POST /api/certs/{id}/cancel", s.audited("cert.cancel", "cert", s.cancelCert))
	mux.HandleFunc("GET /api/certs/{id}/log", s.certLog)

	mux.HandleFunc("POST /api/targets", s.audited("target.create", "target", s.saveTarget))
	mux.HandleFunc("PUT /api/targets/{id}", s.audited("target.update", "target", s.saveTarget))
	mux.HandleFunc("DELETE /api/targets/{id}", s.audited("target.delete", "target", s.deleteTarget))
	mux.HandleFunc("POST /api/targets/{id}/deploy", s.audited("target.deploy", "target", s.deployTarget))
	mux.HandleFunc("POST /api/targets/{id}/pause", s.audited("target.pause", "target", s.pauseTarget(true)))
	mux.HandleFunc("POST /api/targets/{id}/resume", s.audited("target.resume", "target", s.pauseTarget(false)))
	mux.HandleFunc("GET /api/targets/{id}/calls", s.targetCalls)
	mux.HandleFunc("POST /api/test-target", s.testTarget)
	mux.HandleFunc("POST /api/discover-target", s.discoverTarget)
	mux.HandleFunc("POST /api/probe", s.audited("endpoints.check", "", s.probe))

	// No request body is larger than an uploaded certificate with its key, a few hundred KB.
	return http.MaxBytesHandler(s.auth(mux), 4<<20)
}

// ---- helpers --------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		fail(w, 400, "bad request: "+err.Error())
		return false
	}
	return true
}

// mask replaces stored secrets with the placeholder shown in the UI.
func mask(d plugin.Descriptor, cfg map[string]string) map[string]string {
	sec := d.SecretKeys()
	out := make(map[string]string, len(cfg))
	for k, v := range cfg {
		if sec[k] && v != "" {
			v = secret.Mask
		}
		out[k] = v
	}
	return out
}

// merge builds the config to store from the submitted one: placeholders keep the
// previously stored (sealed) value, new secret values are sealed.
func (s *Server) merge(d plugin.Descriptor, in, old map[string]string) map[string]string {
	sec := d.SecretKeys()
	out := map[string]string{}
	for k, v := range in {
		if sec[k] {
			if v == secret.Mask {
				v = old[k]
			} else {
				v = s.Box.Seal(v)
			}
		}
		out[k] = v
	}
	return out
}

// sameConfig compares two plugin configurations, treating a missing key and an empty
// value as the same. The form fills in defaults for fields that were never stored, so a
// plain map comparison would call every save a change.
func sameConfig(a, b map[string]string) bool {
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	for k, v := range b {
		if a[k] != v {
			return false
		}
	}
	return true
}

// normResolver turns what was typed into host:port (53 when no port is given), refusing nonsense.
// IPv6 addresses may be bare or bracketed.
func normResolver(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	host, port := s, "53"
	if h, p, err := net.SplitHostPort(s); err == nil {
		host, port = h, p
	}
	host = strings.Trim(host, "[]")
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("resolver %q: the port must be a number from 1 to 65535", s)
	}
	if net.ParseIP(host) == nil && !domainRe.MatchString(strings.ToLower(host)) {
		return "", fmt.Errorf("resolver %q: not an IP address or host name", s)
	}
	return net.JoinHostPort(host, port), nil
}

var emailRe = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

var domainRe = regexp.MustCompile(`^(\*\.)?([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z0-9-]{2,}$`)

func normDomains(in []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, d := range in {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" || seen[d] {
			continue
		}
		if !domainRe.MatchString(d) {
			return nil, fmt.Errorf("%q is not a valid domain (wildcards only as a leading *.)", d)
		}
		seen[d] = true
		out = append(out, d)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("at least one domain is required")
	}
	return out, nil
}

// ---- audit ------------------------------------------------------------------------------

func (s *Server) auditAs(r *http.Request, user, action, subject, detail string) {
	s.St.AddAudit(model.AuditEntry{User: user, IP: s.clientAddr(r), Action: action, Subject: subject, Detail: detail})
}

func (s *Server) audit(r *http.Request, action, subject, detail string) {
	s.auditAs(r, userFrom(r), action, subject, detail)
}

// notifyAdmin sends an administration alert without holding up the request that caused it.
func (s *Server) notifyAdmin(typ, subject, body string) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		s.Eng.Notify(ctx, typ, subject, body)
	}()
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (w *statusRecorder) WriteHeader(code int) { w.status = code; w.ResponseWriter.WriteHeader(code) }

// audited records a successful request to a route in the audit log: who did it, what it was done to
// (named, not the id), and from where. Request bodies are looked at only for the "name" or "id", and
// never stored.
func (s *Server) audited(action, kind string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		subject := s.subjectOf(kind, r)
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		h(rec, r)
		if rec.status < 400 {
			s.audit(r, action, subject, "")
		}
	}
}

// subjectOf names what a request is about: the object in the path, or the one in the body.
func (s *Server) subjectOf(kind string, r *http.Request) string {
	if kind == "" {
		return ""
	}
	id := r.PathValue("id")
	name := ""
	if r.Body != nil && r.Method != http.MethodGet && r.Method != http.MethodDelete {
		b, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(b))
		var m struct{ ID, Name string }
		_ = json.Unmarshal(b, &m)
		name = m.Name
		if id == "" {
			id = m.ID
		}
	}
	if id != "" {
		s.St.View(func(db *model.DB) {
			switch kind {
			case "provider":
				for _, p := range db.DNSProviders {
					if p.ID == id {
						name = p.Name
					}
				}
			case "cert":
				for _, c := range db.Certificates {
					if c.ID == id {
						name = c.Name
					}
				}
			case "target":
				for _, t := range db.Targets {
					if t.ID == id {
						name = t.Name
					}
				}
			}
		})
	}
	return name
}

// changedFields lists the top-level settings whose value differs, by name only: the values can be secrets.
func changedFields(before, after model.Settings) []string {
	toMap := func(v model.Settings) map[string]any {
		b, _ := json.Marshal(v)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		return m
	}
	a, b := toMap(before), toMap(after)
	var out []string
	for k := range a {
		if !reflect.DeepEqual(a[k], b[k]) {
			out = append(out, k)
		}
	}
	for k := range b {
		if _, ok := a[k]; !ok {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// ---- read endpoints ----------------------------------------------------------------

func (s *Server) schema(w http.ResponseWriter, r *http.Request) {
	host, _ := os.Hostname()
	writeJSON(w, map[string]any{
		"dns":            plugin.DNSDescriptors(),
		"eab_cas":        acme.CAPresets, // CAs that need External Account Binding, with their directory URLs
		"alert_types":    notify.Types,   // what the Alerts card lets each channel receive
		"targets":        plugin.TargetDescriptors(),
		"allow_commands": plugin.GetOptions().AllowCommands,
		"hostname":       host, // names the "(This server)" target
	})
}

func (s *Server) state(w http.ResponseWriter, r *http.Request) {
	db := s.St.Snapshot()
	db.AdminHash = ""
	users := publicUsers(&db) // names only: never password hashes
	db.Users = nil
	db.Alerts = nil
	// Go encodes a nil slice as null, which the UI would trip over on a fresh install.
	if db.DNSProviders == nil {
		db.DNSProviders = []model.DNSProvider{}
	}
	if db.Certificates == nil {
		db.Certificates = []model.Certificate{}
	}
	if db.Targets == nil {
		db.Targets = []model.Target{}
	}
	if db.Events == nil {
		db.Events = []model.Event{}
	}
	if db.PendingDNS == nil {
		db.PendingDNS = []model.PendingDNS{}
	}
	if db.Settings.SMTP.Password != "" {
		db.Settings.SMTP.Password = secret.Mask
	}
	for i := range db.DNSProviders {
		if p, ok := plugin.DNS(db.DNSProviders[i].Kind); ok {
			db.DNSProviders[i].Config = mask(p.Descriptor(), db.DNSProviders[i].Config)
		}
		if db.DNSProviders[i].EABHMAC != "" {
			db.DNSProviders[i].EABHMAC = secret.Mask
		}
	}
	for i := range db.Targets {
		if p, ok := plugin.TargetFor(db.Targets[i].Kind); ok {
			db.Targets[i].Config = mask(p.Descriptor(), db.Targets[i].Config)
		}
	}
	// Certificate events and administrative actions are separate lists. Administrative events written
	// by earlier versions (subject "security") are folded into the audit log.
	var ev []model.Event
	audit := append([]model.AuditEntry(nil), db.Audit...)
	for _, e := range db.Events {
		if e.Subject == "security" {
			audit = append(audit, model.AuditEntry{Time: e.Time, Action: "event", Detail: e.Message})
			continue
		}
		ev = append(ev, e)
	}
	// newest first, capped for the UI
	sort.SliceStable(ev, func(i, j int) bool { return ev[i].Time.After(ev[j].Time) })
	if len(ev) > 100 {
		ev = ev[:100]
	}
	sort.SliceStable(audit, func(i, j int) bool { return audit[i].Time.After(audit[j].Time) })
	if len(audit) > 300 {
		audit = audit[:300]
	}
	if ev == nil {
		ev = []model.Event{}
	}
	if audit == nil {
		audit = []model.AuditEntry{}
	}
	db.Events, db.Audit = ev, audit
	out := map[string]any{"now": time.Now(), "me": userFrom(r), "users": users, "ui_cert": uiCertInfo(), "db": db, "version": s.Version}
	if s.Updates != nil {
		out["update"] = s.Updates.Last()
	}
	writeJSON(w, out)
}

// SetUpdates tells the server which version is running and where to look for newer ones.
func (s *Server) SetUpdates(version string, c *update.Checker) {
	s.Version, s.Updates = version, c
}

// checkUpdate looks for a newer release now, whatever the automatic setting says. Repeated clicks
// within a few seconds get the answer already held, so the release host is not hammered.
func (s *Server) checkUpdate(w http.ResponseWriter, r *http.Request) {
	if s.Updates == nil {
		fail(w, http.StatusServiceUnavailable, "update checks are not available in this build")
		return
	}
	if last := s.Updates.Last(); !last.CheckedAt.IsZero() && time.Since(last.CheckedAt) < 10*time.Second {
		writeJSON(w, last)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	info := s.Updates.Check(ctx)
	s.audit(r, "update.check", "software", updateDetail(info))
	writeJSON(w, info)
}

// updateDetail words the outcome of an update check for the audit log: what was found, nothing more.
func updateDetail(info update.Info) string {
	switch {
	case info.Error != "":
		return "failed: " + info.Error
	case info.Available:
		return "version " + strings.TrimPrefix(info.Latest, "v") + " is available (running " + info.Current + ")"
	case info.Latest != "":
		return "up to date (latest release " + strings.TrimPrefix(info.Latest, "v") + ", running " + info.Current + ")"
	}
	return "no release information"
}

// AutoCheckUpdates runs the automatic check: once a day, an hour after a failure, and not at all
// when the administrator switched it off. It returns when ctx ends.
func (s *Server) AutoCheckUpdates(ctx context.Context) {
	if s.Updates == nil {
		return
	}
	timer := time.NewTimer(time.Minute) // not at the very start: let the service settle first
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		s.autoCheckOnce(ctx)
		timer.Reset(15 * time.Minute)
	}
}

func (s *Server) autoCheckOnce(ctx context.Context) {
	var disabled bool
	s.St.View(func(db *model.DB) { disabled = db.Settings.UpdateCheckDisabled })
	if disabled || !update.Due(s.Updates.Last(), time.Now()) {
		return
	}
	before := s.Updates.Last().Latest
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	info := s.Updates.Check(cctx)
	s.auditAutoCheck(info)
	switch {
	case info.Error != "":
		s.Log.Info("update check failed", "err", info.Error)
	case info.Available && info.Latest != before:
		s.Log.Info("a newer version is available", "current", info.Current, "latest", info.Latest)
	}
}

// auditAutoCheck records an automatic check in the audit log (with no user: CertSmith did it). A check
// that keeps failing for the same reason, hourly, is recorded once and then again after a day, so the
// log is not filled with the same line.
func (s *Server) auditAutoCheck(info update.Info) {
	if info.Error != "" {
		if info.Error == s.autoAuditErr && time.Since(s.autoAuditAt) < 24*time.Hour {
			return
		}
		s.autoAuditErr, s.autoAuditAt = info.Error, time.Now()
	} else {
		s.autoAuditErr = ""
	}
	s.St.AddAudit(model.AuditEntry{Action: "update.check", Subject: "software", Detail: "automatic: " + updateDetail(info)})
}

// ---- settings ------------------------------------------------------------------------

func (s *Server) putSettings(w http.ResponseWriter, r *http.Request) {
	var in model.Settings
	if !decode(w, r, &in) {
		return
	}
	switch d := in.ACMEDirectory; {
	case d == model.DirProduction, d == model.DirStaging, d == model.DirSelfSigned, strings.HasPrefix(d, "https://"):
	default:
		fail(w, 400, "ACME directory must be production, staging, selfsigned or an https:// URL")
		return
	}
	var resolvers []string
	for _, entry := range in.DNSResolvers {
		n, err := normResolver(entry)
		if err != nil {
			fail(w, 400, err.Error())
			return
		}
		if n != "" {
			resolvers = append(resolvers, n)
		}
	}
	in.DNSResolvers = resolvers
	proxies, _, perr := parseProxies(in.TrustedProxies)
	if perr != nil {
		fail(w, 400, "trusted proxies: "+perr.Error())
		return
	}
	in.TrustedProxies = proxies
	switch in.DNSCheck {
	case "auto", "check", "wait":
	case "":
		in.DNSCheck = "auto"
	default:
		fail(w, 400, "DNS check must be auto, check or wait")
		return
	}
	if in.DNSWaitSeconds == 0 {
		in.DNSWaitSeconds = 25
	}
	in.DNSWaitSeconds = clamp(in.DNSWaitSeconds, 5, 300)
	in.RenewBeforeDays = clamp(in.RenewBeforeDays, 1, 60)
	in.KeepOnDevice = clamp(model.KeepOnDeviceOrDefault(in.KeepOnDevice), 1, 20)
	in.WarnDays = clamp(in.WarnDays, 1, 90)
	in.ProbeMinutes = clamp(in.ProbeMinutes, 1, 1440)
	in.ACMEEmail = strings.TrimSpace(in.ACMEEmail)
	if in.ACMEEmail != "" && !emailRe.MatchString(in.ACMEEmail) {
		fail(w, 400, "that does not look like an email address")
		return
	}
	if in.SMTP.Enabled {
		if in.SMTP.Host == "" || in.SMTP.From == "" || len(in.SMTP.To) == 0 {
			fail(w, 400, "email needs a host, From address and at least one recipient")
			return
		}
		if in.SMTP.Port == 0 {
			in.SMTP.Port = 587
		}
	}
	if u := strings.TrimSpace(in.WebhookURL); u != "" && !strings.HasPrefix(u, "http") {
		fail(w, 400, "webhook URL must start with http:// or https://")
		return
	}
	if in.AlertRouting != nil {
		clean := func(ids []string) ([]string, error) {
			seen := map[string]bool{}
			out := []string{}
			for _, id := range ids {
				if !notify.Known(id) {
					return nil, fmt.Errorf("unknown alert type %q", id)
				}
				if !seen[id] {
					seen[id] = true
					out = append(out, id)
				}
			}
			sort.Strings(out)
			return out, nil
		}
		var err error
		if in.AlertRouting.Email, err = clean(in.AlertRouting.Email); err != nil {
			fail(w, 400, err.Error())
			return
		}
		if in.AlertRouting.Webhook, err = clean(in.AlertRouting.Webhook); err != nil {
			fail(w, 400, err.Error())
			return
		}
	}
	var changed []string
	err := s.St.Update(func(db *model.DB) error {
		if in.SMTP.Password == secret.Mask {
			in.SMTP.Password = db.Settings.SMTP.Password
		} else {
			in.SMTP.Password = s.Box.Seal(in.SMTP.Password)
		}
		changed = changedFields(db.Settings, in)
		db.Settings = in
		return nil
	})
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	if len(changed) > 0 {
		s.audit(r, "settings.update", "", "changed: "+strings.Join(changed, ", "))
		s.notifyAdmin(notify.SettingsChanged, "[CertSmith] settings changed",
			fmt.Sprintf("%s changed these settings: %s.", userFrom(r), strings.Join(changed, ", ")))
	}
	s.Eng.Kick()
	writeJSON(w, map[string]bool{"ok": true})
}

func clamp(v, lo, hi int) int { return min(max(v, lo), hi) }

func (s *Server) testAlert(w http.ResponseWriter, r *http.Request) {
	var in model.Settings
	if !decode(w, r, &in) {
		return
	}
	// use the submitted form values, falling back to the stored password
	if in.SMTP.Password == secret.Mask || in.SMTP.Password == "" {
		in.SMTP.Password = s.St.Snapshot().Settings.SMTP.Password
	} else {
		in.SMTP.Password = s.Box.Seal(in.SMTP.Password)
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	if err := s.Eng.SendTest(ctx, in); err != nil {
		fail(w, 400, err.Error())
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

// ---- DNS providers -------------------------------------------------------------------

func (s *Server) saveDNS(w http.ResponseWriter, r *http.Request) {
	var in model.DNSProvider
	if !decode(w, r, &in) {
		return
	}
	in.Kind = strings.TrimSpace(in.Kind)
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		fail(w, 400, "name is required")
		return
	}
	// A provider normally carries DNS credentials. Only one at a CA that validates domains in its
	// account may do without (normProvider decides); it then has no DNS provider type at all.
	var p plugin.DNSProvider
	var cfg map[string]string
	if in.Kind != "" {
		var ok bool
		if p, ok = plugin.DNS(in.Kind); !ok {
			fail(w, 400, "unknown DNS provider type")
			return
		}
		var err error
		if cfg, err = p.Descriptor().Validate(in.Config); err != nil {
			fail(w, 400, err.Error())
			return
		}
	}
	id := r.PathValue("id")
	var savedID string
	err := s.St.Update(func(db *model.DB) error {
		in.ID = id
		var old map[string]string
		idx := -1
		for i := range db.DNSProviders {
			if db.DNSProviders[i].ID == id {
				idx, old = i, db.DNSProviders[i].Config
			}
		}
		if id != "" && idx < 0 {
			return fmt.Errorf("not found")
		}
		var oldP *model.DNSProvider
		if idx >= 0 {
			oldP = &db.DNSProviders[idx]
		}
		if err := s.normProvider(&in, oldP); err != nil {
			return err
		}
		if in.Kind != "" {
			in.Config = s.merge(p.Descriptor(), cfg, old)
		} else {
			in.Config = nil
		}
		if idx >= 0 {
			db.DNSProviders[idx] = in
		} else {
			in.ID = store.NewID()
			db.DNSProviders = append(db.DNSProviders, in)
		}
		savedID = in.ID
		return nil
	})
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true, "id": savedID}) // the cert dialog creates credentials inline and needs the id
}

// normProvider validates the certificate authority part of a provider and prepares it for storage:
// Let's Encrypt providers carry nothing but their DNS credentials; an EAB provider needs the CA's
// directory and the key the CA issued, and the HMAC key is stored sealed (a masked value on an edit
// keeps the stored one). old is the provider as stored, if it is being edited.
func (s *Server) normProvider(in *model.DNSProvider, old *model.DNSProvider) error {
	return s.normProviderFor(in, old, true)
}

// normProviderFor is normProvider with the DNS credentials optional: checking a CA account never
// touches DNS, so it must not demand credentials that only issuing needs.
func (s *Server) normProviderFor(in *model.DNSProvider, old *model.DNSProvider, needDNS bool) error {
	switch in.Authority {
	case "", model.AuthorityLE:
		in.Authority, in.CA, in.Directory, in.EABKid, in.EABHMAC, in.Email = "", "", "", "", "", ""
		if in.Kind == "" && needDNS {
			return fmt.Errorf("choose a DNS provider: Let's Encrypt validates names with DNS-01")
		}
		return nil
	case model.AuthorityEAB:
	default:
		return fmt.Errorf("unknown certificate authority type")
	}
	in.CA, in.Directory = strings.TrimSpace(in.CA), strings.TrimSpace(in.Directory)
	if in.Directory == "" {
		for _, c := range acme.CAPresets {
			if c.ID == in.CA {
				in.Directory = c.Directory
			}
		}
	}
	if in.Directory == "" {
		return fmt.Errorf("enter the CA's directory URL")
	}
	if err := acme.ValidDirectory(in.Directory); err != nil {
		return err
	}
	if in.EABKid = strings.TrimSpace(in.EABKid); in.EABKid == "" {
		return fmt.Errorf("the EAB key ID is required: the CA shows it when it creates the key")
	}
	if in.EABHMAC == secret.Mask {
		if old == nil || old.EABHMAC == "" {
			return fmt.Errorf("the EAB HMAC key is required")
		}
		in.EABHMAC = old.EABHMAC
	} else {
		n, err := acme.NormalizeHMAC(in.EABHMAC)
		if err != nil {
			return err
		}
		in.EABHMAC = s.Box.Seal(n)
	}
	if in.Email = strings.TrimSpace(in.Email); in.Email != "" && !strings.Contains(in.Email, "@") {
		return fmt.Errorf("%q is not an email address", in.Email)
	}
	if needDNS && in.Kind == "" && !acme.PreValidates(in.CA) {
		return fmt.Errorf("%s checks every name with a DNS challenge, so this provider needs DNS credentials", acme.CALabel(in.CA))
	}
	return nil
}

// checkAccount proves a provider's CA details work, for saved or not-yet-saved values, without
// issuing anything: it creates the account at the CA (with the EAB credentials) or finds it set up.
func (s *Server) checkAccount(w http.ResponseWriter, r *http.Request) {
	var in model.DNSProvider
	if !decode(w, r, &in) {
		return
	}
	var old *model.DNSProvider
	s.St.View(func(db *model.DB) {
		for i := range db.DNSProviders {
			if db.DNSProviders[i].ID == in.ID {
				cp := db.DNSProviders[i]
				old = &cp
			}
		}
	})
	if err := s.normProviderFor(&in, old, false); err != nil {
		fail(w, 400, err.Error())
		return
	}
	msg, err := s.Eng.CheckProviderAccount(r.Context(), in)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true, "message": msg})
}

// dismissPendingDNS forgets a leftover record after the user deleted it by hand.
func (s *Server) dismissPendingDNS(w http.ResponseWriter, r *http.Request) {
	s.Eng.DismissPending(r.PathValue("id"))
	writeJSON(w, map[string]bool{"ok": true})
}

// testDNS runs the end-to-end DNS check for saved or not-yet-saved credentials.
func (s *Server) testDNS(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ID          string            `json:"id"`
		Kind        string            `json:"kind"`
		Config      map[string]string `json:"config"`
		Domain      string            `json:"domain"`
		HoldSeconds int               `json:"hold_seconds"`
	}
	if !decode(w, r, &in) {
		return
	}
	kind, cfgIn := in.Kind, in.Config
	var old map[string]string
	s.St.View(func(db *model.DB) {
		for _, d := range db.DNSProviders {
			if d.ID == in.ID {
				kind, old = d.Kind, d.Config
				if cfgIn == nil { // testing saved credentials as they are
					cfgIn = d.Config
				}
			}
		}
	})
	if kind == "" {
		fail(w, 400, "this provider has no DNS credentials, so there is no DNS challenge to test")
		return
	}
	p, ok := plugin.DNS(kind)
	if !ok {
		fail(w, 400, "unknown DNS provider type")
		return
	}
	cfg, err := p.Descriptor().Validate(cfgIn)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Minute)
	defer cancel()
	steps, err := s.Eng.TestDNS(ctx, kind, s.merge(p.Descriptor(), cfg, old), in.Domain, time.Duration(clamp(in.HoldSeconds, 0, 120))*time.Second)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	ok = true
	for _, st := range steps {
		if !st.OK && !st.Info {
			ok = false
		}
	}
	writeJSON(w, map[string]any{"ok": ok, "steps": steps})
}

func (s *Server) deleteDNS(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	err := s.St.Update(func(db *model.DB) error {
		for _, c := range db.Certificates {
			if c.DNSID == id {
				return fmt.Errorf("in use by certificate %q", c.Name)
			}
		}
		for i := range db.DNSProviders {
			if db.DNSProviders[i].ID == id {
				db.DNSProviders = append(db.DNSProviders[:i], db.DNSProviders[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("not found")
	})
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

// ---- certificates --------------------------------------------------------------------

func (s *Server) saveCert(w http.ResponseWriter, r *http.Request) {
	var in model.Certificate
	if !decode(w, r, &in) {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		fail(w, 400, "name is required")
		return
	}
	// An imported certificate's names, key and dates come from the file: only its label and whether it is
	// in use can be edited. (Its names must not be rewritten to something the certificate does not cover.)
	if eid := r.PathValue("id"); eid != "" {
		imported, found := false, false
		_ = s.St.Update(func(db *model.DB) error {
			for i := range db.Certificates {
				if c := &db.Certificates[i]; c.ID == eid {
					found, imported = true, c.Source == model.SourceImport
					if imported {
						c.Name, c.Enabled = in.Name, in.Enabled
					}
				}
			}
			return nil
		})
		if found && imported {
			s.Eng.Kick()
			writeJSON(w, map[string]string{"ok": "true", "id": eid})
			return
		}
	}
	doms, err := normDomains(in.Domains)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	in.Domains = doms
	switch in.KeyType {
	case "rsa2048", "rsa3072", "rsa4096", "ec256", "ec384":
	case "":
		in.KeyType = "rsa2048"
	default:
		fail(w, 400, "unknown key type")
		return
	}
	id := r.PathValue("id")
	var newID string
	err = s.St.Update(func(db *model.DB) error {
		if in.DNSID != "" {
			found := false
			for _, d := range db.DNSProviders {
				found = found || d.ID == in.DNSID
			}
			if !found {
				return fmt.Errorf("certificate provider not found")
			}
		} else if db.Settings.ACMEDirectory != model.DirSelfSigned { // the built-in test CA validates nothing
			return fmt.Errorf("choose a certificate provider: CertSmith validates every name with DNS-01, which covers plain host names and wildcards alike (add one under Certificate providers first)")
		}
		for i := range db.Certificates {
			if db.Certificates[i].ID == id {
				c := &db.Certificates[i]
				c.Name, c.Domains, c.DNSID, c.KeyType = in.Name, in.Domains, in.DNSID, in.KeyType
				c.Enabled, c.AutoRenew = in.Enabled, in.AutoRenew
				c.PropagationSeconds = clamp(in.PropagationSeconds, 0, 3600)
				return nil
			}
		}
		if id != "" {
			return fmt.Errorf("not found")
		}
		in.ID = store.NewID()
		newID = in.ID
		in.Serial, in.LastError, in.ForceIssue = "", "", false
		in.PropagationSeconds = clamp(in.PropagationSeconds, 0, 3600)
		db.Certificates = append(db.Certificates, in)
		return nil
	})
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	s.Eng.Kick()
	writeJSON(w, map[string]string{"ok": "true", "id": newID})
}

func (s *Server) deleteCert(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	err := s.St.Update(func(db *model.DB) error {
		for _, t := range db.Targets {
			if t.CertID == id {
				return fmt.Errorf("still used by target %q - remove or repoint it first", t.Name)
			}
		}
		for i := range db.Certificates {
			if db.Certificates[i].ID == id {
				db.Certificates = append(db.Certificates[:i], db.Certificates[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("not found")
	})
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	_ = os.RemoveAll(filepath.Join(s.DataDir, "certs", filepath.Base(id)))
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) renewCert(w http.ResponseWriter, r *http.Request) {
	var imported bool
	s.St.View(func(db *model.DB) {
		for _, c := range db.Certificates {
			if c.ID == r.PathValue("id") && c.Source == model.SourceImport {
				imported = true
			}
		}
	})
	if imported {
		fail(w, http.StatusConflict, "an imported certificate is replaced, not renewed: upload the new certificate instead")
		return
	}
	if err := s.Eng.StartIssue(r.PathValue("id")); err != nil {
		startFailed(w, err)
		return
	}
	w.WriteHeader(http.StatusAccepted)
	writeJSON(w, map[string]bool{"started": true})
}

func (s *Server) cancelCert(w http.ResponseWriter, r *http.Request) {
	if err := s.Eng.CancelIssue(r.PathValue("id")); err != nil {
		fail(w, http.StatusConflict, "no issuance is running for this certificate")
		return
	}
	writeJSON(w, map[string]bool{"stopping": true})
}

func startFailed(w http.ResponseWriter, err error) {
	if errors.Is(err, engine.ErrBusy) {
		fail(w, http.StatusConflict, "already running - wait for it to finish")
		return
	}
	fail(w, http.StatusNotFound, err.Error())
}

// certLog serves the most recent ACME log for a certificate: lego's own output
// plus CertSmith's step lines. It never contains credentials.
func (s *Server) certLog(w http.ResponseWriter, r *http.Request) {
	txt, err := s.Eng.IssueLog(r.PathValue("id"))
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(txt))
}

// ---- targets ---------------------------------------------------------------------------

func (s *Server) saveTarget(w http.ResponseWriter, r *http.Request) {
	var in model.Target
	if !decode(w, r, &in) {
		return
	}
	p, ok := plugin.TargetFor(in.Kind)
	if !ok {
		fail(w, 400, "unknown target type")
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		fail(w, 400, "name is required")
		return
	}
	if in.CertID == "" && in.Kind != "watch" {
		fail(w, 400, "choose a certificate")
		return
	}
	cfg, err := p.Descriptor().Validate(in.Config)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	id := r.PathValue("id")
	err = s.St.Update(func(db *model.DB) error {
		if in.CertID != "" {
			found := false
			for _, c := range db.Certificates {
				found = found || c.ID == in.CertID
			}
			if !found {
				return fmt.Errorf("certificate not found")
			}
		}
		idx := -1
		var old map[string]string
		for i := range db.Targets {
			if db.Targets[i].ID == id {
				idx, old = i, db.Targets[i].Config
			}
		}
		if id != "" && idx < 0 {
			return fmt.Errorf("not found")
		}
		merged := s.merge(p.Descriptor(), cfg, old)
		if idx >= 0 {
			t := &db.Targets[idx]
			// the form fills in each field's default; apply the same defaults to what was stored,
			// or every save would look like a change
			current, _ := p.Descriptor().Validate(t.Config)
			if t.CertID != in.CertID || t.Kind != in.Kind || !sameConfig(current, merged) {
				// different certificate or settings: it has to be deployed by hand again
				t.DeployedSerial, t.DeployedAt, t.LastError, t.Probes, t.AutoDeploy, t.Paused = "", time.Time{}, "", nil, false, false
			}
			t.Name, t.Kind, t.CertID, t.Enabled, t.Config = in.Name, in.Kind, in.CertID, in.Enabled, merged
			return nil
		}
		in.ID, in.Config = store.NewID(), merged
		in.DeployedSerial, in.LastError = "", ""
		db.Targets = append(db.Targets, in)
		return nil
	})
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	s.Eng.Kick()
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) deleteTarget(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	err := s.St.Update(func(db *model.DB) error {
		for i := range db.Targets {
			if db.Targets[i].ID == id {
				db.Targets = append(db.Targets[:i], db.Targets[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("not found")
	})
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	s.Eng.ForgetCalls(id)
	writeJSON(w, map[string]bool{"ok": true})
}

// pauseTarget pauses or resumes automatic deployment of renewals to a target. Only a target that
// has been deployed to has anything to pause: until then every deployment is manual anyway.
func (s *Server) pauseTarget(pause bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		err := s.St.Update(func(db *model.DB) error {
			for i := range db.Targets {
				if db.Targets[i].ID != id {
					continue
				}
				if !db.Targets[i].AutoDeploy {
					return fmt.Errorf("nothing to pause: this target has not been deployed to yet")
				}
				db.Targets[i].Paused = pause
				return nil
			}
			return fmt.Errorf("not found")
		})
		if err != nil {
			fail(w, 400, err.Error())
			return
		}
		s.St.AddEvent("info", "targets", fmt.Sprintf("automatic deployment %s for target %s", map[bool]string{true: "paused", false: "resumed"}[pause], id))
		if !pause {
			s.Eng.Kick() // catch up straight away on anything renewed while paused
		}
		writeJSON(w, map[string]bool{"ok": true})
	}
}

func (s *Server) deployTarget(w http.ResponseWriter, r *http.Request) {
	if err := s.Eng.StartDeploy(r.PathValue("id")); err != nil {
		startFailed(w, err)
		return
	}
	w.WriteHeader(http.StatusAccepted)
	writeJSON(w, map[string]bool{"started": true})
}

// testTarget checks connectivity/credentials for the submitted (unsaved) form values.
// discoverTarget asks a device what it uses certificates for, without changing it: the answer fills
// the choices in the target dialog (for a FortiGate, its ZTNA servers).
func (s *Server) discoverTarget(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ID     string            `json:"id"`
		Kind   string            `json:"kind"`
		Config map[string]string `json:"config"`
	}
	if !decode(w, r, &in) {
		return
	}
	p, ok := plugin.TargetFor(in.Kind)
	if !ok {
		fail(w, 400, "unknown target type")
		return
	}
	var old map[string]string
	var trusted string
	s.St.View(func(db *model.DB) {
		for _, t := range db.Targets {
			if t.ID == in.ID {
				old, trusted = t.Config, t.DeployedSHA256
			}
		}
	})
	cfg, err := p.Descriptor().Validate(in.Config)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	stored := s.merge(p.Descriptor(), cfg, old)
	res, calls, err := s.Eng.DiscoverTarget(r.Context(), in.ID, in.Kind, stored, trusted)
	if err != nil {
		// a device whose certificate cannot be verified: send its details so the dialog can ask, as for a test
		if info := s.Eng.UntrustedCert(r.Context(), in.Kind, stored, err); info != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "the device's certificate is not trusted", "untrusted": info})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": err.Error(), "calls": calls})
		return
	}
	writeJSON(w, map[string]any{"result": res, "calls": calls})
}

func (s *Server) testTarget(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ID     string            `json:"id"`
		Kind   string            `json:"kind"`
		Config map[string]string `json:"config"`
	}
	if !decode(w, r, &in) {
		return
	}
	p, ok := plugin.TargetFor(in.Kind)
	if !ok {
		fail(w, 400, "unknown target type")
		return
	}
	var old map[string]string
	var trusted string
	s.St.View(func(db *model.DB) {
		for _, t := range db.Targets {
			if t.ID == in.ID {
				old, trusted = t.Config, t.DeployedSHA256
			}
		}
	})
	cfg, err := p.Descriptor().Validate(in.Config)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	stored := s.merge(p.Descriptor(), cfg, old)
	msg, calls, err := s.Eng.TestTargetCalls(r.Context(), in.ID, in.Kind, stored, trusted)
	if err != nil {
		// A device with a certificate we cannot verify (a FortiGate before it has a real
		// one) is not a failure to hide: send its details so the UI can ask whether to trust it.
		if info := s.Eng.UntrustedCert(r.Context(), in.Kind, stored, err); info != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":     "the device's certificate is not trusted",
				"untrusted": info,
			})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": err.Error(), "calls": calls})
		return
	}
	writeJSON(w, map[string]any{"message": msg, "calls": calls})
}

// targetCalls returns the API calls made to a target, oldest first.
func (s *Server) targetCalls(w http.ResponseWriter, r *http.Request) {
	calls, err := s.Eng.TargetCalls(r.PathValue("id"))
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	if calls == nil {
		calls = []model.APICall{}
	}
	writeJSON(w, map[string]any{"calls": calls})
}

// probe checks every enabled target's endpoints now and answers when it has finished, with how many
// endpoints were checked and how many need attention, so the page can say so. It runs on its own
// context: a reader who navigates away does not leave the results half written.
func (s *Server) probe(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	s.Eng.ProbeAll(ctx)
	var sum probeSummary
	s.St.View(func(db *model.DB) { sum = summariseProbes(db.Targets) })
	writeJSON(w, sum)
}

// probeSummary is the outcome of an endpoint check.
type probeSummary struct {
	Targets  int `json:"targets"`  // enabled targets that have endpoints
	Checked  int `json:"checked"`  // endpoints with a result
	Problems int `json:"problems"` // endpoints that could not be reached, or serve the wrong certificate
}

// summariseProbes counts the latest results the way the page marks them: an endpoint is a problem when
// it gave an error, or when it serves a different certificate than the one deployed to it.
func summariseProbes(targets []model.Target) probeSummary {
	var sum probeSummary
	for _, t := range targets {
		if !t.Enabled || len(t.Probes) == 0 {
			continue
		}
		sum.Targets++
		for _, p := range t.Probes {
			sum.Checked++
			if p.Error != "" || (!p.Match && t.CertID != "") {
				sum.Problems++
			}
		}
	}
	return sum
}
