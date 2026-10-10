// Package engine runs the control loop: issue/renew, deploy, probe, alert.
package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-acme/lego/v5/challenge"

	"github.com/CautiousCapsLock/certsmith/internal/acme"
	"github.com/CautiousCapsLock/certsmith/internal/model"
	"github.com/CautiousCapsLock/certsmith/internal/notify"
	"github.com/CautiousCapsLock/certsmith/internal/plugin"
	"github.com/CautiousCapsLock/certsmith/internal/secret"
	"github.com/CautiousCapsLock/certsmith/internal/store"
)

const (
	issueBackoff  = time.Hour        // after a failed issuance (Let's Encrypt limits repeated failures)
	deployBackoff = 30 * time.Minute // after a failed deployment
	alertRepeat   = 24 * time.Hour
	tickEvery     = time.Minute
)

type Engine struct {
	St      *store.Store
	Box     *secret.Box
	DataDir string
	Log     *slog.Logger

	issuer interface {
		Issue(ctx context.Context, r acme.Request) (*plugin.Bundle, error)
	}
	kick chan struct{}

	cancelMu sync.Mutex
	cancels  map[string]context.CancelFunc // running issuances, by certificate id

	wg           sync.WaitGroup // background work that must finish (and clean up) before exit
	shuttingDown atomic.Bool

	lockMu  sync.Mutex
	callsMu sync.Mutex // guards the per-target API call history files
	locks   map[string]*sync.Mutex
}

func New(st *store.Store, box *secret.Box, dataDir string, log *slog.Logger) *Engine {
	e := &Engine{St: st, Box: box, DataDir: dataDir, Log: log,
		issuer: &acme.Issuer{DataDir: dataDir}, kick: make(chan struct{}, 1), locks: map[string]*sync.Mutex{},
		cancels: map[string]context.CancelFunc{}}
	// anything marked busy belongs to a process that no longer exists
	_ = st.Update(func(db *model.DB) error {
		for _, p := range db.PendingDNS { // a test was cut short last time: say so, loudly
			db.Events = append(db.Events, model.Event{Time: time.Now(), Level: "warn", Subject: "DNS test",
				Message: fmt.Sprintf("a DNS test was interrupted and may have left TXT record %s = %s in your zone: delete it in your DNS provider's dashboard", strings.TrimSuffix(p.Fqdn, "."), p.Value)})
		}
		for i := range db.Certificates {
			db.Certificates[i].Issuing = false
		}
		for i := range db.Targets {
			db.Targets[i].Deploying = false
		}
		return nil
	})
	return e
}

// interceptCheck is a variable so tests need not probe the network.
var interceptCheck = acme.Intercepted

func clampInt(v, lo, hi, def int) int {
	if v == 0 {
		v = def
	}
	return min(max(v, lo), hi)
}

// defaultPropagationSeconds is the longest an issuance waits for the DNS record to appear
// unless the certificate says otherwise.
const defaultPropagationSeconds = 300

// settleAfterDeploy is how long a device is given to reload its web service before the
// served certificate is checked. A variable so that tests need not wait.
var settleAfterDeploy = 5 * time.Second

// ErrNotRunning is returned when there is no issuance to stop.
var ErrNotRunning = errors.New("nothing is running")

// CancelIssue stops a running issuance: the DNS wait ends at once, no further
// ACME requests are sent, and the challenge record is cleaned up.
func (e *Engine) CancelIssue(id string) error {
	e.cancelMu.Lock()
	cancel, ok := e.cancels[id]
	e.cancelMu.Unlock()
	if !ok {
		return ErrNotRunning
	}
	cancel()
	return nil
}

// ErrBusy is returned when the same certificate or target is already being worked on.
var ErrBusy = errors.New("already in progress")

// claim marks a certificate or target busy; false means it is missing or already busy.
func (e *Engine) claim(kind, id string) (found, ok bool) {
	_ = e.St.Update(func(db *model.DB) error {
		if kind == "cert" {
			for i := range db.Certificates {
				if db.Certificates[i].ID == id {
					found = true
					if !db.Certificates[i].Issuing {
						db.Certificates[i].Issuing, ok = true, true
					}
				}
			}
			return nil
		}
		for i := range db.Targets {
			if db.Targets[i].ID == id {
				found = true
				if !db.Targets[i].Deploying {
					db.Targets[i].Deploying, ok = true, true
				}
			}
		}
		return nil
	})
	return
}

func (e *Engine) release(kind, id string) {
	if kind == "cert" {
		e.updateCert(id, func(c *model.Certificate) { c.Issuing = false })
		return
	}
	e.updateTarget(id, func(t *model.Target) { t.Deploying = false })
}

func (e *Engine) start(kind, id string, run func(context.Context, string) error) error {
	found, ok := e.claim(kind, id)
	if !found {
		return fmt.Errorf("not found")
	}
	if !ok {
		return ErrBusy
	}
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		defer e.release(kind, id)
		_ = run(context.Background(), id)
	}()
	return nil
}

// Drain is called when the process is asked to stop: it cancels running issuances
// (they remove their DNS challenge records as they stop) and waits for them, so a
// restart or deployment never kills work half way and leaves records behind.
func (e *Engine) Drain(ctx context.Context) {
	e.shuttingDown.Store(true)
	e.cancelMu.Lock()
	for _, cancel := range e.cancels {
		cancel()
	}
	e.cancelMu.Unlock()
	done := make(chan struct{})
	go func() { e.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

func (e *Engine) addPending(p model.PendingDNS) {
	_ = e.St.Update(func(db *model.DB) error { db.PendingDNS = append(db.PendingDNS, p); return nil })
}

func (e *Engine) removePending(id string) {
	_ = e.St.Update(func(db *model.DB) error {
		for i := range db.PendingDNS {
			if db.PendingDNS[i].ID == id {
				db.PendingDNS = append(db.PendingDNS[:i], db.PendingDNS[i+1:]...)
			}
		}
		return nil
	})
}

// DismissPending forgets a leftover record the user has deleted by hand.
func (e *Engine) DismissPending(id string) { e.removePending(id) }

// StartIssue begins an issuance in the background; the UI shows a spinner while Issuing is set.
func (e *Engine) StartIssue(id string) error { return e.start("cert", id, e.issue) }

// StartDeploy begins a deployment in the background.
func (e *Engine) StartDeploy(id string) error { return e.start("target", id, e.deploy) }

func (e *Engine) issueLogPath(id string) string {
	return filepath.Join(e.DataDir, "certs", filepath.Base(id), "issue.log")
}

// stageWriter passes the ACME log through and turns the lines that mark a change of phase into a
// short description of what the issuance is doing, so the UI can say what it is waiting for.
type stageWriter struct {
	w    io.WriteCloser
	set  func(string)
	last string
}

func (s *stageWriter) Write(p []byte) (int, error) {
	text := string(p)
	for marker, stage := range map[string]string{
		"Preparing to solve":         "creating the DNS record",
		"Waiting for DNS record":     "waiting for DNS to publish the record",
		"DNS check:":                 "waiting for DNS to publish the record",
		"Wait for propagation":       "waiting for DNS to publish the record",
		"The server validated":       "validated, finishing up",
		"Validations succeeded":      "requesting the certificate",
		"Server responded with a ce": "done",
	} {
		if strings.Contains(text, marker) && stage != s.last {
			s.last = stage
			s.set(stage)
		}
	}
	return s.w.Write(p)
}

func (s *stageWriter) Close() error { return s.w.Close() }

type nopCloser struct{ io.Writer }

func (nopCloser) Close() error { return nil }

// openIssueLog starts a fresh log for this issuance. It is written as the run
// proceeds, so the UI can follow it live.
func (e *Engine) openIssueLog(id string) io.WriteCloser {
	path := e.issueLogPath(id)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err == nil {
		if f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600); err == nil {
			return f
		}
	}
	return nopCloser{io.Discard}
}

func logLine(w io.Writer, format string, a ...any) {
	fmt.Fprintf(w, "%s [CERTSMITH] %s\n", time.Now().Format("2006/01/02 15:04:05"), fmt.Sprintf(format, a...))
}

// IssueLog returns the most recent ACME log for a certificate (last 128 KiB).
func (e *Engine) IssueLog(id string) (string, error) {
	b, err := os.ReadFile(e.issueLogPath(id))
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if len(b) > 128<<10 {
		b = b[len(b)-128<<10:]
	}
	return string(b), nil
}

// Kick asks the loop to reconcile soon (after configuration changes).
func (e *Engine) Kick() {
	select {
	case e.kick <- struct{}{}:
	default:
	}
}

func (e *Engine) lock(id string) func() {
	e.lockMu.Lock()
	m, ok := e.locks[id]
	if !ok {
		m = &sync.Mutex{}
		e.locks[id] = m
	}
	e.lockMu.Unlock()
	m.Lock()
	return m.Unlock
}

// Run blocks until ctx is cancelled.
func (e *Engine) Run(ctx context.Context) {
	t := time.NewTicker(tickEvery)
	defer t.Stop()
	var lastProbe time.Time
	step := func() {
		e.Reconcile(ctx)
		e.probePending(ctx)
		var every time.Duration
		e.St.View(func(db *model.DB) { every = time.Duration(max(db.Settings.ProbeMinutes, 1)) * time.Minute })
		if time.Since(lastProbe) >= every {
			lastProbe = time.Now()
			e.ProbeAll(ctx)
		}
		e.CheckAlerts(ctx)
	}
	run := func() { e.wg.Add(1); defer e.wg.Done(); step() }
	select {
	case <-time.After(3 * time.Second):
		run()
	case <-ctx.Done():
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-e.kick:
		}
		run()
	}
}

// ---- decrypting plugin config ------------------------------------------------

// OpenConfig returns cfg with secret fields decrypted.
func (e *Engine) OpenConfig(d plugin.Descriptor, cfg map[string]string) (map[string]string, error) {
	sec := d.SecretKeys()
	out := make(map[string]string, len(cfg))
	for k, v := range cfg {
		if sec[k] {
			pt, err := e.Box.Unseal(v)
			if err != nil {
				return nil, err
			}
			v = pt
		}
		out[k] = v
	}
	return out, nil
}

// ---- reconcile -----------------------------------------------------------------

// providerOf returns the certificate provider a certificate uses, or nil.
func providerOf(db model.DB, c model.Certificate) *model.DNSProvider {
	if c.DNSID == "" {
		return nil
	}
	for i := range db.DNSProviders {
		if db.DNSProviders[i].ID == c.DNSID {
			return &db.DNSProviders[i]
		}
	}
	return nil
}

// directoryFor is the ACME directory a certificate comes from: its own CA's for an EAB provider,
// otherwise the Let's Encrypt directory chosen in Settings. Changing it (or moving a certificate to
// a provider at another CA) reissues the certificate, because one from a different CA is not the
// certificate that was asked for.
func directoryFor(db model.DB, c model.Certificate) string {
	if p := providerOf(db, c); p != nil && p.IsEAB() {
		return p.Directory
	}
	return db.Settings.ACMEDirectory
}

// wrongDirectory reports a certificate that came from a different ACME directory than the
// one now selected (staging versus production, say). Certificates made before this was
// recorded are recognised by their issuer's name: Let's Encrypt staging says so in it.
func wrongDirectory(c model.Certificate, selected string) bool {
	if c.Serial == "" {
		return false
	}
	from := c.IssuedDirectory
	if from == "" && strings.Contains(c.Issuer, "(STAGING)") {
		from = model.DirStaging
	}
	return from != "" && from != selected
}

func domainsEqual(a, b []string) bool {
	norm := func(x []string) string {
		c := append([]string(nil), x...)
		sort.Strings(c)
		return strings.Join(c, ",")
	}
	return norm(a) == norm(b)
}

func daysLeft(t time.Time) int {
	return int(time.Until(t).Hours() / 24)
}

func (e *Engine) Reconcile(ctx context.Context) {
	snap := e.St.Snapshot()
	now := time.Now()
	for _, c := range snap.Certificates {
		// an imported certificate is never issued or renewed here: it is replaced by uploading a new one
		if !c.Enabled || c.Source == model.SourceImport {
			continue
		}
		due := c.Serial == "" || c.ForceIssue || !domainsEqual(c.Domains, c.IssuedDomains) ||
			(c.AutoRenew && daysLeft(c.NotAfter) < snap.Settings.RenewBeforeDays) ||
			wrongDirectory(c, directoryFor(snap, c))
		if !due {
			continue
		}
		if c.LastError != "" && !c.ForceIssue && now.Sub(c.LastAttempt) < issueBackoff {
			continue
		}
		if !c.CancelledAt.IsZero() && !c.ForceIssue && now.Sub(c.CancelledAt) < issueBackoff {
			continue // the user stopped it: do not restart behind their back
		}
		_ = e.Issue(ctx, c.ID)
	}

	snap = e.St.Snapshot()
	certs := map[string]model.Certificate{}
	for _, c := range snap.Certificates {
		certs[c.ID] = c
	}
	for _, t := range snap.Targets {
		c, ok := certs[t.CertID]
		// never-deployed targets wait for the user: only renewals to an already-deployed target are automatic
		if !t.Enabled || !ok || c.Serial == "" || t.Kind == "watch" || t.DeployedSerial == c.Serial || !t.AutoDeploy || t.Paused {
			continue
		}
		if t.LastError != "" && now.Sub(t.LastAttempt) < deployBackoff {
			continue
		}
		_ = e.Deploy(ctx, t.ID)
	}
}

// ---- issuing -------------------------------------------------------------------

// propagationLimit overrides how long lego waits for the DNS-01 record to
// appear. lego polls and continues as soon as the record is visible, so this is
// a ceiling, not a fixed delay.
type propagationLimit struct {
	challenge.Provider
	wait time.Duration
}

func (p propagationLimit) Timeout() (timeout, interval time.Duration) {
	return p.wait, 5 * time.Second
}

func (e *Engine) updateCert(id string, fn func(c *model.Certificate)) {
	_ = e.St.Update(func(db *model.DB) error {
		for i := range db.Certificates {
			if db.Certificates[i].ID == id {
				fn(&db.Certificates[i])
			}
		}
		return nil
	})
}

// Issue runs an issuance in the calling goroutine (used by the scheduler).
func (e *Engine) Issue(ctx context.Context, id string) error {
	found, ok := e.claim("cert", id)
	if !found {
		return fmt.Errorf("certificate not found")
	}
	if !ok {
		return ErrBusy
	}
	defer e.release("cert", id)
	return e.issue(ctx, id)
}

func (e *Engine) issue(ctx context.Context, id string) error {
	defer e.lock("cert:" + id)()
	snap := e.St.Snapshot()
	var c *model.Certificate
	for i := range snap.Certificates {
		if snap.Certificates[i].ID == id {
			c = &snap.Certificates[i]
		}
	}
	if c == nil {
		return fmt.Errorf("certificate not found")
	}
	if c.Source == model.SourceImport {
		return errors.New("an imported certificate is replaced, not issued: upload the new certificate instead")
	}
	e.updateCert(id, func(c *model.Certificate) { c.LastAttempt = time.Now(); c.CancelledAt = time.Time{} })

	lw := &stageWriter{w: e.openIssueLog(id), set: func(stage string) {
		e.updateCert(id, func(c *model.Certificate) { c.Stage = stage })
	}}
	defer lw.Close()
	defer lw.set("")
	fail := func(err error) error {
		e.Log.Error("issue failed", "cert", c.Name, "err", err)
		logLine(lw, "FAILED: %v", err)
		msg := withHint(err)
		e.updateCert(id, func(c *model.Certificate) { c.LastError = msg })
		e.St.AddEvent("error", c.Name, "issuance failed: "+err.Error())
		return err
	}

	dir := directoryFor(snap, *c)
	logLine(lw, "Issuing %q for %s (DNS-01, %s key) from the %q ACME directory", c.Name, strings.Join(c.Domains, ", "), c.KeyType, dir)
	req := acme.Request{Name: c.Name, Domains: c.Domains, KeyType: c.KeyType, Settings: snap.Settings, Log: lw}
	if c.DNSID == "" && dir != model.DirSelfSigned { // the built-in test CA validates nothing
		return fail(errors.New("this certificate has no certificate provider: CertSmith validates names with DNS-01 only. Edit the certificate and choose a provider"))
	}
	if c.DNSID != "" {
		dp := providerOf(snap, *c)
		if dp == nil {
			return fail(fmt.Errorf("the certificate provider no longer exists"))
		}
		if dp.IsEAB() { // a CA other than Let's Encrypt, with its own account
			eab, err := e.eabFor(*dp)
			if err != nil {
				return fail(err)
			}
			req.Directory, req.Email, req.EAB = dp.Directory, dp.Email, eab
			logLine(lw, "Certificate authority: %s (account bound with EAB key %s)", dp.Directory, dp.EABKid)
		}
		if dp.Kind == "" {
			// No DNS credentials: only a CA that validates domains in the account can issue this
			if !dp.IsEAB() {
				return fail(fmt.Errorf("provider %s has no DNS credentials: add them, because Let's Encrypt validates names with DNS-01", dp.Name))
			}
			req.Solver = acme.NoChallenge{}
			logLine(lw, "This provider has no DNS credentials: the CA must already have validated these names in your account. If it asks for a DNS challenge instead, the issuance fails here.")
		} else {
			p, ok := plugin.DNS(dp.Kind)
			if !ok {
				return fail(fmt.Errorf("unknown DNS provider kind %q", dp.Kind))
			}
			cfg, err := e.OpenConfig(p.Descriptor(), dp.Config)
			if err != nil {
				return fail(err)
			}
			if req.Solver, err = p.Solver(cfg); err != nil {
				return fail(fmt.Errorf("DNS provider %s: %w", dp.Name, err))
			}
			logLine(lw, "DNS provider: %s (%s)", dp.Name, dp.Kind)
			// Providers publish at very different speeds, and the same provider varies from day to day. A
			// short limit only turns "slow" into "failed", so the default is generous: the wait ends the
			// moment the record is visible, which costs nothing when DNS is quick.
			wait := c.PropagationSeconds
			if wait <= 0 {
				wait = defaultPropagationSeconds
			}
			req.Solver = propagationLimit{Provider: req.Solver, wait: time.Duration(wait) * time.Second}
			// How to tell the record is published. Asking the zone's nameservers is the best evidence, but
			// on a network that intercepts DNS the "nameserver" answering is a cache that can hold an old
			// answer (even "no such name") for minutes, so there the check is replaced by a fixed wait.
			settle := time.Duration(clampInt(snap.Settings.DNSWaitSeconds, 5, 300, 25)) * time.Second
			switch snap.Settings.DNSCheck {
			case "wait":
				req.SettleFor = settle
				logLine(lw, "Asking the nameservers is switched off in Settings: waiting %s for the provider to publish the record", settle)
			case "check":
				logLine(lw, "Will ask the zone's nameservers until they serve the record, for up to %ds", wait)
			default: // auto
				if hit, via := interceptCheck(ctx); hit {
					req.SettleFor = settle
					logLine(lw, "This network intercepts DNS (a query sent to %s, where no DNS server lives, was answered), so the nameservers cannot be asked reliably: waiting %s for the provider to publish the record instead", via, settle)
				} else {
					logLine(lw, "Will ask the zone's nameservers until they serve the record, for up to %ds", wait)
				}
			}
		}
	}

	ictx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	e.cancelMu.Lock()
	e.cancels[id] = cancel
	e.cancelMu.Unlock()
	defer func() {
		e.cancelMu.Lock()
		delete(e.cancels, id)
		e.cancelMu.Unlock()
	}()
	b, err := e.issuer.Issue(ictx, req)
	if err != nil {
		if e.shuttingDown.Load() {
			logLine(lw, "INTERRUPTED: CertSmith is restarting; this will run again afterwards")
			return context.Canceled
		}
		if errors.Is(ictx.Err(), context.Canceled) { // only CancelIssue cancels this context
			logLine(lw, "CANCELLED by user")
			e.updateCert(id, func(c *model.Certificate) { c.CancelledAt = time.Now(); c.LastError = "" })
			e.St.AddEvent("info", c.Name, "issuance stopped by user")
			return context.Canceled
		}
		return fail(err)
	}
	if err := acme.Save(e.DataDir, id, b); err != nil {
		return fail(fmt.Errorf("save certificate: %w", err))
	}
	issuer := b.Leaf.Issuer.CommonName
	if issuer == "" && len(b.Leaf.Issuer.Organization) > 0 {
		issuer = b.Leaf.Issuer.Organization[0]
	}
	e.updateCert(id, func(c *model.Certificate) {
		c.Serial, c.Issuer, c.IssuedDirectory = b.Serial, issuer, dir
		c.NotBefore, c.NotAfter = b.NotBefore, b.NotAfter
		c.IssuedDomains = append([]string(nil), c.Domains...)
		c.LastError, c.ForceIssue = "", false
	})
	e.Log.Info("issued", "cert", c.Name, "serial", b.Serial, "expires", b.NotAfter)
	logLine(lw, "OK: issued serial %s, valid until %s", b.Serial, b.NotAfter.Format(time.RFC3339))
	e.St.AddEvent("info", c.Name, fmt.Sprintf("issued certificate %s (expires %s)", b.Serial[:min(8, len(b.Serial))], b.NotAfter.Format("2006-01-02")))
	e.Notify(ctx, notify.CertIssued, "Certificate issued: "+c.Name, fmt.Sprintf("%s issued by %s, valid until %s.", strings.Join(c.Domains, ", "), issuer, b.NotAfter.Format(time.RFC1123)))
	e.Kick() // deploy promptly
	return nil
}

// ---- deploying -----------------------------------------------------------------

func (e *Engine) updateTarget(id string, fn func(t *model.Target)) {
	_ = e.St.Update(func(db *model.DB) error {
		for i := range db.Targets {
			if db.Targets[i].ID == id {
				fn(&db.Targets[i])
			}
		}
		return nil
	})
}

// Deploy runs a deployment in the calling goroutine (used by the scheduler).
func (e *Engine) Deploy(ctx context.Context, id string) error {
	found, ok := e.claim("target", id)
	if !found {
		return fmt.Errorf("target not found")
	}
	if !ok {
		return ErrBusy
	}
	defer e.release("target", id)
	return e.deploy(ctx, id)
}

func (e *Engine) deploy(ctx context.Context, id string) error {
	defer e.lock("target:" + id)()
	snap := e.St.Snapshot()
	var t *model.Target
	for i := range snap.Targets {
		if snap.Targets[i].ID == id {
			t = &snap.Targets[i]
		}
	}
	if t == nil {
		return fmt.Errorf("target not found")
	}
	var c *model.Certificate
	for i := range snap.Certificates {
		if snap.Certificates[i].ID == t.CertID {
			c = &snap.Certificates[i]
		}
	}
	e.updateTarget(id, func(t *model.Target) { t.LastAttempt = time.Now() })
	fail := func(err error) error {
		e.Log.Error("deploy failed", "target", t.Name, "err", err)
		e.updateTarget(id, func(t *model.Target) { t.LastError = err.Error() })
		e.St.AddEvent("error", t.Name, "deployment failed: "+err.Error())
		return err
	}
	if c == nil || c.Serial == "" {
		return fail(fmt.Errorf("no issued certificate to deploy"))
	}
	p, ok := plugin.TargetFor(t.Kind)
	if !ok {
		return fail(fmt.Errorf("unknown target kind %q", t.Kind))
	}
	cfg, err := e.OpenConfig(p.Descriptor(), t.Config)
	if err != nil {
		return fail(err)
	}
	if t.DeployedSHA256 != "" {
		cfg["_trusted_sha256"] = t.DeployedSHA256 // the certificate we installed last time is the one the device now serves
	}
	b, err := acme.Load(e.DataDir, c.ID, c.Name, c.Domains)
	if err != nil {
		return fail(fmt.Errorf("load certificate: %w", err))
	}
	dctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	tr := plugin.NewTrace("deploy")
	msg, err := p.Deploy(plugin.WithTrace(dctx, tr), cfg, b)
	e.recordCalls(id, tr.Calls())
	if err != nil {
		return fail(err)
	}
	fp := sha256.Sum256(b.Leaf.Raw)
	e.updateTarget(id, func(t *model.Target) {
		t.DeployedSerial, t.DeployedAt, t.LastError, t.Message = b.Serial, time.Now(), "", msg
		t.DeployedSHA256 = hex.EncodeToString(fp[:])
		t.AutoDeploy = true // proven to work once: from now on renewals go out by themselves
	})
	e.Log.Info("deployed", "target", t.Name, "msg", msg)
	e.St.AddEvent("info", t.Name, "deployed: "+msg)
	e.Notify(ctx, notify.DeployOK, "Certificate deployed: "+t.Name, fmt.Sprintf("%s was updated with serial %s. %s", t.Name, short(b.Serial), msg))

	// give the device a moment to reload its web service, then confirm what is served
	select {
	case <-time.After(settleAfterDeploy):
	case <-ctx.Done():
	}
	e.probeTarget(ctx, id)
	return nil
}

// UntrustedCert explains a failed connection test: if the device presented a
// certificate that could not be verified, it returns that certificate's details
// so the user can decide whether to trust it. It returns nil for any other failure.
func (e *Engine) UntrustedCert(ctx context.Context, kind string, cfg map[string]string, testErr error) *plugin.CertInfo {
	if !plugin.IsTLSTrustError(testErr) {
		return nil
	}
	p, ok := plugin.TargetFor(kind)
	if !ok {
		return nil
	}
	ep, ok := p.(plugin.Endpointer)
	if !ok {
		return nil
	}
	open, err := e.OpenConfig(p.Descriptor(), cfg)
	if err != nil {
		return nil
	}
	addr := ep.APIEndpoint(open)
	if addr == "" {
		return nil
	}
	info, err := plugin.FetchCert(ctx, addr)
	if err != nil {
		return nil
	}
	return info
}

// TestTarget checks connectivity and credentials. trusted is the fingerprint of the
// certificate CertSmith last installed on this target, if any.
func (e *Engine) TestTarget(ctx context.Context, kind string, cfg map[string]string, trusted string) (string, error) {
	msg, _, err := e.TestTargetCalls(ctx, "", kind, cfg, trusted)
	return msg, err
}

// TestTargetCalls is TestTarget that also returns the API calls the test made. When id names a
// saved target they are added to its call history too.
func (e *Engine) TestTargetCalls(ctx context.Context, id, kind string, cfg map[string]string, trusted string) (string, []model.APICall, error) {
	p, ok := plugin.TargetFor(kind)
	if !ok {
		return "", nil, fmt.Errorf("unknown target kind %q", kind)
	}
	open, err := e.OpenConfig(p.Descriptor(), cfg)
	if err != nil {
		return "", nil, err
	}
	if trusted != "" {
		open["_trusted_sha256"] = trusted
	}
	tctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	tr := plugin.NewTrace("test")
	msg, err := p.Test(plugin.WithTrace(tctx, tr), open)
	calls := tr.Calls()
	if id != "" {
		e.recordCalls(id, calls)
	}
	return msg, calls, err
}

// ---- API call history ----------------------------------------------------------------------

// keepCalls is how many recent API calls are remembered per target: several deployments' worth.
const keepCalls = 300

func (e *Engine) callsPath(id string) string {
	return filepath.Join(e.DataDir, "targets", filepath.Base(id), "calls.json")
}

// recordCalls appends calls to the target's history, dropping the oldest beyond keepCalls.
func (e *Engine) recordCalls(id string, calls []model.APICall) {
	if len(calls) == 0 {
		return
	}
	e.callsMu.Lock()
	defer e.callsMu.Unlock()
	all, _ := e.readCalls(id)
	all = append(all, calls...)
	if len(all) > keepCalls {
		all = all[len(all)-keepCalls:]
	}
	b, err := json.Marshal(all)
	if err != nil {
		return
	}
	path := e.callsPath(id)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		e.Log.Warn("cannot keep API call history", "target", id, "err", err)
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o640); err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		e.Log.Warn("cannot keep API call history", "target", id, "err", err)
	}
}

func (e *Engine) readCalls(id string) ([]model.APICall, error) {
	b, err := os.ReadFile(e.callsPath(id))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []model.APICall
	return out, json.Unmarshal(b, &out)
}

// TargetCalls returns the API calls made to a target, oldest first.
func (e *Engine) TargetCalls(id string) ([]model.APICall, error) {
	e.callsMu.Lock()
	defer e.callsMu.Unlock()
	return e.readCalls(id)
}

// ForgetCalls removes a deleted target's history.
func (e *Engine) ForgetCalls(id string) {
	e.callsMu.Lock()
	defer e.callsMu.Unlock()
	_ = os.RemoveAll(filepath.Dir(e.callsPath(id)))
}

// eabFor opens a provider's stored External Account Binding credentials.
func (e *Engine) eabFor(p model.DNSProvider) (*acme.EAB, error) {
	hmac, err := e.Box.Unseal(p.EABHMAC)
	if err != nil {
		return nil, fmt.Errorf("provider %s: cannot read the stored HMAC key: %w", p.Name, err)
	}
	if strings.TrimSpace(p.EABKid) == "" || strings.TrimSpace(hmac) == "" {
		return nil, fmt.Errorf("provider %s: the EAB key ID and HMAC key are both needed", p.Name)
	}
	return &acme.EAB{Kid: p.EABKid, HMAC: hmac}, nil
}

// CheckProviderAccount proves a provider's CA details (directory, email, EAB credentials) are
// accepted, without issuing anything. p carries the HMAC key sealed, as stored.
func (e *Engine) CheckProviderAccount(ctx context.Context, p model.DNSProvider) (string, error) {
	snap := e.St.Snapshot()
	req := acme.Request{Settings: snap.Settings, KeyType: "ec256"}
	if p.IsEAB() {
		eab, err := e.eabFor(p)
		if err != nil {
			return "", err
		}
		req.Directory, req.Email, req.EAB = p.Directory, p.Email, eab
	} else if snap.Settings.ACMEDirectory == model.DirSelfSigned {
		return "the built-in test CA needs no account", nil
	}
	checker, ok := e.issuer.(interface {
		CheckAccount(ctx context.Context, r acme.Request) (string, error)
	})
	if !ok {
		return "", errors.New("this issuer cannot check accounts")
	}
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	return checker.CheckAccount(cctx, req)
}
