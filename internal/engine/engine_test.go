package engine

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/CautiousCapsLock/certsmith/internal/acme"
	"github.com/CautiousCapsLock/certsmith/internal/model"
	"github.com/CautiousCapsLock/certsmith/internal/plugin"
	"github.com/CautiousCapsLock/certsmith/internal/secret"
	"github.com/CautiousCapsLock/certsmith/internal/store"

	_ "github.com/CautiousCapsLock/certsmith/internal/dns"     // the DNS credentials the certificates use
	_ "github.com/CautiousCapsLock/certsmith/internal/targets" // the "files" target used below
)

func init() {
	settleAfterDeploy = 10 * time.Millisecond
	interceptCheck = func(context.Context) (bool, string) { return false, "" } // tests must not probe the network
}

func newEngine(t *testing.T) *Engine {
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
	_ = st.Update(func(db *model.DB) error {
		db.Settings.ACMEDirectory = model.DirSelfSigned
		db.Settings.ACMEEmail = "t@example.com"
		db.Certificates = append(db.Certificates, model.Certificate{
			ID: "c1", Name: "lab", Domains: []string{"lab.example"}, KeyType: "ec256", Enabled: true, AutoRenew: true})
		return nil
	})
	return New(st, box, dir, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// addCredentials gives the test certificate DNS credentials, which every certificate needs
// except under the built-in test CA.
func addCredentials(e *Engine) {
	_ = e.St.Update(func(db *model.DB) error {
		db.DNSProviders = append(db.DNSProviders, model.DNSProvider{ID: "d1", Name: "CF", Kind: "cloudflare", Config: map[string]string{"api_token": "t"}})
		db.Certificates[0].DNSID = "d1"
		return nil
	})
}

func cert(e *Engine) (c model.Certificate) {
	e.St.View(func(db *model.DB) { c = db.Certificates[0] })
	return
}

func TestIssueWritesALiveReadableLog(t *testing.T) {
	e := newEngine(t)
	if err := e.Issue(context.Background(), "c1"); err != nil {
		t.Fatal(err)
	}
	log, err := e.IssueLog("c1")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"[CERTSMITH] Issuing \"lab\"", "lab.example", "OK: issued serial"} {
		if !strings.Contains(log, want) {
			t.Errorf("log missing %q:\n%s", want, log)
		}
	}
	if c := cert(e); c.Serial == "" || c.Issuing {
		t.Fatalf("after issuing: serial=%q issuing=%v", c.Serial, c.Issuing)
	}
}

func TestSecondIssueWhileRunningIsRefused(t *testing.T) {
	e := newEngine(t)
	if _, ok := e.claim("cert", "c1"); !ok {
		t.Fatal("first claim should succeed")
	}
	if err := e.StartIssue("c1"); !errors.Is(err, ErrBusy) {
		t.Fatalf("a double click must be refused, got %v", err)
	}
	e.release("cert", "c1")
	if err := e.StartIssue("nope"); err == nil || errors.Is(err, ErrBusy) {
		t.Fatalf("unknown id should be 'not found', got %v", err)
	}
}

func TestStaleBusyFlagsClearedOnStart(t *testing.T) {
	e := newEngine(t)
	e.claim("cert", "c1") // as if the process had died mid-issuance
	e2 := New(e.St, e.Box, e.DataDir, e.Log)
	if cert(e2).Issuing {
		t.Fatal("a restart must not leave the spinner stuck on")
	}
}

func TestFailureKeepsLogAndAddsHint(t *testing.T) {
	e := newEngine(t)
	// a real (non-test-CA) directory with DNS credentials but no ACME email: the failure that people hit first
	addCredentials(e)
	_ = e.St.Update(func(db *model.DB) error {
		db.Settings.ACMEDirectory, db.Settings.ACMEEmail = model.DirProduction, ""
		return nil
	})
	if err := e.Issue(context.Background(), "c1"); err == nil {
		t.Fatal("expected failure without an ACME email")
	}
	c := cert(e)
	if !strings.Contains(c.LastError, "Hint:") || !strings.Contains(c.LastError, "Settings") {
		t.Fatalf("last_error should explain the fix: %q", c.LastError)
	}
	if log, _ := e.IssueLog("c1"); !strings.Contains(log, "FAILED") {
		t.Fatalf("log should record the failure: %q", log)
	}
}

func TestACertificateWithoutDNSCredentialsIsRefusedClearly(t *testing.T) {
	e := newEngine(t)
	setDirectory(e, "production")
	if err := e.Issue(context.Background(), "c1"); err == nil || !strings.Contains(cert(e).LastError, "no certificate provider") {
		t.Fatalf("expected a clear refusal, got err=%v last_error=%q", err, cert(e).LastError)
	}
}

// ---- confirming the record is published: ask the nameservers, or wait when DNS is intercepted ----

type capturingIssuer struct{ settle chan time.Duration }

func (c capturingIssuer) Issue(ctx context.Context, r acme.Request) (*plugin.Bundle, error) {
	c.settle <- r.SettleFor
	r.Settings.ACMEDirectory = model.DirSelfSigned
	return (&acme.Issuer{DataDir: os.TempDir()}).Issue(ctx, r)
}

func settleFor(t *testing.T, mode string, intercepted bool) time.Duration {
	t.Helper()
	e := newEngine(t)
	ci := capturingIssuer{settle: make(chan time.Duration, 1)}
	e.issuer = ci
	old := interceptCheck
	interceptCheck = func(context.Context) (bool, string) { return intercepted, "192.0.2.53" }
	t.Cleanup(func() { interceptCheck = old })
	addCredentials(e)
	_ = e.St.Update(func(db *model.DB) error {
		db.Settings.ACMEDirectory, db.Settings.DNSCheck, db.Settings.DNSWaitSeconds = model.DirProduction, mode, 25
		return nil
	})
	if err := e.Issue(context.Background(), "c1"); err != nil {
		t.Fatal(err)
	}
	return <-ci.settle
}

func TestWhetherToAskTheNameserversOrJustWaitFollowsTheSettingAndTheNetwork(t *testing.T) {
	cases := []struct {
		mode        string
		intercepted bool
		want        time.Duration
	}{
		{"auto", false, 0},                // a clean network: ask the nameservers
		{"auto", true, 25 * time.Second},  // DNS is intercepted: the answers cannot be believed, so wait
		{"check", true, 0},                // told to always ask, even if that is unreliable
		{"wait", false, 25 * time.Second}, // told to always wait
		{"", true, 25 * time.Second},      // an older database with no setting behaves as auto
	}
	for _, c := range cases {
		if got := settleFor(t, c.mode, c.intercepted); got != c.want {
			t.Errorf("mode %q, intercepted=%v: settle %v, want %v", c.mode, c.intercepted, got, c.want)
		}
	}
}

func TestHints(t *testing.T) {
	cases := map[string]string{
		"propagation: time limit exceeded: last error: authoritative nameservers: NS gwen.ns.cloudflare.com.:53 did not return the expected TXT record": "authoritative nameservers never served it",
		"cloudflare: failed to create TXT record: HTTP 403 Forbidden":                                                                                   "rejected the credentials",
		"acme: error: 429 :: urn:ietf:params:acme:error:rateLimited":                                                                                    "rate limiting",
		"dial tcp: lookup acme-v02.api.letsencrypt.org: no such host":                                                                                   "outbound access",
	}
	for in, want := range cases {
		if got := hintFor(in); !strings.Contains(got, want) {
			t.Errorf("hintFor(%q) = %q, want mention of %q", in, got, want)
		}
	}
	if hintFor("something nobody has seen before") != "" {
		t.Error("unknown errors should not get an invented hint")
	}
}

// blockingIssuer behaves like an issuance stuck waiting for DNS: it only returns
// once its context is cancelled.
type blockingIssuer struct {
	started chan struct{}
	calls   atomic.Int32
}

func (b *blockingIssuer) Issue(ctx context.Context, r acme.Request) (*plugin.Bundle, error) {
	b.calls.Add(1)
	select {
	case b.started <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return nil, errors.New("propagation: cancelled by user")
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestStopCancelsARunningIssuanceCleanly(t *testing.T) {
	e := newEngine(t)
	bi := &blockingIssuer{started: make(chan struct{}, 1)}
	e.issuer = bi

	if err := e.CancelIssue("c1"); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("stopping when idle = %v, want ErrNotRunning", err)
	}
	if err := e.StartIssue("c1"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-bi.started:
	case <-time.After(2 * time.Second):
		t.Fatal("issuance never started")
	}
	if !cert(e).Issuing {
		t.Fatal("certificate should show as issuing while it runs")
	}

	if err := e.CancelIssue("c1"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the spinner to clear", func() bool { return !cert(e).Issuing })

	c := cert(e)
	if c.LastError != "" {
		t.Errorf("a stop is not a failure, but last_error = %q", c.LastError)
	}
	if c.CancelledAt.IsZero() {
		t.Error("cancelled_at should be set")
	}
	var snap model.DB = e.St.Snapshot()
	if _, bad := desiredAlerts(&snap)["cert:c1:error"]; bad {
		t.Error("stopping an issuance must not raise a failure alert")
	}
	if log, _ := e.IssueLog("c1"); !strings.Contains(log, "CANCELLED by user") {
		t.Errorf("log should record the stop: %q", log)
	}

	// the scheduler must not restart something the user just stopped
	e.Reconcile(context.Background())
	time.Sleep(50 * time.Millisecond)
	if n := bi.calls.Load(); n != 1 {
		t.Errorf("scheduler restarted a stopped issuance (%d runs)", n)
	}
	if err := e.CancelIssue("c1"); !errors.Is(err, ErrNotRunning) {
		t.Errorf("second stop = %v, want ErrNotRunning", err)
	}
}

func TestIssueNowAfterStopIsAllowedAgain(t *testing.T) {
	e := newEngine(t)
	bi := &blockingIssuer{started: make(chan struct{}, 1)}
	e.issuer = bi
	_ = e.StartIssue("c1")
	<-bi.started
	_ = e.CancelIssue("c1")
	waitFor(t, "stop", func() bool { return !cert(e).Issuing })

	if err := e.StartIssue("c1"); err != nil {
		t.Fatalf("pressing Issue now after a stop must work, got %v", err)
	}
	<-bi.started
	if !cert(e).CancelledAt.IsZero() {
		t.Error("a new run clears the cancelled marker")
	}
	_ = e.CancelIssue("c1")
	waitFor(t, "second stop", func() bool { return !cert(e).Issuing })
}

// ---- the first deployment is a deliberate click, renewals after it are automatic ----

func TestFirstDeploymentWaitsForTheUserThenRenewalsAreAutomatic(t *testing.T) {
	e := newEngine(t)
	dir := t.TempDir()
	if err := e.Issue(context.Background(), "c1"); err != nil {
		t.Fatal(err)
	}
	_ = e.St.Update(func(db *model.DB) error {
		db.Targets = append(db.Targets, model.Target{ID: "t1", Name: "files", Kind: "files", CertID: "c1", Enabled: true,
			Config: map[string]string{"dir": dir}})
		return nil
	})
	target := func() (t model.Target) { e.St.View(func(db *model.DB) { t = db.Targets[0] }); return }
	deployedSerial := func() string { return target().DeployedSerial }

	// a certificate exists and a target is waiting for it: nothing is pushed on its own
	e.Reconcile(context.Background())
	if deployedSerial() != "" || target().AutoDeploy {
		t.Fatal("the first deployment must not start by itself")
	}
	if _, err := os.Stat(filepath.Join(dir, "fullchain.pem")); err == nil {
		t.Fatal("files were written to the target without anyone asking")
	}

	// the user presses Deploy
	if err := e.Deploy(context.Background(), "t1"); err != nil {
		t.Fatal(err)
	}
	first := cert(e).Serial
	if deployedSerial() != first || !target().AutoDeploy {
		t.Fatalf("after the manual deploy: serial=%q auto=%v", deployedSerial(), target().AutoDeploy)
	}

	// a renewal now goes out without being asked
	e.updateCert("c1", func(c *model.Certificate) { c.ForceIssue = true })
	if err := e.Issue(context.Background(), "c1"); err != nil {
		t.Fatal(err)
	}
	renewed := cert(e).Serial
	if renewed == first {
		t.Fatal("expected a new certificate")
	}
	e.Reconcile(context.Background())
	if deployedSerial() != renewed {
		t.Fatalf("renewals to an already-deployed target must be automatic: have %q want %q", deployedSerial(), renewed)
	}
}

func TestAFailedFirstDeploymentDoesNotArmAutomaticDeployment(t *testing.T) {
	e := newEngine(t)
	if err := e.Issue(context.Background(), "c1"); err != nil {
		t.Fatal(err)
	}
	_ = e.St.Update(func(db *model.DB) error {
		db.Targets = append(db.Targets, model.Target{ID: "t1", Name: "broken", Kind: "files", CertID: "c1", Enabled: true,
			Config: map[string]string{"dir": "/proc/definitely/not/writable"}})
		return nil
	})
	if err := e.Deploy(context.Background(), "t1"); err == nil {
		t.Fatal("expected the deployment to fail")
	}
	var armed bool
	e.St.View(func(db *model.DB) { armed = db.Targets[0].AutoDeploy })
	if armed {
		t.Fatal("a deployment that never worked must not switch on automatic deployment")
	}
}

// ---- changing between staging and production ----

// anyDirectory issues from the built-in test CA whatever directory is selected, so the
// directory-change rules can be tested without contacting Let's Encrypt.
type anyDirectory struct{ inner *acme.Issuer }

func (a anyDirectory) Issue(ctx context.Context, r acme.Request) (*plugin.Bundle, error) {
	r.Settings.ACMEDirectory = model.DirSelfSigned
	return a.inner.Issue(ctx, r)
}

func setDirectory(e *Engine, dir string) {
	_ = e.St.Update(func(db *model.DB) error { db.Settings.ACMEDirectory = dir; return nil })
}

func TestSwitchingDirectoryReissuesAndRedeploysToDeployedTargetsOnly(t *testing.T) {
	e := newEngine(t)
	e.issuer = anyDirectory{&acme.Issuer{DataDir: e.DataDir}}
	addCredentials(e)
	armedDir, waitingDir := t.TempDir(), t.TempDir()
	setDirectory(e, "staging")
	if err := e.Issue(context.Background(), "c1"); err != nil {
		t.Fatal(err)
	}
	if got := cert(e).IssuedDirectory; got != "staging" {
		t.Fatalf("issued directory = %q", got)
	}
	_ = e.St.Update(func(db *model.DB) error {
		db.Targets = append(db.Targets,
			model.Target{ID: "armed", Name: "deployed before", Kind: "files", CertID: "c1", Enabled: true, Config: map[string]string{"dir": armedDir}},
			model.Target{ID: "waiting", Name: "never deployed", Kind: "files", CertID: "c1", Enabled: true, Config: map[string]string{"dir": waitingDir}})
		return nil
	})
	if err := e.Deploy(context.Background(), "armed"); err != nil { // the user's one manual first deployment
		t.Fatal(err)
	}
	staging := cert(e).Serial
	deployed := func(id string) (s string) {
		e.St.View(func(db *model.DB) {
			for _, x := range db.Targets {
				if x.ID == id {
					s = x.DeployedSerial
				}
			}
		})
		return
	}

	// nothing changes while the directory stays the same
	e.Reconcile(context.Background())
	if cert(e).Serial != staging {
		t.Fatal("reissued without a reason")
	}

	// the user switches to production: the certificate is reissued and rolled out
	setDirectory(e, "production")
	e.Reconcile(context.Background())
	c := cert(e)
	if c.Serial == staging || c.IssuedDirectory != "production" {
		t.Fatalf("switching directory must reissue: serial changed=%v dir=%q", c.Serial != staging, c.IssuedDirectory)
	}
	if deployed("armed") != c.Serial {
		t.Fatalf("a target that was deployed before must receive the new certificate automatically: has %q want %q", deployed("armed"), c.Serial)
	}
	if deployed("waiting") != "" {
		t.Fatal("a target nobody has deployed to yet must still wait for the user")
	}

	// and back again later: same behaviour in the other direction
	prod := c.Serial
	setDirectory(e, "staging")
	e.Reconcile(context.Background())
	if c := cert(e); c.Serial == prod || c.IssuedDirectory != "staging" || deployed("armed") != c.Serial {
		t.Fatalf("switching back must reissue and redeploy too: %+v", c)
	}
}

func TestOldStagingCertificatesAreRecognisedWithoutARecordedDirectory(t *testing.T) {
	legacy := model.Certificate{Serial: "abc", Issuer: "(STAGING) Ersatz Emmer YR2"} // made before the directory was recorded
	if !wrongDirectory(legacy, "production") {
		t.Fatal("a staging certificate must be replaced when production is selected")
	}
	if wrongDirectory(legacy, "staging") {
		t.Fatal("no reason to reissue when staging is still selected")
	}
	if wrongDirectory(model.Certificate{Serial: "abc", Issuer: "R11"}, "production") {
		t.Fatal("an unrecorded real certificate must not be reissued out of the blue")
	}
	if wrongDirectory(model.Certificate{Issuer: ""}, "production") {
		t.Fatal("a certificate that was never issued has nothing to replace")
	}
}

func TestNewInstallsDefaultToProduction(t *testing.T) {
	if got := model.DefaultSettings().ACMEDirectory; got != model.DirProduction {
		t.Fatalf("default directory = %q", got)
	}
}

// ---- the probe notices a server that sends the certificate without its intermediate ----

func serveChain(t *testing.T, sendIntermediate bool) string {
	t.Helper()
	mk := func(cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, ca bool) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		serial, _ := rand.Int(rand.Reader, big.NewInt(1<<60))
		tpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour),
			NotAfter: time.Now().AddDate(1, 0, 0), IsCA: ca, BasicConstraintsValid: true, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
		signer, signKey := tpl, key
		if parent != nil {
			signer, signKey = parent, parentKey
		}
		der, _ := x509.CreateCertificate(rand.Reader, tpl, signer, &key.PublicKey, signKey)
		c, _ := x509.ParseCertificate(der)
		return c, key, der
	}
	root, rootKey, _ := mk("root", nil, nil, true)
	inter, interKey, interDER := mk("intermediate", root, rootKey, true)
	_, leafKey, leafDER := mk("leaf", inter, interKey, false)
	chain := [][]byte{leafDER}
	if sendIntermediate {
		chain = append(chain, interDER)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: chain, PrivateKey: leafKey}}})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = c.(*tls.Conn).Handshake(); c.Close() }()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

func TestProbeSeesWhetherTheIntermediateIsSent(t *testing.T) {
	bare := ProbeAddr(context.Background(), serveChain(t, false), "")
	if bare.Error != "" || bare.ChainLen != 1 || bare.SelfSigned {
		t.Fatalf("a CA-signed certificate sent alone: %+v", bare)
	}
	full := ProbeAddr(context.Background(), serveChain(t, true), "")
	if full.ChainLen != 2 {
		t.Fatalf("leaf plus intermediate should be 2 certificates: %+v", full)
	}

	mkDB := func(p model.ProbeResult) *model.DB {
		return &model.DB{Settings: model.DefaultSettings(), Targets: []model.Target{{ID: "t", Name: "fw", Enabled: true, Probes: []model.ProbeResult{p}}}}
	}
	if _, warn := desiredAlerts(mkDB(model.ProbeResult{Addr: "fw:443", Match: true, ChainLen: 1, NotAfter: time.Now().AddDate(0, 3, 0)}))["probe:t:fw:443:chain"]; !warn {
		t.Fatal("a bare CA-signed certificate must raise a warning")
	}
	if _, warn := desiredAlerts(mkDB(model.ProbeResult{Addr: "fw:443", Match: true, ChainLen: 2, NotAfter: time.Now().AddDate(0, 3, 0)}))["probe:t:fw:443:chain"]; warn {
		t.Fatal("a complete chain must not warn")
	}
	if _, warn := desiredAlerts(mkDB(model.ProbeResult{Addr: "fw:443", Match: true, ChainLen: 1, SelfSigned: true, NotAfter: time.Now().AddDate(0, 3, 0)}))["probe:t:fw:443:chain"]; warn {
		t.Fatal("a self-signed certificate has no intermediate to miss")
	}
}

func TestPausedTargetsAreNotUpdatedAutomaticallyAndCatchUpWhenResumed(t *testing.T) {
	e := newEngine(t)
	dir := t.TempDir()
	if err := e.Issue(context.Background(), "c1"); err != nil {
		t.Fatal(err)
	}
	_ = e.St.Update(func(db *model.DB) error {
		db.Targets = append(db.Targets, model.Target{ID: "t1", Name: "files", Kind: "files", CertID: "c1", Enabled: true, Config: map[string]string{"dir": dir}})
		return nil
	})
	if err := e.Deploy(context.Background(), "t1"); err != nil { // first deployment, by hand
		t.Fatal(err)
	}
	served := func() (s string) { e.St.View(func(db *model.DB) { s = db.Targets[0].DeployedSerial }); return }
	pause := func(p bool) { e.updateTarget("t1", func(t *model.Target) { t.Paused = p }) }

	pause(true)
	e.updateCert("c1", func(c *model.Certificate) { c.ForceIssue = true })
	if err := e.Issue(context.Background(), "c1"); err != nil { // a renewal arrives while paused
		t.Fatal(err)
	}
	renewed := cert(e).Serial
	e.Reconcile(context.Background())
	if served() == renewed {
		t.Fatal("a paused target must not be updated automatically")
	}

	pause(false) // resumed: it catches up by itself
	e.Reconcile(context.Background())
	if served() != renewed {
		t.Fatalf("after resuming, the target must receive the renewal that arrived meanwhile: has %q want %q", served(), renewed)
	}
}

func TestStageWriterDescribesWhatTheIssuanceIsDoing(t *testing.T) {
	var stages []string
	var out strings.Builder
	w := &stageWriter{w: nopCloser{&out}, set: func(s string) { stages = append(stages, s) }}
	for _, line := range []string{
		"2026/10/08 23:50:35 [INFO] [*.x] acme: Preparing to solve DNS-01\n",
		"2026/10/08 23:50:38 [INFO] Wait for propagation [timeout: 5m0s, interval: 5s]\n",
		"2026/10/08 23:50:43 [INFO] [*.x] acme: Waiting for DNS record propagation.\n", // repeats every few seconds: one change only
		"2026/10/08 23:50:48 [INFO] [*.x] acme: Waiting for DNS record propagation.\n",
		"2026/10/08 23:51:10 [INFO] [*.x] The server validated our request\n",
	} {
		w.Write([]byte(line))
	}
	want := []string{"creating the DNS record", "waiting for DNS to publish the record", "validated, finishing up"}
	if strings.Join(stages, "|") != strings.Join(want, "|") {
		t.Fatalf("stages = %v, want %v", stages, want)
	}
	if !strings.Contains(out.String(), "Preparing to solve") {
		t.Fatal("the log itself must pass through untouched")
	}
}

func TestDefaultDNSWaitIsGenerousButACertificateCanOverrideIt(t *testing.T) {
	if defaultPropagationSeconds < 300 {
		t.Fatalf("the default wait is %ds: Cloudflare was seen taking longer than 2 minutes", defaultPropagationSeconds)
	}
}
