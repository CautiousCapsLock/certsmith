package engine

import (
	"context"
	"strings"
	"testing"

	"github.com/CautiousCapsLock/certsmith/internal/acme"
	"github.com/CautiousCapsLock/certsmith/internal/model"
	"github.com/CautiousCapsLock/certsmith/internal/plugin"
)

// recordingIssuer notes every request it is asked to issue and then answers with the built-in test
// CA, so no real CA is contacted.
type recordingIssuer struct {
	dir  string
	reqs []acme.Request
}

func (r *recordingIssuer) Issue(ctx context.Context, req acme.Request) (*plugin.Bundle, error) {
	r.reqs = append(r.reqs, req)
	req.Settings.ACMEDirectory, req.Directory = model.DirSelfSigned, ""
	return (&acme.Issuer{DataDir: r.dir}).Issue(ctx, req)
}

const zerosslDir = "https://acme.zerossl.com/v2/DV90"

// addCA adds a second provider: ZeroSSL, with External Account Binding.
func addCA(e *Engine, kid, hmac string) {
	_ = e.St.Update(func(db *model.DB) error {
		db.DNSProviders = append(db.DNSProviders, model.DNSProvider{
			ID: "d2", Name: "ZeroSSL", Kind: "cloudflare", Config: map[string]string{"api_token": "t"},
			Authority: model.AuthorityEAB, CA: "zerossl", Directory: zerosslDir,
			EABKid: kid, EABHMAC: e.Box.Seal(hmac), Email: "eab@example.com"})
		return nil
	})
}

func useProvider(e *Engine, id string) {
	_ = e.St.Update(func(db *model.DB) error { db.Certificates[0].DNSID = id; return nil })
}

func TestAnEABProviderSendsItsOwnCAAndAccountToTheIssuer(t *testing.T) {
	e := newEngine(t)
	ri := &recordingIssuer{dir: e.DataDir}
	e.issuer = ri
	addCredentials(e)
	addCA(e, "kid-1", "c2VjcmV0LWhtYWM")
	setDirectory(e, model.DirProduction) // the Let's Encrypt setting must not leak into another CA's certificate
	useProvider(e, "d2")
	if err := e.Issue(context.Background(), "c1"); err != nil {
		t.Fatal(err)
	}
	req := ri.reqs[0]
	if req.Directory != zerosslDir || req.Email != "eab@example.com" {
		t.Fatalf("directory/email = %q / %q", req.Directory, req.Email)
	}
	if req.EAB == nil || req.EAB.Kid != "kid-1" || req.EAB.HMAC != "c2VjcmV0LWhtYWM" {
		t.Fatalf("EAB = %+v (the HMAC key must reach the issuer unsealed)", req.EAB)
	}
	if got := cert(e).IssuedDirectory; got != zerosslDir {
		t.Fatalf("issued directory = %q", got)
	}
	if log, _ := e.IssueLog("c1"); !strings.Contains(log, zerosslDir) || strings.Contains(log, "c2VjcmV0") {
		t.Fatalf("the log must name the CA and never show the key:\n%s", log)
	}
}

func TestALetsEncryptProviderIsUnchanged(t *testing.T) {
	e := newEngine(t)
	ri := &recordingIssuer{dir: e.DataDir}
	e.issuer = ri
	addCredentials(e)
	setDirectory(e, model.DirStaging)
	if err := e.Issue(context.Background(), "c1"); err != nil {
		t.Fatal(err)
	}
	if req := ri.reqs[0]; req.Directory != "" || req.EAB != nil || req.Email != "" {
		t.Fatalf("a Let's Encrypt provider must leave the request to Settings: %+v", req)
	}
	if got := cert(e).IssuedDirectory; got != model.DirStaging {
		t.Fatalf("issued directory = %q", got)
	}
}

func TestMovingACertificateToAnotherCAReissuesItAndLaterLetsEncryptSettingsDoNot(t *testing.T) {
	e := newEngine(t)
	e.issuer = &recordingIssuer{dir: e.DataDir}
	addCredentials(e)
	addCA(e, "kid-1", "c2VjcmV0LWhtYWM")
	setDirectory(e, model.DirProduction)
	if err := e.Issue(context.Background(), "c1"); err != nil {
		t.Fatal(err)
	}
	first := cert(e).Serial

	e.Reconcile(context.Background())
	if cert(e).Serial != first {
		t.Fatal("reissued without a reason")
	}

	useProvider(e, "d2") // now it should come from ZeroSSL
	e.Reconcile(context.Background())
	c := cert(e)
	if c.Serial == first || c.IssuedDirectory != zerosslDir {
		t.Fatalf("moving to another CA must reissue: serial changed=%v dir=%q", c.Serial != first, c.IssuedDirectory)
	}

	second := c.Serial
	setDirectory(e, model.DirStaging) // a Let's Encrypt setting: irrelevant to a ZeroSSL certificate
	e.Reconcile(context.Background())
	if cert(e).Serial != second {
		t.Fatal("changing the Let's Encrypt directory must not touch a certificate from another CA")
	}
}

func TestAnEABProviderWithoutItsCredentialsFailsClearly(t *testing.T) {
	e := newEngine(t)
	e.issuer = &recordingIssuer{dir: e.DataDir}
	addCredentials(e)
	addCA(e, "", "") // key id and HMAC both missing
	useProvider(e, "d2")
	err := e.Issue(context.Background(), "c1")
	if err == nil || !strings.Contains(cert(e).LastError, "key ID and HMAC key are both needed") {
		t.Fatalf("err=%v last_error=%q", err, cert(e).LastError)
	}
}

// A provider at a CA that validates domains in the account has no DNS credentials: the issuer gets
// a solver that refuses to answer a challenge, and the log says so.
func TestAProviderWithoutDNSCredentialsIssuesWithTheNoChallengeSolver(t *testing.T) {
	e := newEngine(t)
	ri := &recordingIssuer{dir: e.DataDir}
	e.issuer = ri
	_ = e.St.Update(func(db *model.DB) error {
		db.DNSProviders = append(db.DNSProviders, model.DNSProvider{
			ID: "d3", Name: "Sectigo", Kind: "", Authority: model.AuthorityEAB, CA: "sectigo",
			Directory: "https://acme.sectigo.com/v2/DV", EABKid: "kid-9", EABHMAC: e.Box.Seal("c2VjcmV0LWhtYWM")})
		return nil
	})
	useProvider(e, "d3")
	if err := e.Issue(context.Background(), "c1"); err != nil {
		t.Fatal(err)
	}
	req := ri.reqs[0]
	if _, ok := req.Solver.(acme.NoChallenge); !ok {
		t.Fatalf("solver = %T, want acme.NoChallenge", req.Solver)
	}
	if req.Directory != "https://acme.sectigo.com/v2/DV" || req.EAB == nil || req.EAB.Kid != "kid-9" {
		t.Fatalf("request = %+v", req)
	}
	if log, _ := e.IssueLog("c1"); !strings.Contains(log, "no DNS credentials") || strings.Contains(log, "DNS provider:") {
		t.Fatalf("the log should explain there is no DNS step:\n%s", log)
	}
}

func TestALetsEncryptProviderWithoutDNSCredentialsIsRefused(t *testing.T) {
	e := newEngine(t)
	e.issuer = &recordingIssuer{dir: e.DataDir}
	_ = e.St.Update(func(db *model.DB) error {
		db.DNSProviders = append(db.DNSProviders, model.DNSProvider{ID: "d4", Name: "Broken", Kind: ""})
		return nil
	})
	useProvider(e, "d4")
	setDirectory(e, model.DirProduction)
	if err := e.Issue(context.Background(), "c1"); err == nil || !strings.Contains(cert(e).LastError, "has no DNS credentials") {
		t.Fatalf("err=%v last_error=%q", err, cert(e).LastError)
	}
}
