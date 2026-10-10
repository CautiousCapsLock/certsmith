package engine

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/CautiousCapsLock/certsmith/internal/model"
)

// An imported certificate is replaced by uploading a new one. Nothing may try to issue it, however
// close to expiry it is and whatever the flags say: there is no certificate provider behind it.
func markImported(e *Engine, notAfter time.Time) {
	_ = e.St.Update(func(db *model.DB) error {
		c := &db.Certificates[0]
		c.Source, c.Serial, c.NotAfter = model.SourceImport, "abc123", notAfter
		c.IssuedDomains = c.Domains
		c.DNSID, c.AutoRenew, c.ForceIssue = "", true, true // as hostile as it gets
		return nil
	})
}

func TestTheSchedulerNeverIssuesAnImportedCertificate(t *testing.T) {
	e := newEngine(t)
	ri := &recordingIssuer{dir: e.DataDir}
	e.issuer = ri
	markImported(e, time.Now().Add(24*time.Hour)) // about to expire, forced, auto-renew on

	e.Reconcile(context.Background())

	if len(ri.reqs) != 0 {
		t.Fatalf("the issuer was asked to issue an imported certificate: %+v", ri.reqs)
	}
	c := cert(e)
	if !c.LastAttempt.IsZero() || c.LastError != "" || c.Serial != "abc123" {
		t.Errorf("the imported certificate was touched: %+v", c)
	}
}

func TestIssuingAnImportedCertificateIsRefusedWithoutSideEffects(t *testing.T) {
	e := newEngine(t)
	ri := &recordingIssuer{dir: e.DataDir}
	e.issuer = ri
	markImported(e, time.Now().Add(90*24*time.Hour))

	err := e.Issue(context.Background(), "c1")
	if err == nil || !strings.Contains(err.Error(), "replaced, not issued") {
		t.Fatalf("got %v", err)
	}
	if len(ri.reqs) != 0 {
		t.Fatal("the issuer was reached")
	}
	if c := cert(e); !c.LastAttempt.IsZero() || c.LastError != "" {
		t.Errorf("a refused issuance must leave no trace on the certificate: %+v", c)
	}
}

func TestACertificateThatIsNotImportedStillIssues(t *testing.T) {
	e := newEngine(t)
	if err := e.Issue(context.Background(), "c1"); err != nil {
		t.Fatalf("a normal certificate stopped issuing: %v", err)
	}
	if c := cert(e); c.Source != "" || c.Serial == "" {
		t.Errorf("%+v", c)
	}
}
