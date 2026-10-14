package engine

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/CautiousCapsLock/certsmith/internal/acme"
	"github.com/CautiousCapsLock/certsmith/internal/model"
)

// persistProvider adds a dns-persist-01 provider at a CA with External Account Binding. withDNS gives
// it DNS credentials too, which is what makes a fallback to DNS-01 possible.
func persistProvider(e *Engine, withDNS bool, until time.Time) {
	_ = e.St.Update(func(db *model.DB) error {
		p := model.DNSProvider{ID: "p1", Name: "Persist CA", Authority: model.AuthorityEAB, CA: acme.CustomCA,
			Directory: "https://ca.example.test/dir", EABKid: "kid", EABHMAC: e.Box.Seal("c2VjcmV0LWhtYWM"),
			Email: "p@example.com", Validation: model.ValidationPersist, PersistUntil: until}
		if withDNS {
			p.Kind, p.Config = "cloudflare", map[string]string{"api_token": "t"}
		}
		db.DNSProviders = append(db.DNSProviders, p)
		db.Certificates[0].DNSID = "p1"
		return nil
	})
}

func TestAPersistProviderAsksTheIssuerForTheStandingRecordAndNeedsNoDNSCredentials(t *testing.T) {
	e := newEngine(t)
	ri := &recordingIssuer{dir: e.DataDir}
	e.issuer = ri
	until := time.Now().Add(100 * 24 * time.Hour).UTC().Truncate(time.Second)
	persistProvider(e, false, until)
	if err := e.Issue(context.Background(), "c1"); err != nil {
		t.Fatal(err)
	}
	req := ri.reqs[0]
	if req.Persist == nil || !req.Persist.Until.Equal(until) {
		t.Fatalf("persist = %+v, want the provider's end date %s", req.Persist, until)
	}
	if _, ok := req.Solver.(acme.NoChallenge); !ok {
		t.Fatalf("solver = %T: a provider without DNS credentials must not be able to write to DNS", req.Solver)
	}
	if req.PropagationWait <= 0 {
		t.Error("the wait for a published record to be visible is not set")
	}
	log, _ := e.IssueLog("c1")
	if !strings.Contains(log, "dns-persist-01") || !strings.Contains(log, "Nothing is written to DNS") {
		t.Fatalf("the log must say how the names are validated:\n%s", log)
	}
}

func TestAPersistProviderWithDNSCredentialsKeepsThemAsTheFallback(t *testing.T) {
	e := newEngine(t)
	ri := &recordingIssuer{dir: e.DataDir}
	e.issuer = ri
	persistProvider(e, true, time.Time{})
	if err := e.Issue(context.Background(), "c1"); err != nil {
		t.Fatal(err)
	}
	req := ri.reqs[0]
	if req.Persist == nil || !req.Persist.Until.IsZero() {
		t.Fatalf("persist = %+v", req.Persist)
	}
	if req.Solver == nil {
		t.Fatal("no fallback solver")
	}
	if _, none := req.Solver.(acme.NoChallenge); none {
		t.Fatal("the provider's DNS credentials were dropped: there is no fallback")
	}
}

func TestADNS01ProviderNeverAsksForAStandingRecord(t *testing.T) {
	e := newEngine(t)
	ri := &recordingIssuer{dir: e.DataDir}
	e.issuer = ri
	addCredentials(e)
	if err := e.Issue(context.Background(), "c1"); err != nil {
		t.Fatal(err)
	}
	if ri.reqs[0].Persist != nil {
		t.Fatal("DNS-01 provider asked for dns-persist-01")
	}
}

// persistChecker answers the way the issuer does for a check.
type persistChecker struct {
	recordingIssuer
	recs []model.PersistRecord
	err  error
	got  []acme.Request
}

func (p *persistChecker) CheckPersist(_ context.Context, r acme.Request) ([]model.PersistRecord, error) {
	p.got = append(p.got, r)
	return p.recs, p.err
}

func TestCheckingTheRecordKeepsWhatWasFoundOnTheCertificate(t *testing.T) {
	e := newEngine(t)
	pc := &persistChecker{recs: []model.PersistRecord{
		{Domain: "lab.example", Name: "_validation-persist.lab.example", Value: "ca.example.test; accounturi=https://ca/acct/1", Status: model.PersistMissing},
	}}
	e.issuer = pc
	persistProvider(e, false, time.Time{})
	st, err := e.CheckPersist(context.Background(), "c1")
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Records) != 1 || st.CheckedAt.IsZero() {
		t.Fatalf("state = %+v", st)
	}
	if c := cert(e); c.Persist == nil || c.Persist.Records[0].Status != model.PersistMissing {
		t.Fatalf("stored = %+v: the page and the alerts read it from the certificate", c.Persist)
	}
	if r := pc.got[0]; r.Directory != "https://ca.example.test/dir" || r.EAB == nil || r.EAB.HMAC != "c2VjcmV0LWhtYWM" || r.Persist == nil {
		t.Fatalf("request = %+v", r)
	}
}

func TestACheckThatCannotReachTheCAIsKeptAsAnErrorNotAsAMissingRecord(t *testing.T) {
	e := newEngine(t)
	e.issuer = &persistChecker{err: errors.New("dial tcp: i/o timeout")}
	persistProvider(e, false, time.Time{})
	st, err := e.CheckPersist(context.Background(), "c1")
	if err == nil || st == nil || st.Error == "" || len(st.Records) != 0 {
		t.Fatalf("st = %+v err = %v", st, err)
	}
	var alerts map[string]alert
	e.St.View(func(db *model.DB) { alerts = desiredAlerts(db) })
	for k := range alerts {
		if strings.HasSuffix(k, ":persist") {
			t.Fatalf("an unreachable CA raised %q: only a record that is looked at and not there is an alert", k)
		}
	}
}

func TestADNS01ProviderHasNoRecordToCheck(t *testing.T) {
	e := newEngine(t)
	e.issuer = &persistChecker{}
	addCredentials(e)
	if _, err := e.CheckPersist(context.Background(), "c1"); err == nil || !strings.Contains(err.Error(), "DNS-01") {
		t.Fatalf("err = %v", err)
	}
}

func TestAlertsForARecordThatIsNotThereAndAnAuthorisationThatIsEnding(t *testing.T) {
	e := newEngine(t)
	persistProvider(e, false, time.Now().Add(10*24*time.Hour))
	_ = e.St.Update(func(db *model.DB) error {
		c := &db.Certificates[0]
		c.Serial, c.NotAfter = "abc", time.Now().Add(60*24*time.Hour)
		c.Persist = &model.PersistState{CheckedAt: time.Now(), Records: []model.PersistRecord{
			{Domain: "lab.example", Status: model.PersistMismatch},
			{Domain: "other.example", Status: model.PersistFound},
		}}
		return nil
	})
	var got map[string]alert
	e.St.View(func(db *model.DB) { got = desiredAlerts(db) })
	a, ok := got["cert:c1:persist"]
	if !ok || a.level != "warn" || !strings.Contains(a.line, "lab.example (mismatch)") || strings.Contains(a.line, "other.example") {
		t.Fatalf("record alert = %+v (%v)", a, ok)
	}
	if p, ok := got["provider:p1:persistuntil"]; !ok || p.level != "warn" {
		t.Fatalf("end-date alert = %+v (%v)", p, ok)
	}
	if alertType("cert:c1:persist") == "" || alertType("provider:p1:persistuntil") == "" {
		t.Error("the new alerts cannot be routed to a channel")
	}

	// a renewal that is close and cannot validate is urgent
	_ = e.St.Update(func(db *model.DB) error { db.Certificates[0].NotAfter = time.Now().Add(5 * 24 * time.Hour); return nil })
	e.St.View(func(db *model.DB) { got = desiredAlerts(db) })
	if got["cert:c1:persist"].level != "crit" {
		t.Errorf("level = %q, want crit with the certificate five days from expiry", got["cert:c1:persist"].level)
	}

	// once the date has passed
	_ = e.St.Update(func(db *model.DB) error { db.DNSProviders[0].PersistUntil = time.Now().Add(-time.Hour); return nil })
	e.St.View(func(db *model.DB) { got = desiredAlerts(db) })
	if p := got["provider:p1:persistuntil"]; p.level != "crit" || !strings.Contains(p.line, "ended") {
		t.Errorf("after the end date: %+v", p)
	}
}

func TestNoAlertsWhenTheRecordIsInPlaceOrTheProviderUsesDNS01(t *testing.T) {
	e := newEngine(t)
	persistProvider(e, false, time.Now().Add(200*24*time.Hour))
	_ = e.St.Update(func(db *model.DB) error {
		db.Certificates[0].Persist = &model.PersistState{CheckedAt: time.Now(), Records: []model.PersistRecord{{Domain: "lab.example", Status: model.PersistFound}}}
		return nil
	})
	var got map[string]alert
	e.St.View(func(db *model.DB) { got = desiredAlerts(db) })
	for k := range got {
		if strings.Contains(k, "persist") {
			t.Errorf("unexpected alert %q", k)
		}
	}
	// a leftover result must not alert once the provider is back on DNS-01
	_ = e.St.Update(func(db *model.DB) error {
		db.DNSProviders[0].Validation = ""
		db.Certificates[0].Persist = &model.PersistState{Records: []model.PersistRecord{{Domain: "lab.example", Status: model.PersistMissing}}}
		return nil
	})
	e.St.View(func(db *model.DB) { got = desiredAlerts(db) })
	for k := range got {
		if strings.Contains(k, "persist") {
			t.Errorf("unexpected alert %q for a DNS-01 provider", k)
		}
	}
}

func TestTheWatchOnlyLooksAtCertificatesThatRelyOnARecordAndOncePerDay(t *testing.T) {
	e := newEngine(t)
	pc := &persistChecker{recs: []model.PersistRecord{{Domain: "lab.example", Status: model.PersistFound}}}
	e.issuer = pc
	addCredentials(e)
	e.WatchPersist(context.Background())
	if len(pc.got) != 0 {
		t.Fatal("a DNS-01 certificate was looked at")
	}
	persistProvider(e, false, time.Time{})
	e.WatchPersist(context.Background())
	e.WatchPersist(context.Background())
	if len(pc.got) != 1 {
		t.Fatalf("looked %d times, want once: the CA is asked for an order each time", len(pc.got))
	}
}
