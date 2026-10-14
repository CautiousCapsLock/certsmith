package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/CautiousCapsLock/certsmith/internal/acme"
	"github.com/CautiousCapsLock/certsmith/internal/model"
)

// persistWatchEvery is how often the standing dns-persist-01 records are looked at. A record that was
// removed would otherwise be found only when a renewal fails, which is the worst time to learn it.
const persistWatchEvery = 24 * time.Hour

// persistWarnDays is how long before a provider's persistUntil date the alert starts.
const persistWarnDays = 30

// persistRequest is the CA side of a request for a certificate on a dns-persist-01 provider: the
// account and what it asks for, without any DNS credentials.
func (e *Engine) persistRequest(snap model.DB, c model.Certificate) (acme.Request, *model.DNSProvider, error) {
	dp := providerOf(snap, c)
	if dp == nil {
		return acme.Request{}, nil, errors.New("this certificate has no certificate provider")
	}
	if !dp.UsesPersist() {
		return acme.Request{}, dp, errors.New("this certificate's provider validates names with DNS-01: there is no standing record to check")
	}
	req := acme.Request{Name: c.Name, Domains: c.Domains, KeyType: "ec256", Settings: snap.Settings,
		Persist: &acme.Persist{Until: dp.PersistUntil}}
	if dp.IsEAB() {
		eab, err := e.eabFor(*dp)
		if err != nil {
			return req, dp, err
		}
		req.Directory, req.Email, req.EAB = dp.Directory, dp.Email, eab
	} else if snap.Settings.ACMEDirectory == model.DirSelfSigned {
		return req, dp, errors.New("the built-in test CA validates nothing, so it has no dns-persist-01 record")
	}
	return req, dp, nil
}

// CheckPersist asks the CA what record each name on the certificate needs, looks for it in DNS and
// remembers what it found. It creates the CA account if there is none yet.
func (e *Engine) CheckPersist(ctx context.Context, id string) (*model.PersistState, error) {
	snap := e.St.Snapshot()
	var c *model.Certificate
	for i := range snap.Certificates {
		if snap.Certificates[i].ID == id {
			c = &snap.Certificates[i]
		}
	}
	if c == nil {
		return nil, errors.New("certificate not found")
	}
	if c.Source == model.SourceImport {
		return nil, errors.New("an imported certificate is not issued by CertSmith, so it has no record")
	}
	req, _, err := e.persistRequest(snap, *c)
	if err != nil {
		return nil, err
	}
	checker, ok := e.issuer.(interface {
		CheckPersist(ctx context.Context, r acme.Request) ([]model.PersistRecord, error)
	})
	if !ok {
		return nil, errors.New("this issuer cannot check dns-persist-01 records")
	}
	cctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	st := &model.PersistState{CheckedAt: time.Now()}
	recs, err := checker.CheckPersist(cctx, req)
	if err != nil {
		st.Error = err.Error()
	}
	st.Records = recs
	e.updateCert(id, func(c *model.Certificate) { c.Persist = st })
	return st, err
}

// WatchPersist checks, once a day, every certificate that relies on a standing record. What it finds
// is kept on the certificate, where the alerts and the page read it.
func (e *Engine) WatchPersist(ctx context.Context) {
	snap := e.St.Snapshot()
	for _, c := range snap.Certificates {
		if !c.Enabled || c.Source == model.SourceImport || c.Issuing || ctx.Err() != nil {
			continue
		}
		if dp := providerOf(snap, c); dp == nil || !dp.UsesPersist() {
			continue
		}
		if c.Persist != nil && time.Since(c.Persist.CheckedAt) < persistWatchEvery {
			continue
		}
		if _, err := e.CheckPersist(ctx, c.ID); err != nil {
			e.Log.Warn("dns-persist-01 record check failed", "cert", c.Name, "err", err)
		}
	}
}

// persistAlerts adds the conditions a standing record can be in to the alert set: a record that is
// not there (or no longer names this account), and an authorisation that is about to end.
func persistAlerts(db *model.DB, out map[string]alert) {
	users := map[string]int{} // enabled certificates per provider that relies on a record
	for _, c := range db.Certificates {
		if !c.Enabled || c.Source == model.SourceImport {
			continue
		}
		dp := providerOf(*db, c)
		if dp == nil || !dp.UsesPersist() {
			continue
		}
		users[dp.ID]++
		if c.Persist == nil {
			continue
		}
		var bad []string
		for _, r := range c.Persist.Records {
			if r.Status != model.PersistFound {
				bad = append(bad, fmt.Sprintf("%s (%s)", r.Domain, r.Status))
			}
		}
		if len(bad) == 0 {
			continue
		}
		lvl := "warn"
		if c.Serial == "" || daysLeft(c.NotAfter) <= 14 {
			lvl = "crit" // a renewal is due and cannot validate
		}
		out["cert:"+c.ID+":persist"] = alert{lvl, fmt.Sprintf("Certificate %q: the dns-persist-01 record is not in place for %s: renewal will fail until it is published again",
			c.Name, strings.Join(bad, ", "))}
	}
	for _, p := range db.DNSProviders {
		if !p.UsesPersist() || p.PersistUntil.IsZero() || users[p.ID] == 0 {
			continue
		}
		d := daysLeft(p.PersistUntil)
		if d > persistWarnDays {
			continue
		}
		lvl := "warn"
		if d <= 7 {
			lvl = "crit"
		}
		line := fmt.Sprintf("Provider %q: the dns-persist-01 authorisation ends in %d day(s) (%s): publish the new record, then set the new end date on the provider", p.Name, d, p.PersistUntil.UTC().Format("2006-01-02"))
		if time.Now().After(p.PersistUntil) {
			lvl = "crit"
			line = fmt.Sprintf("Provider %q: the dns-persist-01 authorisation ended on %s: certificates cannot be validated until a new record is published", p.Name, p.PersistUntil.UTC().Format("2006-01-02"))
		}
		out["provider:"+p.ID+":persistuntil"] = alert{lvl, line}
	}
}
