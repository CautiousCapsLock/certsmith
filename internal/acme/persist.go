package acme

// dns-persist-01 (draft-ietf-acme-dns-persist): the name is proved with one standing TXT record,
// published once at _validation-persist.<name>, that names the CA and the ACME account. Nothing is
// written to DNS at issuance or renewal, so a certificate can be renewed without DNS credentials.
//
// lego's implementation is experimental, and everything that touches it is kept in this file.
// It cannot be handed a DNS provider: the only solver lego offers is its manual one, which is
// switched to its non-interactive mode here. CertSmith therefore never asks lego to write the record;
// it shows the record (CheckPersist) and verifies it exists (the waiter) before the CA is asked.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/acme/api"
	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/challenge/dnspersist01"
	"github.com/go-acme/lego/v5/lego"

	"github.com/CautiousCapsLock/certsmith/internal/model"
	"github.com/CautiousCapsLock/certsmith/internal/plugin"
)

// Persist asks for validation with a standing dns-persist-01 record.
type Persist struct {
	// Until is the persistUntil of the record: the instant the authorisation ends. Zero means the
	// record has none. lego accepts a record only when this is identical to the record's own, so it
	// is the one value that must stay the same for as long as the record is in place.
	Until time.Time
}

// PersistMissingError is returned when the standing record is not in DNS (or names another
// account), so the CA was not asked to validate anything.
type PersistMissingError struct {
	Name string   // _validation-persist.<domain>
	Seen []string // TXT values found there that did not match
}

func (e *PersistMissingError) Error() string {
	if len(e.Seen) == 0 {
		return fmt.Sprintf("dns-persist-01: there is no TXT record at %s: publish the record shown for this certificate, then issue again", e.Name)
	}
	return fmt.Sprintf("dns-persist-01: the TXT record at %s does not match this ACME account and CA (it holds %d other value(s)): publish the record shown for this certificate", e.Name, len(e.Seen))
}

// persistLabel is the label lego and the draft put before the name.
const persistLabel = "_validation-persist."

// persistEnv switches lego's manual dns-persist-01 provider to the mode that does not read a
// terminal, and sets how long it waits for a record to become visible. It reads these when the
// solver is created, so they only need to hold while it is set up; the previous values are restored.
func persistEnv(timeout time.Duration) (restore func()) {
	set := map[string]string{
		"DNSPERSIST_MANUAL_MODE":                "wait",
		"DNSPERSIST_MANUAL_WAIT":                "0",
		"DNSPERSIST_MANUAL_PROPAGATION_TIMEOUT": strconv.Itoa(max(1, int(timeout.Seconds()))),
		"DNSPERSIST_MANUAL_POLLING_INTERVAL":    "2",
	}
	type old struct {
		v  string
		ok bool
	}
	prev := map[string]old{}
	for k, v := range set {
		o, ok := os.LookupEnv(k)
		prev[k] = old{o, ok}
		_ = os.Setenv(k, v)
	}
	return func() {
		for k, o := range prev {
			if o.ok {
				_ = os.Setenv(k, o.v)
			} else {
				_ = os.Unsetenv(k)
			}
		}
	}
}

// persistGrace is how long a record may stay invisible to the resolvers, from the first look, before
// the issuance gives up on it. A published record is visible at once; the time only absorbs resolvers
// that answered from a cache a moment before it was published. It is a variable for the tests.
var persistGrace = 20 * time.Second

// persistWaiter is attached to lego's wait for the record. lego's loop ends as soon as it returns
// (true, err). Unlike the DNS-01 waiter it ends the issuance early when the record is simply not
// there: a standing record is not going to appear by waiting, and a name the CA cannot validate
// should not be put to it, because a failed validation counts against the account's rate limit.
//
// When settle is set the zone's nameservers are not asked (the network intercepts DNS, or the
// setting says so): the resolvers are asked once, after that wait, and the answer settles it.
type persistWaiter struct {
	ctx     context.Context
	settle  time.Duration
	started time.Time
	missing *PersistMissingError
}

func (w *persistWaiter) run(ctx context.Context, domain, fqdn string, matcher dnspersist01.RecordMatcher, check dnspersist01.PreCheckFunc) (bool, error) {
	if w.ctx.Err() != nil {
		return true, errCancelled
	}
	if w.started.IsZero() {
		w.started = time.Now()
	}
	if w.settle > 0 && time.Since(w.started) < w.settle {
		return false, nil
	}
	if w.settle == 0 {
		ok, err := check(ctx, fqdn, matcher)
		if ok {
			return true, err
		}
		if res, lerr := dnspersist01.DefaultClient().LookupTXT(ctx, fqdn); lerr == nil && !matcher(res.Records) {
			if time.Since(w.started) >= persistGrace {
				return true, w.absent(fqdn, res)
			}
		}
		return false, err
	}
	res, lerr := dnspersist01.DefaultClient().LookupTXT(ctx, fqdn)
	if lerr != nil || matcher(res.Records) {
		return true, nil // found, or unknowable from here: the CA decides
	}
	return true, w.absent(fqdn, res)
}

func (w *persistWaiter) absent(fqdn string, res dnspersist01.TXTResult) error {
	w.missing = &PersistMissingError{Name: strings.TrimSuffix(fqdn, ".")}
	for _, rec := range res.Records {
		w.missing.Seen = append(w.missing.Seen, rec.Value)
	}
	return w.missing
}

// obtainPersist issues with dns-persist-01 only. It returns the typed error when the record is not
// in DNS, which is what makes a fallback to DNS-01 worth trying.
func (i *Issuer) obtainPersist(ctx context.Context, r Request) (*plugin.Bundle, error) {
	client, user, accDir, err := i.setup(ctx, r)
	if err != nil {
		return nil, err
	}
	wait := r.PropagationWait
	if wait <= 0 {
		wait = 2 * time.Minute
	}
	defer persistEnv(wait)()

	w := &persistWaiter{ctx: ctx, settle: r.SettleFor}
	opts := []dnspersist01.ChallengeOption{dnspersist01.WrapPreCheck(w.run)}
	if !r.Persist.Until.IsZero() {
		opts = append(opts, dnspersist01.WithPersistUntil(r.Persist.Until))
	}
	dnsOpts := dnspersist01.NewOptions()
	dnsOpts.RecursiveNameservers = r.Settings.DNSResolvers
	dnspersist01.SetDefaultClient(dnspersist01.NewClient(dnsOpts))
	if err := client.Challenge.SetDNSPersist01(opts...); err != nil {
		return nil, err
	}
	if _, err := register(ctx, client, user, accDir, r.EAB); err != nil {
		return nil, err
	}
	b, err := obtain(ctx, client, r)
	if err != nil && w.missing != nil {
		return nil, w.missing
	}
	return b, err
}

// persistCore is an ACME API client bound to the account, for reading what the CA asks for without
// issuing anything: lego's own client keeps its core private.
func persistCore(ctx context.Context, r Request, user *legoUser) (*api.Core, error) {
	cfg := lego.NewConfig(user)
	cfg.CADirURL = directoryURL(r.directory())
	cfg.HTTPClient.Transport = ctxTransport{ctx: ctx, next: cfg.HTTPClient.Transport}
	if user.reg == nil || user.reg.Location == "" {
		return nil, errors.New("the ACME account is not registered yet")
	}
	return api.New(cfg.HTTPClient, cfg.UserAgent, cfg.CADirURL, user.reg.Location, user.key)
}

// CheckPersist works out the record each name on the request needs and looks for it in DNS. It
// creates the account when it does not exist, and an order at the CA to read the challenges from; the
// order's authorisations are deactivated again, since nothing is validated.
func (i *Issuer) CheckPersist(ctx context.Context, r Request) ([]model.PersistRecord, error) {
	issueMu.Lock()
	defer issueMu.Unlock()
	if r.Persist == nil {
		return nil, errors.New("this request does not use dns-persist-01")
	}
	if len(r.Domains) == 0 {
		return nil, errors.New("no domains")
	}
	client, user, accDir, err := i.setup(ctx, r)
	if err != nil {
		return nil, err
	}
	if _, err := register(ctx, client, user, accDir, r.EAB); err != nil {
		return nil, err
	}
	core, err := persistCore(ctx, r, user)
	if err != nil {
		return nil, err
	}
	order, err := core.Orders.New(ctx, r.Domains, nil)
	if err != nil {
		return nil, fmt.Errorf("ask the CA what it needs: %w", err)
	}
	var authzs []acme.Authorization
	for _, u := range order.Authorizations {
		a, err := core.Authorizations.Get(ctx, u)
		if err != nil {
			return nil, fmt.Errorf("read an authorisation from the CA: %w", err)
		}
		authzs = append(authzs, a)
	}
	defer func() { // the order is never used; do not leave authorisations pending at the CA
		for _, u := range order.Authorizations {
			dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			_ = core.Authorizations.Deactivate(dctx, u)
			cancel()
		}
	}()

	dnsOpts := dnspersist01.NewOptions()
	dnsOpts.RecursiveNameservers = r.Settings.DNSResolvers
	dnspersist01.SetDefaultClient(dnspersist01.NewClient(dnsOpts))

	var out []model.PersistRecord
	index := map[string]int{}
	for _, a := range authzs {
		rec := persistRecordFor(ctx, a, r.Persist.Until)
		// A name and its wildcard share one record, and the wildcard policy covers both
		if n, ok := index[rec.Name]; ok {
			if rec.Wildcard && !out[n].Wildcard {
				out[n] = rec
			}
			continue
		}
		index[rec.Name] = len(out)
		out = append(out, rec)
	}
	return out, nil
}

// persistRecordFor builds the record one authorisation needs from lego's own helper and checks DNS.
func persistRecordFor(ctx context.Context, a acme.Authorization, until time.Time) model.PersistRecord {
	domain := a.Identifier.Value
	rec := model.PersistRecord{Domain: domain, Name: persistLabel + domain, Wildcard: a.Wildcard}
	chlng, err := challenge.FindChallenge(challenge.DNSPersist01, a)
	if err != nil {
		rec.Status = model.PersistError
		rec.Detail = "the CA does not offer dns-persist-01 for this name"
		for _, c := range a.Challenges {
			rec.Offered = append(rec.Offered, c.Type)
		}
		return rec
	}
	if chlng.AccountURI == "" || len(chlng.IssuerDomainNames) == 0 {
		rec.Status = model.PersistError
		rec.Detail = "the CA's dns-persist-01 challenge names no account or issuer: it implements an older draft than this CertSmith expects"
		return rec
	}
	rec.Account = chlng.AccountURI

	// What is published decides which of the CA's issuer names is used, as it does in lego; with
	// nothing published, the first in alphabetical order.
	issuers := append([]string(nil), chlng.IssuerDomainNames...)
	sort.Strings(issuers)
	res, lerr := dnspersist01.DefaultClient().LookupTXT(ctx, persistLabel+domain+".")
	if lerr != nil {
		rec.Status = model.PersistError
		rec.Detail = "DNS could not be asked: " + lerr.Error()
	}
	for _, t := range res.Records {
		rec.Seen = append(rec.Seen, t.Value)
	}
	rec.Issuer = issuers[0]
	for _, is := range issuers {
		for _, v := range rec.Seen {
			if ok, _ := matchPersist(v, is, chlng.AccountURI, a.Wildcard, until); ok {
				rec.Issuer = is
			}
		}
	}
	info, err := dnspersist01.GetChallengeInfo(a, rec.Issuer, chlng.AccountURI, until)
	if err != nil {
		rec.Status = model.PersistError
		rec.Detail = err.Error()
		return rec
	}
	rec.Value = info.Value
	if !until.IsZero() {
		rec.Until = until.UTC().Unix()
	}
	if lerr != nil {
		return rec
	}
	switch {
	case len(rec.Seen) == 0:
		rec.Status = model.PersistMissing
		rec.Detail = "there is no TXT record at this name"
	default:
		rec.Status = model.PersistMismatch
		var why string
		for _, v := range rec.Seen {
			ok, reason := matchPersist(v, rec.Issuer, chlng.AccountURI, a.Wildcard, until)
			if ok {
				rec.Status, why = model.PersistFound, ""
				break
			}
			if why == "" {
				why = reason
			}
		}
		if rec.Status == model.PersistMismatch {
			rec.Detail = why
		}
	}
	return rec
}

// matchPersist reports whether a TXT value is the record wanted, with the rule lego applies: same
// issuer and account, the same persistUntil (absent counts as a value), and policy=wildcard when the
// name is a wildcard. The second result says what differs when it does not match.
func matchPersist(value, issuer, account string, wildcard bool, until time.Time) (bool, string) {
	parts := strings.Split(value, ";")
	got := strings.Trim(parts[0], " \t")
	if got == "" {
		return false, "the value does not start with a CA's issuer-domain-name"
	}
	params := map[string]string{}
	for _, p := range parts[1:] {
		k, v, ok := strings.Cut(strings.Trim(p, " \t"), "=")
		if !ok {
			return false, "the value is not a list of tag=value parameters"
		}
		params[strings.ToLower(strings.Trim(k, " \t"))] = strings.Trim(v, " \t")
	}
	switch {
	case got != issuer:
		return false, fmt.Sprintf("it names a different CA (%s)", got)
	case params["accounturi"] != account:
		return false, "it names a different ACME account: the account may have been replaced, so the record must be published again"
	}
	have, hasUntil := params["persistuntil"]
	switch {
	case until.IsZero() && hasUntil:
		return false, "it has a persistUntil date, but this provider has none set"
	case !until.IsZero() && !hasUntil:
		return false, "it has no persistUntil date, but this provider has one set"
	case !until.IsZero() && have != strconv.FormatInt(until.UTC().Unix(), 10):
		return false, "its persistUntil date is not the one set on this provider"
	}
	if wildcard && !strings.EqualFold(params["policy"], "wildcard") {
		return false, "the certificate has a wildcard name, so the record needs policy=wildcard"
	}
	return true, ""
}
