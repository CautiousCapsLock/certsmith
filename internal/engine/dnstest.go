package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"

	"github.com/CautiousCapsLock/certsmith/internal/model"
	"github.com/CautiousCapsLock/certsmith/internal/plugin"
)

// waitGone polls the zone's nameservers until none of them serves the value any more
// (or 20 seconds pass). It is deliberately independent of the request's context so a
// cancelled request still gets its record confirmed removed.
func (e *Engine) waitGone(names []string, fqdn, value string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	deadline := time.Now().Add(goneTimeout)
	for {
		still := false
		for _, n := range names {
			if vals, err := txtAt(ctx, n, fqdn); err == nil && contains(vals, value) {
				still = true
			}
		}
		if !still {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(2 * time.Second)
	}
}

// DNSStep is one line of a DNS test report.
type DNSStep struct {
	OK   bool   `json:"ok"`
	Info bool   `json:"info,omitempty"` // neutral note, neither pass nor fail
	Msg  string `json:"msg"`
}

// dnsPort and goneTimeout are variables only so tests can point at a local server and not wait 20 s.
var (
	dnsPort     = "53"
	goneTimeout = 20 * time.Second
)

// txtAt asks one specific server (not a recursive resolver) for the TXT records at a name.
func txtAt(ctx context.Context, server, fqdn string) ([]string, error) {
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		d := net.Dialer{Timeout: 5 * time.Second}
		return d.DialContext(ctx, "udp", net.JoinHostPort(strings.TrimSuffix(server, "."), dnsPort))
	}}
	vals, err := r.LookupTXT(ctx, strings.TrimSuffix(fqdn, "."))
	var de *net.DNSError
	if errors.As(err, &de) && de.IsNotFound { // no record at that name is an answer, not a failure to ask
		return nil, nil
	}
	return vals, err
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// TestDNS proves a DNS provider's credentials end to end without involving a CA:
// it publishes a throwaway TXT record at the real _acme-challenge name, asks the
// zone's authoritative servers and public resolvers whether they serve it, optionally
// keeps it for a while so it can be seen in the provider's dashboard, then removes it.
// Only the record it created is removed. Each step says what was actually observed.
func (e *Engine) TestDNS(ctx context.Context, kind string, cfg map[string]string, domain string, hold time.Duration) ([]DNSStep, error) {
	p, ok := plugin.DNS(kind)
	if !ok {
		return nil, fmt.Errorf("unknown DNS provider kind %q", kind)
	}
	open, err := e.OpenConfig(p.Descriptor(), cfg)
	if err != nil {
		return nil, err
	}
	domain = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(domain)), "*.")
	if domain == "" {
		return nil, fmt.Errorf("enter a domain to test with")
	}
	var steps []DNSStep
	add := func(ok bool, f string, a ...any) { steps = append(steps, DNSStep{OK: ok, Msg: fmt.Sprintf(f, a...)}) }
	note := func(f string, a ...any) { steps = append(steps, DNSStep{Info: true, Msg: fmt.Sprintf(f, a...)}) }

	solver, err := p.Solver(open)
	if err != nil {
		add(false, "The provider rejected its settings: %v", err)
		return steps, nil
	}
	add(true, "Provider settings accepted")
	intercepted, via := interceptCheck(ctx)
	if intercepted {
		note("This network intercepts DNS: a query sent to %s, where no DNS server lives, was answered. Answers from nameservers below may come from a cache, so \"not served yet\" can be stale. Certificate issuance waits a fixed time instead of relying on them.", via)
	}

	rnd := make([]byte, 12)
	_, _ = rand.Read(rnd)
	token, keyAuth := hex.EncodeToString(rnd), "certsmith-dns-test."+hex.EncodeToString(rnd)
	info := dns01.GetChallengeInfo(domain, keyAuth)
	fqdn := info.EffectiveFQDN
	if fqdn != info.FQDN {
		note("%s is a CNAME, so the challenge is published at %s", strings.TrimSuffix(info.FQDN, "."), strings.TrimSuffix(fqdn, "."))
	}

	start := time.Now()
	if err := solver.Present(domain, token, keyAuth); err != nil {
		add(false, "The provider refused to create the record: %v", err)
		if h := hintFor(err.Error()); h != "" {
			note("%s", h)
		}
		return steps, nil
	}
	pendingID := hex.EncodeToString(rnd[:6])
	e.addPending(model.PendingDNS{ID: pendingID, Provider: kind, Fqdn: fqdn, Value: info.Value, Since: time.Now(), Note: "DNS test"})
	var names []string // the zone's nameservers, once known: used to check the record really went away
	cleaned := false
	cleanup := func() DNSStep {
		cleaned = true
		if err := solver.CleanUp(domain, token, keyAuth); err != nil {
			return DNSStep{OK: false, Msg: fmt.Sprintf("Could not remove the test record (delete the TXT record %s = %s by hand): %v", strings.TrimSuffix(fqdn, "."), info.Value, err)}
		}
		// Several providers, lego's Cloudflare one among them, log a failed delete and still
		// report success. So do not take the provider's word for it: ask the nameservers.
		if len(names) == 0 {
			e.removePending(pendingID)
			return DNSStep{OK: true, Msg: "Asked the provider to remove the test record (could not verify)"}
		}
		if e.waitGone(names, fqdn, info.Value) {
			e.removePending(pendingID)
			return DNSStep{OK: true, Msg: "Removed the test record (confirmed: the nameservers no longer serve it)"}
		}
		return DNSStep{OK: false, Msg: fmt.Sprintf("The provider said it removed the record, but your nameservers still serve it. Delete the TXT record %s = %s in your DNS dashboard.", strings.TrimSuffix(fqdn, "."), info.Value)}
	}
	defer func() { // whatever happens, our record must not be left behind
		if !cleaned {
			cleanup()
		}
	}()
	add(true, "Provider created TXT %s = %s (took %s)", strings.TrimSuffix(fqdn, "."), info.Value, time.Since(start).Round(100*time.Millisecond))

	zone, err := dns01.FindZoneByFqdn(fqdn)
	if err != nil {
		add(false, "Could not work out which zone serves %s: %v", strings.TrimSuffix(fqdn, "."), err)
		return append(steps, cleanup()), nil
	}
	nss, err := net.LookupNS(strings.TrimSuffix(zone, "."))
	if err != nil || len(nss) == 0 {
		add(false, "Could not look up the nameservers of %s: %v", strings.TrimSuffix(zone, "."), err)
		return append(steps, cleanup()), nil
	}
	for _, ns := range nss {
		names = append(names, strings.TrimSuffix(ns.Host, "."))
	}
	sort.Strings(names)
	note("Zone %s is served by %s", strings.TrimSuffix(zone, "."), strings.Join(names, ", "))

	// poll every authoritative server until all serve the record, or time runs out
	type seen struct {
		found  bool
		after  time.Duration
		values []string
		err    error
	}
	res := map[string]*seen{}
	for _, n := range names {
		res[n] = &seen{}
	}
	pollStart := time.Now()
	deadline := pollStart.Add(60 * time.Second)
	for {
		pending := 0
		for _, n := range names {
			if res[n].found {
				continue
			}
			vals, err := txtAt(ctx, n, fqdn)
			res[n].values, res[n].err = vals, err
			if err == nil && contains(vals, info.Value) {
				res[n].found, res[n].after = true, time.Since(pollStart)
			} else {
				pending++
			}
		}
		if pending == 0 || time.Now().After(deadline) || ctx.Err() != nil {
			break
		}
		select {
		case <-time.After(3 * time.Second):
		case <-ctx.Done():
		}
	}
	allFound := true
	for _, n := range names {
		r := res[n]
		switch {
		case r.found:
			add(true, "%s serves the record (visible after %s)", n, r.after.Round(time.Second))
		case r.err != nil:
			allFound = false
			add(false, "%s could not be queried: %v", n, r.err)
		default:
			allFound = false
			others := "no TXT records at all"
			if len(r.values) > 0 {
				others = "only " + strings.Join(r.values, ", ")
			}
			add(false, "%s does NOT serve the record after 60s: it returned %s", n, others)
		}
	}
	if !allFound {
		add(false, "The provider accepted the record but the zone's own nameservers do not serve it, so a CA could never validate it. Most often the API token belongs to a different account or zone than the one actually serving this domain's DNS: compare the nameservers your provider shows for the zone with the list above.")
	}

	// what resolvers further out see (split-horizon DNS can differ from the authoritative answer)
	if vals, err := net.DefaultResolver.LookupTXT(ctx, strings.TrimSuffix(fqdn, ".")); err == nil && contains(vals, info.Value) {
		add(true, "This server's own resolver sees the record")
	} else if allFound {
		note("This server's own resolver does not see the record yet (it may cache; a CA queries the authoritative servers directly)")
	}
	if vals, err := txtAt(ctx, "1.1.1.1", fqdn); err == nil && contains(vals, info.Value) {
		add(true, "Public resolver 1.1.1.1 sees the record")
	}

	// anything already there that is not ours (left by another ACME tool)
	if first := names[0]; len(res[first].values) > 0 {
		var other []string
		for _, v := range res[first].values {
			if v != info.Value {
				other = append(other, v)
			}
		}
		if len(other) > 0 {
			note("Other TXT values already at this name (not created by this test): %s", strings.Join(other, ", "))
		}
	}

	if hold > 0 {
		note("Kept the record for %s so you could look for it in your provider's dashboard", hold)
		select {
		case <-time.After(hold):
		case <-ctx.Done():
		}
	}
	return append(steps, cleanup()), nil
}
