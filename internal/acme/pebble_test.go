package acme

// An end-to-end run against Pebble, Let's Encrypt's test CA, which implements dns-persist-01. It
// needs a Pebble started with External Account Binding and pebble-challtestsrv as its DNS, so it only
// runs when CERTSMITH_PEBBLE is set. docs/DNS-PERSIST.md (section 5) says how to start one.
//
//	CERTSMITH_PEBBLE=1
//	CERTSMITH_PEBBLE_DIRECTORY   (default https://localhost:14000/dir)
//	CERTSMITH_PEBBLE_DNS         the DNS server Pebble asks (default 127.0.0.1:8053)
//	CERTSMITH_PEBBLE_MGMT        its management API (default http://127.0.0.1:8055)
//	LEGO_CA_CERTIFICATES         Pebble's test CA certificate, so its HTTPS is trusted

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/CautiousCapsLock/certsmith/internal/model"
)

type pebbleRig struct {
	dir, dns, mgmt string
	iss            *Issuer
}

func newPebbleRig(t *testing.T) *pebbleRig {
	t.Helper()
	if os.Getenv("CERTSMITH_PEBBLE") == "" {
		t.Skip("set CERTSMITH_PEBBLE=1 with a Pebble running to run this")
	}
	env := func(k, def string) string {
		if v := os.Getenv(k); v != "" {
			return v
		}
		return def
	}
	return &pebbleRig{
		dir:  env("CERTSMITH_PEBBLE_DIRECTORY", "https://localhost:14000/dir"),
		dns:  env("CERTSMITH_PEBBLE_DNS", "127.0.0.1:8053"),
		mgmt: env("CERTSMITH_PEBBLE_MGMT", "http://127.0.0.1:8055"),
		iss:  &Issuer{DataDir: t.TempDir()},
	}
}

func (p *pebbleRig) post(t *testing.T, path string, body any) {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := http.Post(p.mgmt+path, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s: %s", path, resp.Status)
	}
}

// publish puts a TXT record in the DNS Pebble asks; the name is cleared again when the test ends.
func (p *pebbleRig) publish(t *testing.T, name, value string) {
	t.Helper()
	host := strings.TrimSuffix(name, ".") + "."
	p.post(t, "/set-txt", map[string]string{"host": host, "value": value})
	t.Cleanup(func() { p.post(t, "/clear-txt", map[string]string{"host": host}) })
}

func (p *pebbleRig) request(domains ...string) Request {
	return Request{
		Name: "pebble", Domains: domains, KeyType: "ec256",
		Directory: p.dir, Email: "pebble@example.test",
		// the key Pebble's test configuration issues for kid-1
		EAB:      &EAB{Kid: "kid-1", HMAC: "zWNDZM6eQGHWpSRTPal5eIUYFTu7EajVIoguysqZ9wG44nMEtx3MUAsUDkMTQ12W"},
		Settings: model.Settings{DNSResolvers: []string{p.dns}, ACMEDirectory: model.DirProduction},
		Persist:  &Persist{},
		// the test DNS server has no zone to ask the nameservers of, so a fixed wait stands in for that
		SettleFor: 2 * time.Second,
		Solver:    NoChallenge{},
	}
}

func TestPebbleIssuesWithAStandingRecordAndNothingWrittenAtIssuance(t *testing.T) {
	p := newPebbleRig(t)
	ctx := context.Background()
	name := fmt.Sprintf("app%d.persist.test", time.Now().UnixNano()%1_000_000)

	recs, err := p.iss.CheckPersist(ctx, p.request(name))
	if err != nil {
		t.Fatal(err)
	}
	r := recs[0]
	t.Logf("Pebble wants: %s TXT %q (account %s, issuer %s)", r.Name, r.Value, r.Account, r.Issuer)
	if r.Status != model.PersistMissing || r.Issuer != "pebble.letsencrypt.org" || !strings.HasPrefix(r.Account, "https://") {
		t.Fatalf("before publishing: %+v", r)
	}
	if want := r.Issuer + "; accounturi=" + r.Account; r.Value != want {
		t.Fatalf("value = %q, want %q", r.Value, want)
	}

	// With the record missing the CA is never asked: a failed validation counts against its limits.
	_, err = p.iss.Issue(ctx, p.request(name))
	var miss *PersistMissingError
	if !errors.As(err, &miss) {
		t.Fatalf("issue without the record: %v", err)
	}

	p.publish(t, r.Name, r.Value)
	recs, _ = p.iss.CheckPersist(ctx, p.request(name))
	if recs[0].Status != model.PersistFound {
		t.Fatalf("after publishing: %+v", recs[0])
	}
	b, err := p.iss.Issue(ctx, p.request(name))
	if err != nil {
		t.Fatalf("issue with the record in place: %v", err)
	}
	if len(b.Leaf.DNSNames) != 1 || b.Leaf.DNSNames[0] != name {
		t.Errorf("names = %v", b.Leaf.DNSNames)
	}
	t.Logf("issued serial %s by %s, valid until %s", b.Serial, b.Leaf.Issuer.CommonName, b.NotAfter.Format(time.RFC3339))

	// renewal is the same again: still nothing to write
	if _, err := p.iss.Issue(ctx, p.request(name)); err != nil {
		t.Errorf("renewal: %v", err)
	}
}

func TestPebbleWildcardsAndAnEndDate(t *testing.T) {
	p := newPebbleRig(t)
	ctx := context.Background()
	base := fmt.Sprintf("wild%d.persist.test", time.Now().UnixNano()%1_000_000)
	req := p.request("*."+base, base)
	req.Persist.Until = time.Now().Add(45 * 24 * time.Hour).UTC().Truncate(time.Second)

	recs, err := p.iss.CheckPersist(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || !recs[0].Wildcard {
		t.Fatalf("a wildcard and its apex need one record: %+v", recs)
	}
	t.Logf("Pebble wants: %s TXT %q", recs[0].Name, recs[0].Value)
	if !strings.Contains(recs[0].Value, "policy=wildcard") || !strings.Contains(recs[0].Value, "persistUntil=") {
		t.Fatalf("value = %q", recs[0].Value)
	}

	// an old-style record without the end date does not match: the CA would accept it, but CertSmith
	// would not know what it is looking at, so it is reported rather than guessed
	p.publish(t, recs[0].Name, recs[0].Issuer+"; accounturi="+recs[0].Account+"; policy=wildcard")
	if got, _ := p.iss.CheckPersist(ctx, req); got[0].Status != model.PersistMismatch {
		t.Errorf("a record without the end date: %+v", got[0])
	}
	p.publish(t, recs[0].Name, recs[0].Value)
	if got, _ := p.iss.CheckPersist(ctx, req); got[0].Status != model.PersistFound {
		t.Fatalf("the record as shown: %+v", got[0])
	}
	b, err := p.iss.Issue(ctx, req)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if len(b.Leaf.DNSNames) != 2 {
		t.Errorf("names = %v", b.Leaf.DNSNames)
	}
}

func TestPebbleRefusesARecordForAnotherAccount(t *testing.T) {
	p := newPebbleRig(t)
	ctx := context.Background()
	name := fmt.Sprintf("other%d.persist.test", time.Now().UnixNano()%1_000_000)
	recs, err := p.iss.CheckPersist(ctx, p.request(name))
	if err != nil {
		t.Fatal(err)
	}
	other := strings.Replace(recs[0].Account, "/my-account/", "/my-account/not-", 1)
	p.publish(t, recs[0].Name, recs[0].Issuer+"; accounturi="+other)
	got, _ := p.iss.CheckPersist(ctx, p.request(name))
	if got[0].Status != model.PersistMismatch || !strings.Contains(got[0].Detail, "different ACME account") {
		t.Errorf("check: %+v", got[0])
	}
	_, err = p.iss.Issue(ctx, p.request(name))
	var miss *PersistMissingError
	if !errors.As(err, &miss) || len(miss.Seen) != 1 {
		t.Fatalf("err = %v, want the record for another account reported, with what was seen", err)
	}
}
