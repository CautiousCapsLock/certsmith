package acme

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/CautiousCapsLock/certsmith/internal/model"
)

// testDNS is a DNS server that answers TXT queries from a map the test edits: the resolver CertSmith
// is pointed at, and the place the mock CA reads the standing record from.
type testDNS struct {
	mu  sync.Mutex
	txt map[string][]string // lower-case name without the trailing dot
	adr string
}

func newTestDNS(t *testing.T) *testDNS {
	t.Helper()
	d := &testDNS{txt: map[string][]string{}}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	d.adr = pc.LocalAddr().String()
	ln, err := net.Listen("tcp", d.adr)
	if err != nil {
		t.Fatal(err)
	}
	h := dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(q)
		m.Authoritative = true
		for _, qq := range q.Question {
			if qq.Qtype != dns.TypeTXT {
				continue
			}
			for _, v := range d.get(strings.TrimSuffix(qq.Name, ".")) {
				m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: qq.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{v}})
			}
		}
		_ = w.WriteMsg(m)
	})
	for _, srv := range []*dns.Server{{PacketConn: pc, Handler: h}, {Listener: ln, Handler: h}} {
		go func() { _ = srv.ActivateAndServe() }()
		t.Cleanup(func() { _ = srv.Shutdown() })
	}
	return d
}

func (d *testDNS) get(name string) []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.txt[strings.ToLower(name)]...)
}

func (d *testDNS) set(name string, values ...string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.txt[strings.ToLower(name)] = values
}

// persistRig is a mock CA that offers dns-persist-01 and a DNS server it reads records from.
type persistRig struct {
	ca  *mockCA
	dns *testDNS
	iss *Issuer
}

const rigIssuer = "ca.example.test"

func newPersistRig(t *testing.T) *persistRig {
	t.Helper()
	ca := newMockCA(t, "kid-1", testMAC)
	d := newTestDNS(t)
	ca.persist, ca.issuerName, ca.txt = true, rigIssuer, d.get
	return &persistRig{ca: ca, dns: d, iss: &Issuer{DataDir: t.TempDir()}}
}

func (g *persistRig) request(domains ...string) Request {
	r := eabRequest(g.ca, "kid-1", testMAC)
	r.Domains, r.Name = domains, "test"
	r.Persist = &Persist{}
	r.Settings.DNSResolvers = []string{g.dns.adr}
	r.SettleFor = time.Second // the test DNS has no zone, so the zone's own nameservers cannot be asked
	return r
}

func (g *persistRig) account() string { return g.ca.srv.URL + "/acct/1" }

func TestTheRecordANameNeedsIsBuiltFromTheCAsChallengeAndTheAccount(t *testing.T) {
	g := newPersistRig(t)
	recs, err := g.iss.CheckPersist(context.Background(), g.request("app.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 {
		t.Fatalf("records = %+v", recs)
	}
	r := recs[0]
	if r.Name != "_validation-persist.app.example.com" || r.Domain != "app.example.com" {
		t.Errorf("name = %q domain = %q", r.Name, r.Domain)
	}
	if want := rigIssuer + "; accounturi=" + g.account(); r.Value != want {
		t.Errorf("value = %q, want %q", r.Value, want)
	}
	if r.Status != model.PersistMissing {
		t.Errorf("status = %q, want missing: nothing is published yet", r.Status)
	}
	if g.ca.issued || g.ca.orders != 1 {
		t.Errorf("checking must only read: issued=%v orders=%d", g.ca.issued, g.ca.orders)
	}
}

func TestAPublishedRecordIsRecognisedAndAWrongOneSaysWhatDiffers(t *testing.T) {
	g := newPersistRig(t)
	ctx := context.Background()
	name := "_validation-persist.app.example.com"
	cases := []struct {
		value, status, detail string
	}{
		{rigIssuer + "; accounturi=" + g.account(), model.PersistFound, ""},
		{rigIssuer + ";accounturi=" + g.account() + ";", model.PersistMismatch, ""}, // a trailing ; is malformed
		{rigIssuer + "; accounturi=" + g.ca.srv.URL + "/acct/9", model.PersistMismatch, "different ACME account"},
		{"other.example; accounturi=" + g.account(), model.PersistMismatch, "different CA"},
		{rigIssuer + "; accounturi=" + g.account() + "; persistUntil=4102444800", model.PersistMismatch, "has a persistUntil date, but this provider has none"},
	}
	for _, c := range cases {
		g.dns.set(name, c.value)
		recs, err := g.iss.CheckPersist(ctx, g.request("app.example.com"))
		if err != nil {
			t.Fatal(err)
		}
		if recs[0].Status != c.status {
			t.Errorf("%q: status = %q (%s), want %q", c.value, recs[0].Status, recs[0].Detail, c.status)
		}
		if c.detail != "" && !strings.Contains(recs[0].Detail, c.detail) {
			t.Errorf("%q: detail = %q, want it to say %q", c.value, recs[0].Detail, c.detail)
		}
	}
}

func TestAWildcardNeedsThePolicyAndShareItsRecordWithTheName(t *testing.T) {
	g := newPersistRig(t)
	ctx := context.Background()
	recs, err := g.iss.CheckPersist(ctx, g.request("*.example.com", "example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || !recs[0].Wildcard || !strings.HasSuffix(recs[0].Value, "; policy=wildcard") {
		t.Fatalf("a wildcard and its apex share one record that carries the policy: %+v", recs)
	}
	g.dns.set("_validation-persist.example.com", rigIssuer+"; accounturi="+g.account())
	recs, _ = g.iss.CheckPersist(ctx, g.request("*.example.com"))
	if recs[0].Status != model.PersistMismatch || !strings.Contains(recs[0].Detail, "policy=wildcard") {
		t.Errorf("without the policy: %+v", recs[0])
	}
	g.dns.set("_validation-persist.example.com", rigIssuer+"; accounturi="+g.account()+"; policy=wildcard")
	recs, _ = g.iss.CheckPersist(ctx, g.request("*.example.com"))
	if recs[0].Status != model.PersistFound {
		t.Errorf("with the policy: %+v", recs[0])
	}
}

func TestAnEndDateIsPartOfTheRecordAndMustMatchExactly(t *testing.T) {
	g := newPersistRig(t)
	ctx := context.Background()
	until := time.Now().Add(90 * 24 * time.Hour).UTC().Truncate(time.Second)
	r := g.request("app.example.com")
	r.Persist.Until = until
	recs, err := g.iss.CheckPersist(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(recs[0].Value, "; persistUntil="+strconv.FormatInt(until.Unix(), 10)) || recs[0].Until != until.Unix() {
		t.Fatalf("value = %q", recs[0].Value)
	}
	g.dns.set("_validation-persist.app.example.com", rigIssuer+"; accounturi="+g.account())
	if recs, _ = g.iss.CheckPersist(ctx, r); recs[0].Status != model.PersistMismatch || !strings.Contains(recs[0].Detail, "no persistUntil") {
		t.Errorf("a record without the date: %+v", recs[0])
	}
	g.dns.set("_validation-persist.app.example.com", recs[0].Value)
	if recs, _ = g.iss.CheckPersist(ctx, r); recs[0].Status != model.PersistFound {
		t.Errorf("the record as shown: %+v", recs[0])
	}
}

func TestACertificateIsIssuedWithNothingWrittenToDNS(t *testing.T) {
	g := newPersistRig(t)
	g.dns.set("_validation-persist.app.example.com", rigIssuer+"; accounturi="+g.account())
	r := g.request("app.example.com")
	r.Solver = NoChallenge{} // no DNS credentials: a write would fail the issuance
	b, err := g.iss.Issue(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Leaf.DNSNames) != 1 || b.Leaf.DNSNames[0] != "app.example.com" {
		t.Errorf("names = %v", b.Leaf.DNSNames)
	}
	if len(g.ca.answered) != 1 || g.ca.answered[0] != "dns-persist-01" {
		t.Errorf("challenges answered = %v, want one dns-persist-01 and no dns-01", g.ca.answered)
	}
	if got := g.dns.get("_acme-challenge.app.example.com"); len(got) != 0 {
		t.Errorf("a DNS-01 record was written: %v", got)
	}
}

func TestWithoutTheRecordIssuanceStopsBeforeTheCAIsAsked(t *testing.T) {
	old := persistGrace
	persistGrace = 0
	defer func() { persistGrace = old }()
	g := newPersistRig(t)
	r := g.request("app.example.com")
	r.SettleFor = 0
	r.PropagationWait = 20 * time.Second
	r.Solver = NoChallenge{}
	start := time.Now()
	_, err := g.iss.Issue(context.Background(), r)
	var miss *PersistMissingError
	if !errors.As(err, &miss) {
		t.Fatalf("err = %v, want a PersistMissingError", err)
	}
	if miss.Name != "_validation-persist.app.example.com" {
		t.Errorf("name = %q", miss.Name)
	}
	if len(g.ca.answered) != 0 {
		t.Errorf("the CA was asked to validate a name that could not pass: %v", g.ca.answered)
	}
	if d := time.Since(start); d > 15*time.Second {
		t.Errorf("took %s: a missing standing record should fail at once, not wait out the propagation limit", d)
	}
}

// recordingSolver is a DNS-01 provider that publishes into the test DNS.
type recordingSolver struct {
	dns       *testDNS
	presented []string
}

func (s *recordingSolver) Present(_ context.Context, domain, token, keyAuth string) error {
	s.presented = append(s.presented, domain)
	s.dns.set("_acme-challenge."+domain, "some-challenge-value")
	return nil
}
func (s *recordingSolver) CleanUp(_ context.Context, domain, token, keyAuth string) error { return nil }

func TestAProviderWithDNSCredentialsFallsBackToDNS01WhenTheRecordIsMissing(t *testing.T) {
	old := persistGrace
	persistGrace = 0
	defer func() { persistGrace = old }()
	g := newPersistRig(t)
	sol := &recordingSolver{dns: g.dns}
	r := g.request("app.example.com")
	r.SettleFor = 0
	r.PropagationWait = 20 * time.Second
	r.Solver = sol
	r.Settings.DNSCheck = "wait"
	r.SettleFor = time.Second
	var why error
	r.OnFallback = func(e error) { why = e }
	b, err := g.iss.Issue(context.Background(), r)
	if err != nil {
		t.Fatalf("the fallback should have issued: %v", err)
	}
	if why == nil {
		t.Error("the fallback was not reported")
	}
	if len(sol.presented) != 1 {
		t.Errorf("DNS-01 record written %d time(s), want once", len(sol.presented))
	}
	if b.Leaf.DNSNames[0] != "app.example.com" {
		t.Errorf("names = %v", b.Leaf.DNSNames)
	}
}

func TestAProviderWithoutCredentialsReportsTheMissingRecordInsteadOfFallingBack(t *testing.T) {
	g := newPersistRig(t)
	r := g.request("app.example.com") // with a fixed wait instead of asking the nameservers
	r.Solver = NoChallenge{}
	var fell bool
	r.OnFallback = func(error) { fell = true }
	_, err := g.iss.Issue(context.Background(), r)
	var miss *PersistMissingError
	if !errors.As(err, &miss) {
		t.Fatalf("err = %v, want a PersistMissingError", err)
	}
	if fell {
		t.Error("fell back although there are no DNS credentials")
	}
	if len(g.ca.answered) != 0 {
		t.Errorf("the CA was asked to validate a name whose record is not there: %v", g.ca.answered)
	}
}

func TestACAThatOffersNoPersistChallengeIsReported(t *testing.T) {
	g := newPersistRig(t)
	g.ca.persist = false
	g.ca.prevalidated = false
	recs, err := g.iss.CheckPersist(context.Background(), g.request("app.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if recs[0].Status != model.PersistError || !strings.Contains(recs[0].Detail, "does not offer dns-persist-01") {
		t.Errorf("record = %+v", recs[0])
	}
	if len(recs[0].Offered) == 0 || recs[0].Offered[0] != "dns-01" {
		t.Errorf("offered = %v, want the types the CA did offer", recs[0].Offered)
	}
}

func TestACheckLeavesNoPendingAuthorisationsAtTheCA(t *testing.T) {
	g := newPersistRig(t)
	if _, err := g.iss.CheckPersist(context.Background(), g.request("a.example.com", "b.example.com")); err != nil {
		t.Fatal(err)
	}
	// the mock accepts the deactivation request on the authorisation URL; what matters is that the
	// order was only read: nothing was answered and nothing issued
	if len(g.ca.answered) != 0 || g.ca.issued {
		t.Errorf("answered=%v issued=%v", g.ca.answered, g.ca.issued)
	}
}
