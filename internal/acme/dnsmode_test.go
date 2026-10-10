package acme

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/go-acme/lego/v5/challenge/dns01"
	"github.com/miekg/dns"

	"github.com/CautiousCapsLock/certsmith/internal/model"
)

// fakeDNS is a tiny UDP DNS server: it answers every TXT question with the given values (or with
// NXDOMAIN when there are none).
func fakeDNS(t *testing.T, values ...string) (host, port string) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if len(values) == 0 {
			m.Rcode = dns.RcodeNameError
		}
		for _, v := range values {
			m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 1}, Txt: []string{v}})
		}
		_ = w.WriteMsg(m)
	})}
	go srv.ActivateAndServe()
	t.Cleanup(func() { _ = srv.Shutdown() })
	host, port, _ = net.SplitHostPort(pc.LocalAddr().String())
	return
}

func TestInterceptionIsDetectedWhenANonDNSAddressAnswers(t *testing.T) {
	host, port := fakeDNS(t, "cached-by-a-gateway") // stands in for a gateway that answers every address
	oldP, oldPort := interceptProbes, interceptPort
	interceptProbes, interceptPort = []string{host}, port
	t.Cleanup(func() { interceptProbes, interceptPort = oldP, oldPort })
	if hit, via := Intercepted(context.Background()); !hit || via != host {
		t.Fatalf("an answer from an address that should not answer must count as interception: %v %q", hit, via)
	}
	// "no such name" is still an answer from something that should not be answering
	nxHost, nxPort := fakeDNS(t)
	interceptProbes, interceptPort = []string{nxHost}, nxPort
	if hit, _ := Intercepted(context.Background()); !hit {
		t.Fatal("even an NXDOMAIN reply from a non-DNS address is interception")
	}
}

func TestACleanNetworkIsNotFlaggedAsIntercepted(t *testing.T) {
	// a port nothing listens on: the query gets no answer, as on an untouched network
	l, _ := net.ListenPacket("udp", "127.0.0.1:0")
	_, port, _ := net.SplitHostPort(l.LocalAddr().String())
	l.Close()
	oldP, oldPort := interceptProbes, interceptPort
	interceptProbes, interceptPort = []string{"127.0.0.1"}, port
	t.Cleanup(func() { interceptProbes, interceptPort = oldP, oldPort })
	if hit, _ := Intercepted(context.Background()); hit {
		t.Fatal("no answer must not be reported as interception")
	}
}

func TestNoRecordAtANameIsAnAnswerNotAFailure(t *testing.T) {
	host, port := fakeDNS(t) // NXDOMAIN
	old := dnsPortForTest
	_ = old
	// txtAt always dials :53, so check the classification through the resolver it builds
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "udp", net.JoinHostPort(host, port))
	}}
	_, err := r.LookupTXT(context.Background(), "_acme-challenge.fortigate.example.net")
	var de *net.DNSError
	if err == nil || !asNotFound(err, &de) {
		t.Fatalf("expected a not-found DNSError, got %v", err)
	}
	if got := describeObservation("gwen.ns.cloudflare.com", nil, nil, "ours"); !strings.Contains(got, "serves no TXT record") {
		t.Fatalf("an empty answer must read as 'no TXT record', not as a failure to ask: %q", got)
	}
}

const dnsPortForTest = "53"

func asNotFound(err error, target **net.DNSError) bool {
	de, ok := err.(*net.DNSError)
	if ok {
		*target = de
	}
	return ok && de.IsNotFound
}

func TestFixedWaitReplacesTheCheckAndNeverAsksTheNameservers(t *testing.T) {
	asked := 0
	check := func(_ context.Context, fqdn, value string) (bool, error) { asked++; return true, nil }
	w := &waiter{ctx: context.Background(), settle: 60 * time.Millisecond}

	if stop, err := w.run(context.Background(), "d", "_acme-challenge.d.", "v", check); stop || err != nil {
		t.Fatalf("too early: must keep waiting, got stop=%v err=%v", stop, err)
	}
	time.Sleep(80 * time.Millisecond)
	if stop, err := w.run(context.Background(), "d", "_acme-challenge.d.", "v", check); !stop || err != nil {
		t.Fatalf("after the wait it must let validation proceed, got stop=%v err=%v", stop, err)
	}
	if asked != 0 {
		t.Fatal("in fixed-wait mode the (untrustworthy) nameserver check must not be consulted at all")
	}
}

func TestNormalModeDelegatesToTheCheckAndStopsWhenCancelled(t *testing.T) {
	calls := 0
	check := dns01.PreCheckFunc(func(_ context.Context, fqdn, value string) (bool, error) { calls++; return false, nil })
	w := &waiter{ctx: context.Background()}
	if stop, _ := w.run(context.Background(), "d", "f.", "v", check); stop || calls != 1 {
		t.Fatalf("normal mode must ask the real check: stop=%v calls=%d", stop, calls)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w = &waiter{ctx: ctx}
	if stop, err := w.run(context.Background(), "d", "f.", "v", check); !stop || err != errCancelled {
		t.Fatalf("a stopped issuance must end the wait at once: stop=%v err=%v", stop, err)
	}
}

func TestIssuingWithoutDNSCredentialsFailsAtOnceWithoutTouchingTheNetwork(t *testing.T) {
	i := &Issuer{DataDir: t.TempDir()}
	_, err := i.Issue(context.Background(), Request{
		Name: "x", Domains: []string{"fw.example.com"}, KeyType: "rsa2048",
		Settings: model.Settings{ACMEDirectory: model.DirProduction, ACMEEmail: "a@example.com"},
	})
	if err == nil || !strings.Contains(err.Error(), "DNS credentials") {
		t.Fatalf("a certificate without DNS credentials must be refused with that reason: %v", err)
	}
}
