package engine

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-acme/lego/v5/challenge"

	"github.com/CautiousCapsLock/certsmith/internal/plugin"
)

type refusingProvider struct{ cleaned bool }

func (p *refusingProvider) Present(_ context.Context, domain, token, keyAuth string) error {
	return errors.New("cloudflare: failed to create TXT record: HTTP 403 Forbidden")
}
func (p *refusingProvider) CleanUp(_ context.Context, domain, token, keyAuth string) error {
	p.cleaned = true
	return nil
}

type refusingDNS struct{ p *refusingProvider }

func (refusingDNS) Descriptor() plugin.Descriptor {
	return plugin.Descriptor{Kind: "dnstest-refuse", Label: "test", Fields: []plugin.Field{{Key: "t", Label: "t", Type: "text"}}}
}
func (r refusingDNS) Solver(map[string]string) (challenge.Provider, error) { return r.p, nil }

func TestDNSTestReportsARefusedRecordWithAHint(t *testing.T) {
	e := newEngine(t)
	p := &refusingProvider{}
	plugin.RegisterDNS(refusingDNS{p})

	steps, err := e.TestDNS(context.Background(), "dnstest-refuse", map[string]string{"t": "x"}, "*.Lab.Example", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) < 3 || !steps[0].OK {
		t.Fatalf("steps = %+v", steps)
	}
	if steps[1].OK || !strings.Contains(steps[1].Msg, "refused to create the record") || !strings.Contains(steps[1].Msg, "403") {
		t.Fatalf("the provider's refusal must be reported verbatim: %+v", steps[1])
	}
	if !steps[2].Info || !strings.Contains(steps[2].Msg, "rejected the credentials") {
		t.Fatalf("a refusal should come with a hint: %+v", steps[2])
	}
	if p.cleaned {
		t.Fatal("nothing was created, so nothing should be cleaned up")
	}
}

func TestDNSTestNeedsADomain(t *testing.T) {
	e := newEngine(t)
	plugin.RegisterDNS(refusingDNS{&refusingProvider{}})
	if _, err := e.TestDNS(context.Background(), "dnstest-refuse", map[string]string{"t": "x"}, "  ", time.Second); err == nil {
		t.Fatal("expected an error without a domain")
	}
}
