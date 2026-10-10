package engine

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/CautiousCapsLock/certsmith/internal/model"
)

// fakeDNS answers TXT queries for one name with whatever values it is told to serve.
type fakeDNS struct {
	mu     sync.Mutex
	values []string
	addr   string
}

func startFakeDNS(t *testing.T, values ...string) *fakeDNS {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeDNS{values: values, addr: pc.LocalAddr().String()}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		f.mu.Lock()
		for _, v := range f.values {
			m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 1}, Txt: []string{v}})
		}
		f.mu.Unlock()
		_ = w.WriteMsg(m)
	})}
	go srv.ActivateAndServe()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return f
}

func (f *fakeDNS) set(values ...string) { f.mu.Lock(); f.values = values; f.mu.Unlock() }

func TestCleanupIsConfirmedAgainstTheNameservers(t *testing.T) {
	f := startFakeDNS(t, "other-tools-record", "our-test-value")
	host, port, _ := net.SplitHostPort(f.addr)
	oldPort, oldTimeout := dnsPort, goneTimeout
	dnsPort, goneTimeout = port, 1500*time.Millisecond
	t.Cleanup(func() { dnsPort, goneTimeout = oldPort, oldTimeout })
	e := newEngine(t)

	// the provider "removed" it but the server still serves it: that must NOT count as removed
	if e.waitGone([]string{host}, "_acme-challenge.x.example.", "our-test-value") {
		t.Fatal("a record that is still being served was reported as removed")
	}
	// now it really is gone (the other tool's record stays, and does not matter)
	f.set("other-tools-record")
	if !e.waitGone([]string{host}, "_acme-challenge.x.example.", "our-test-value") {
		t.Fatal("a removed record was reported as still present")
	}
}

func TestAnInterruptedTestIsRememberedAcrossARestart(t *testing.T) {
	e := newEngine(t)
	e.addPending(model.PendingDNS{ID: "p1", Provider: "cloudflare", Fqdn: "_acme-challenge.example.com.", Value: "yhn4Wq", Since: time.Now(), Note: "DNS test"})

	e2 := New(e.St, e.Box, e.DataDir, e.Log) // the process came back after being killed mid-test
	var pending []model.PendingDNS
	var events []model.Event
	e2.St.View(func(db *model.DB) { pending, events = append(pending, db.PendingDNS...), append(events, db.Events...) })
	if len(pending) != 1 {
		t.Fatalf("the leftover record must still be listed after a restart: %+v", pending)
	}
	found := false
	for _, ev := range events {
		if strings.Contains(ev.Message, "yhn4Wq") && strings.Contains(ev.Message, "delete it") {
			found = true
		}
	}
	if !found {
		t.Fatalf("a restart must say which record may be left behind: %+v", events)
	}
	e2.DismissPending("p1")
	e2.St.View(func(db *model.DB) { pending = db.PendingDNS })
	if len(pending) != 0 {
		t.Fatal("dismissing must forget it")
	}
}

func TestShutdownWaitsForRunningWorkAndIsNotAUserStop(t *testing.T) {
	e := newEngine(t)
	bi := &blockingIssuer{started: make(chan struct{}, 1)}
	e.issuer = bi
	if err := e.StartIssue("c1"); err != nil {
		t.Fatal(err)
	}
	<-bi.started

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	e.Drain(ctx) // what the process does on SIGTERM
	if ctx.Err() != nil {
		t.Fatal("Drain should return as soon as the running work has finished, not wait out the deadline")
	}

	c := cert(e)
	if c.Issuing {
		t.Fatal("work must have finished (and released its spinner) before exit")
	}
	if !c.CancelledAt.IsZero() || c.LastError != "" {
		t.Fatalf("a restart is not the user pressing Stop and not a failure: cancelled_at=%v error=%q", c.CancelledAt, c.LastError)
	}
	if log, _ := e.IssueLog("c1"); !strings.Contains(log, "INTERRUPTED") {
		t.Fatalf("the log should say it was interrupted by a restart: %q", log)
	}
}
