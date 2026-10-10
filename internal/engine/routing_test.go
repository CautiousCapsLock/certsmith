package engine

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/CautiousCapsLock/certsmith/internal/model"
	"github.com/CautiousCapsLock/certsmith/internal/notify"
)

// hook is a webhook endpoint that records what it was sent.
type hook struct {
	srv  *httptest.Server
	mu   sync.Mutex
	msgs []string
}

func newHook(t *testing.T) *hook {
	h := &hook{}
	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		h.mu.Lock()
		h.msgs = append(h.msgs, string(b))
		h.mu.Unlock()
	}))
	t.Cleanup(h.srv.Close)
	return h
}

func (h *hook) count() int { h.mu.Lock(); defer h.mu.Unlock(); return len(h.msgs) }
func (h *hook) all() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return strings.Join(h.msgs, "\n")
}

func useHook(e *Engine, h *hook, routing *model.AlertRouting, notifySuccess bool) {
	_ = e.St.Update(func(db *model.DB) error {
		db.Settings.WebhookURL = h.srv.URL
		db.Settings.AlertRouting = routing
		db.Settings.NotifySuccess = notifySuccess
		return nil
	})
}

func TestAnAlertTypeGoesOnlyWhereItIsRouted(t *testing.T) {
	e := newEngine(t)
	h := newHook(t)
	useHook(e, h, &model.AlertRouting{Webhook: []string{notify.CertIssued}}, false)

	e.Notify(context.Background(), notify.DeployOK, "deployed", "not routed anywhere")
	if h.count() != 0 {
		t.Fatalf("a type that is not routed must not be sent: %s", h.all())
	}
	e.Notify(context.Background(), notify.CertIssued, "issued", "routed to the webhook")
	if h.count() != 1 || !strings.Contains(h.all(), "routed to the webhook") {
		t.Fatalf("webhook got %d: %s", h.count(), h.all())
	}
}

func TestWithoutAChoiceProblemsAreSentAndSuccessesFollowTheOldSwitch(t *testing.T) {
	e := newEngine(t)
	h := newHook(t)
	useHook(e, h, nil, false) // never chosen: the behaviour before alert types existed
	e.Notify(context.Background(), notify.CertIssued, "issued", "a success")
	if h.count() != 0 {
		t.Fatal("successes were off by default")
	}
	e.Notify(context.Background(), notify.UserCreated, "user", "an admin event")
	if h.count() != 0 {
		t.Fatal("admin events are off until someone ticks them")
	}
	_ = e.St.Update(func(db *model.DB) error { db.Settings.NotifySuccess = true; return nil })
	e.Notify(context.Background(), notify.CertIssued, "issued", "a success, switch on")
	if h.count() != 1 {
		t.Fatalf("the old success switch must still work until routing is chosen: %d", h.count())
	}
}

func TestCheckAlertsSendsEachProblemOnlyToItsChannels(t *testing.T) {
	e := newEngine(t)
	h := newHook(t)
	// the webhook wants deployment problems but not certificate problems
	useHook(e, h, &model.AlertRouting{Webhook: []string{notify.DeployFailed}}, false)
	_ = e.St.Update(func(db *model.DB) error {
		db.Certificates[0].LastError = "issuance is failing"
		db.Targets = append(db.Targets, model.Target{ID: "t1", Name: "fw", Kind: "files", CertID: "c1", Enabled: true, LastError: "boom"})
		return nil
	})
	e.CheckAlerts(context.Background())
	got := h.all()
	if !strings.Contains(got, "deployment failing") {
		t.Fatalf("the routed problem must be sent: %q", got)
	}
	if strings.Contains(got, "issuance failing") {
		t.Fatalf("a certificate problem must not go to a channel that did not ask for it: %q", got)
	}
	// both problems still appear in the certificate events
	n := 0
	e.St.View(func(db *model.DB) {
		for _, ev := range db.Events {
			if ev.Subject == "alert" {
				n++
			}
		}
	})
	if n != 2 {
		t.Fatalf("events for both alerts expected, have %d", n)
	}
	// and the alert is remembered as sent, so it is not repeated at once
	before := h.count()
	e.CheckAlerts(context.Background())
	if h.count() != before {
		t.Fatal("an alert already sent was sent again straight away")
	}
}

func TestNoChannelSetUpMeansNothingIsSentAndNothingFails(t *testing.T) {
	e := newEngine(t)
	_ = e.St.Update(func(db *model.DB) error {
		db.Certificates[0].LastError = "x"
		return nil
	})
	e.CheckAlerts(context.Background()) // no webhook, no email
	e.Notify(context.Background(), notify.CertIssued, "s", "b")
	var n int
	e.St.View(func(db *model.DB) {
		n = len(db.Alerts)
		for _, ev := range db.Events {
			if ev.Subject == "notify" {
				t.Errorf("a delivery failure was reported with no channel configured: %+v", ev)
			}
		}
	})
	if n != 1 {
		t.Fatalf("the alert should still be remembered: %d", n)
	}
}
