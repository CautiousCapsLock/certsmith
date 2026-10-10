package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/CautiousCapsLock/certsmith/internal/model"
)

func TestDeploymentsAndTestsLeaveAnAPICallHistory(t *testing.T) {
	e := newEngine(t)
	if err := e.Issue(context.Background(), "c1"); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	cfg := map[string]string{"url": srv.URL + "/hook/secret-token", "insecure": "true"}
	_ = e.St.Update(func(db *model.DB) error {
		db.Targets = append(db.Targets, model.Target{ID: "t1", Name: "hook", Kind: "webhook", CertID: "c1", Enabled: true, Config: cfg})
		return nil
	})
	if calls, err := e.TargetCalls("t1"); err != nil || len(calls) != 0 {
		t.Fatalf("before anything ran: %v %v", calls, err)
	}
	if err := e.Deploy(context.Background(), "t1"); err != nil {
		t.Fatal(err)
	}
	calls, err := e.TargetCalls("t1")
	if err != nil || len(calls) != 1 {
		t.Fatalf("calls = %+v err = %v", calls, err)
	}
	if c := calls[0]; c.Op != "deploy" || c.Method != "POST" || c.Status != 200 || c.Path != "/…" || c.Time.IsZero() {
		t.Fatalf("recorded call = %+v", c)
	}

	// a saved target's test is remembered too, and returned to the caller
	_, tcalls, err := e.TestTargetCalls(context.Background(), "t1", "fortigate",
		map[string]string{"host": "127.0.0.1", "port": "1", "token": "x", "uses": "admin-gui"}, "")
	if err == nil || len(tcalls) == 0 || tcalls[0].Op != "test" || tcalls[0].Error == "" {
		t.Fatalf("a test against a closed port should fail and say how: calls=%+v err=%v", tcalls, err)
	}
	all, _ := e.TargetCalls("t1")
	if len(all) != 1+len(tcalls) || all[0].Op != "deploy" {
		t.Fatalf("history = %+v", all)
	}

	// a test of an unsaved target is returned but not stored
	if _, _, err := e.TestTargetCalls(context.Background(), "", "fortigate",
		map[string]string{"host": "127.0.0.1", "port": "1", "token": "x", "uses": "admin-gui"}, ""); err == nil {
		t.Fatal("expected failure")
	}
	if again, _ := e.TargetCalls("t1"); len(again) != len(all) {
		t.Fatal("an unsaved target's test must not be added to a saved target's history")
	}

	e.ForgetCalls("t1")
	if gone, _ := e.TargetCalls("t1"); len(gone) != 0 {
		t.Fatalf("history survived the target: %+v", gone)
	}
}

func TestTheCallHistoryKeepsOnlyTheMostRecent(t *testing.T) {
	e := newEngine(t)
	for i := 0; i < 5; i++ {
		batch := make([]model.APICall, 100)
		for j := range batch {
			batch[j] = model.APICall{Op: "deploy", Method: "GET", Path: "/x", Millis: int64(i*100 + j)}
		}
		e.recordCalls("t9", batch)
	}
	all, err := e.TargetCalls("t9")
	if err != nil || len(all) != keepCalls {
		t.Fatalf("kept %d (err %v), want %d", len(all), err, keepCalls)
	}
	if all[len(all)-1].Millis != 499 || all[0].Millis != 500-keepCalls {
		t.Fatalf("not the newest ones: first %d last %d", all[0].Millis, all[len(all)-1].Millis)
	}
}
