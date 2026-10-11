package web

import (
	"strings"
	"testing"

	"github.com/CautiousCapsLock/certsmith/internal/model"
)

func TestTheEndpointCheckSummaryCountsWhatThePageMarksAsAProblem(t *testing.T) {
	ok := model.ProbeResult{Addr: "a.example.com:443", Match: true}
	wrong := model.ProbeResult{Addr: "b.example.com:443", Match: false}
	down := model.ProbeResult{Addr: "c.example.com:443", Error: "connection refused"}
	got := summariseProbes([]model.Target{
		{Enabled: true, CertID: "c1", Probes: []model.ProbeResult{ok, wrong}},
		{Enabled: true, CertID: "c1", Probes: []model.ProbeResult{down}},
		{Enabled: true, CertID: "", Probes: []model.ProbeResult{wrong}},   // monitor-only: no expected certificate, so not a mismatch
		{Enabled: false, CertID: "c1", Probes: []model.ProbeResult{down}}, // switched off: not counted
		{Enabled: true, CertID: "c1"},                                     // nothing to check
	})
	if got.Targets != 3 || got.Checked != 4 || got.Problems != 2 {
		t.Fatalf("summary = %+v, want 3 targets, 4 endpoints, 2 problems", got)
	}
}

func TestDiscoverTargetNeedsASessionAndOnlyWorksForPluginsThatCan(t *testing.T) {
	ts, _ := newTestServer(t)
	c := setupAndLogin(t, ts)
	if code, _, _ := call(t, newClient(), "POST", ts.URL+"/api/discover-target", map[string]any{"kind": "fortigate"}, false, nil); code == 200 {
		t.Error("an unauthenticated visitor must not be able to make the server contact a device")
	}
	if code, _, _ := call(t, c, "POST", ts.URL+"/api/discover-target", map[string]any{"kind": "nope", "config": map[string]string{}}, false, nil); code != 400 {
		t.Errorf("unknown kind = %d, want 400", code)
	}
	code, body, _ := call(t, c, "POST", ts.URL+"/api/discover-target", map[string]any{"kind": "watch", "config": map[string]string{"verify": "a.example:443"}}, false, nil)
	if code != 400 || !strings.Contains(body, "cannot look at the device") {
		t.Errorf("a type with nothing to discover: %d %s", code, body)
	}
}
