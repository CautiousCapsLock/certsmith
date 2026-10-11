package web

import (
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
