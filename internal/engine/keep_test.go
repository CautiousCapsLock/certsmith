package engine

import (
	"context"
	"sync"
	"testing"

	"github.com/CautiousCapsLock/certsmith/internal/model"
	"github.com/CautiousCapsLock/certsmith/internal/plugin"
)

// captureTarget records the configuration a deployment was given.
type captureTarget struct {
	mu  sync.Mutex
	got map[string]string
}

func (c *captureTarget) Descriptor() plugin.Descriptor {
	return plugin.Descriptor{Kind: "keepcapture", Label: "capture"}
}
func (c *captureTarget) Test(context.Context, map[string]string) (string, error) { return "ok", nil }
func (c *captureTarget) Deploy(_ context.Context, cfg map[string]string, _ *plugin.Bundle) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.got = map[string]string{}
	for k, v := range cfg {
		c.got[k] = v
	}
	return "ok", nil
}

var (
	captureOnce sync.Once
	capture     = &captureTarget{}
)

func TestADeploymentCarriesTheNumberOfCertificatesToKeepFromSettings(t *testing.T) {
	captureOnce.Do(func() { plugin.RegisterTarget(capture) })
	e := newEngine(t)
	if err := e.Issue(context.Background(), "c1"); err != nil {
		t.Fatal(err)
	}
	_ = e.St.Update(func(db *model.DB) error {
		db.Targets = append(db.Targets, model.Target{ID: "t1", Name: "dev", Kind: "keepcapture", CertID: "c1", Enabled: true, AutoDeploy: true})
		return nil
	})
	for _, tc := range []struct {
		setting int
		want    string
	}{{0, "3"}, {5, "5"}, {1, "1"}} {
		_ = e.St.Update(func(db *model.DB) error { db.Settings.KeepOnDevice = tc.setting; return nil })
		if err := e.Deploy(context.Background(), "t1"); err != nil {
			t.Fatal(err)
		}
		capture.mu.Lock()
		got := capture.got["_keep_total"]
		capture.mu.Unlock()
		if got != tc.want {
			t.Errorf("setting %d: the plugin was told to keep %q, want %q", tc.setting, got, tc.want)
		}
	}
}
