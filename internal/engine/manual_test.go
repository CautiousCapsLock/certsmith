package engine

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/CautiousCapsLock/certsmith/internal/model"
	_ "github.com/CautiousCapsLock/certsmith/internal/targets" // registers the target types
)

// A device whose certificate is installed by hand is never "deployed to", so a different certificate
// on it must count as a problem straight away; for an ordinary target it only counts once CertSmith
// believes the device is up to date.
func TestAManuallyInstalledTargetThatServesTheWrongCertificateIsAProblem(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))

	e := newEngine(t)
	_ = e.St.Update(func(db *model.DB) error {
		db.Certificates[0].Serial = "feedface" // not what the server presents
		db.Targets = append(db.Targets,
			model.Target{ID: "m1", Name: "EMS", Kind: "forticlientems", CertID: "c1", Enabled: true,
				Config: map[string]string{"host": "127.0.0.1", "port": port, "client_port": "0"}},
			model.Target{ID: "w1", Name: "FGT", Kind: "watch", CertID: "c1", Enabled: true,
				Config: map[string]string{"verify": "127.0.0.1:" + port}})
		return nil
	})
	e.probeTarget(context.Background(), "m1")
	e.probeTarget(context.Background(), "w1")
	probes := func(id string) []model.ProbeResult {
		for _, tg := range e.St.Snapshot().Targets {
			if tg.ID == id {
				return tg.Probes
			}
		}
		return nil
	}
	if p := probes("m1"); len(p) != 1 || p[0].Match || p[0].Bad < 1 {
		t.Errorf("manual target probes = %+v, want one mismatch counted as bad", p)
	}
	if p := probes("w1"); len(p) != 1 || p[0].Match || p[0].Bad != 0 {
		t.Errorf("ordinary target not yet deployed must not count a mismatch as bad: %+v", p)
	}
}
