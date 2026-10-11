package targets

import (
	"testing"

	"github.com/CautiousCapsLock/certsmith/internal/plugin"
)

// Saving a target disarms it (the next deployment is manual again) when a setting that decides what is
// installed changed. Only settings that cannot change that are marked NoRedeploy, and every one of them is.
func TestOnlyWatchingAndTrustSettingsNeedNoRedeploy(t *testing.T) {
	noRedeploy := map[string]bool{"verify": true, "pin_sha256": true, "ca_pem": true, "server_name": true, "insecure": true, "fos_version": true}
	for _, d := range []plugin.Descriptor{
		fortiGate{}.Descriptor(), pveTarget{}.Descriptor(), (fortiMgr{kind: "fortimanager"}).Descriptor(), (fortiMgr{kind: "fortianalyzer"}).Descriptor(),
	} {
		for _, f := range d.Fields {
			if f.NoRedeploy != noRedeploy[f.Key] {
				t.Errorf("%s: field %q NoRedeploy = %v, want %v", d.Kind, f.Key, f.NoRedeploy, noRedeploy[f.Key])
			}
		}
	}
}
