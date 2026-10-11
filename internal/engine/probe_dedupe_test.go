package engine

import (
	"errors"
	"reflect"
	"testing"

	"github.com/CautiousCapsLock/certsmith/internal/model"
)

func namesTable(table map[string][]string, calls *int) func(string) ([]string, error) {
	return func(h string) ([]string, error) {
		if calls != nil {
			*calls++
		}
		if ips, ok := table[h]; ok {
			return ips, nil
		}
		return nil, errors.New("no such host")
	}
}

func TestAnIPAndANameThatAreTheSameEndpointAreCheckedOnce(t *testing.T) {
	dns := namesTable(map[string][]string{
		"pve.lab.example":   {"192.0.2.15"},
		"two.lab.example":   {"192.0.2.15", "192.0.2.16"},
		"v6.lab.example":    {"2001:db8::15"},
		"other.lab.example": {"192.0.2.99"},
	}, nil)
	for _, tc := range []struct {
		name string
		in   []string
		want []string
	}{
		{"name typed, IP automatic", []string{"pve.lab.example:8006", "192.0.2.15:8006"}, []string{"pve.lab.example:8006"}},
		{"IP first, name second", []string{"192.0.2.15:8006", "pve.lab.example:8006"}, []string{"pve.lab.example:8006"}},
		{"no port means 443 on both", []string{"192.0.2.15", "pve.lab.example:443"}, []string{"pve.lab.example:443"}},
		{"another port is another endpoint", []string{"pve.lab.example:8006", "192.0.2.15:443"}, []string{"pve.lab.example:8006", "192.0.2.15:443"}},
		{"a name with several addresses merges nothing", []string{"two.lab.example:443", "192.0.2.15:443"}, []string{"two.lab.example:443", "192.0.2.15:443"}},
		{"a different IP is kept", []string{"other.lab.example:443", "192.0.2.15:443"}, []string{"other.lab.example:443", "192.0.2.15:443"}},
		{"two names are never merged", []string{"pve.lab.example:443", "other.lab.example:443"}, []string{"pve.lab.example:443", "other.lab.example:443"}},
		{"an unresolvable name merges nothing", []string{"ghost.lab.example:443", "192.0.2.15:443"}, []string{"ghost.lab.example:443", "192.0.2.15:443"}},
		{"IPv6 in brackets", []string{"v6.lab.example:8443", "[2001:db8::15]:8443"}, []string{"v6.lab.example:8443"}},
	} {
		if got := dropShadowedIPs(tc.in, dns); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: %v -> %v, want %v", tc.name, tc.in, got, tc.want)
		}
	}
}

func TestNoNameLookupIsMadeWhenThereIsNothingToMerge(t *testing.T) {
	calls := 0
	dns := namesTable(nil, &calls)
	dropShadowedIPs([]string{"a.example:443", "b.example:443"}, dns)
	dropShadowedIPs([]string{"192.0.2.1:443", "192.0.2.2:443"}, dns)
	if calls != 0 {
		t.Errorf("%d lookups for lists with only names or only IPs", calls)
	}
}

// The device's address is an IP and its DNS name was typed under Verify: the target lists one endpoint.
func TestATargetAddressedByIPAndVerifiedByItsNameShowsOneEndpoint(t *testing.T) {
	old := lookupHost
	lookupHost = namesTable(map[string][]string{"pve.lab.example": {"192.0.2.15"}}, nil)
	defer func() { lookupHost = old }()
	e := newEngine(t)
	tg := model.Target{ID: "p1", Name: "PVE", Kind: "pve", CertID: "c1", Enabled: true,
		Config: map[string]string{"host": "192.0.2.15", "node": "pve", "token": "x", "verify": "pve.lab.example:8006"}}
	got := e.probeAddrs(tg)
	if !reflect.DeepEqual(got, []string{"pve.lab.example:8006"}) {
		t.Errorf("probeAddrs = %v, want only the name", got)
	}
	// without the typed name, the automatic address by IP is still checked
	tg.Config["verify"] = ""
	if got := e.probeAddrs(tg); !reflect.DeepEqual(got, []string{"192.0.2.15:8006"}) {
		t.Errorf("probeAddrs = %v, want the automatic IP address", got)
	}
}
