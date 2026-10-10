package dns

import (
	"os"
	"testing"

	"github.com/CautiousCapsLock/certsmith/internal/plugin"
)

// Every curated provider must build from its form's fields alone. lego reports
// a missing variable by name, so a wrong environment variable name in the table
// fails here instead of on a user's first issuance.
func TestCuratedProvidersBuildFromTheirForm(t *testing.T) {
	for _, s := range simpleProviders {
		t.Run(s.kind, func(t *testing.T) {
			if s.kind == "azuredns" {
				// Azure contacts Microsoft while constructing, so it cannot run offline.
				// Its variable names were confirmed from lego's own error output instead.
				t.Skip("needs network at construction")
			}
			cfg := map[string]string{}
			for _, f := range s.fields {
				if f.optional {
					continue
				}
				v := f.def
				if v == "" {
					v = "dummy-" + f.env
				}
				cfg[f.env] = v
			}
			// give the dummy values shapes that parse where lego validates them
			if _, ok := cfg["SCALEWAY_API_TOKEN"]; ok {
				cfg["SCALEWAY_API_TOKEN"] = "00000000-0000-0000-0000-000000000000" // validated as a UUID
			}
			if _, ok := cfg["RFC2136_TSIG_SECRET"]; ok {
				cfg["RFC2136_TSIG_SECRET"] = "c2VjcmV0"
			}
			if _, ok := cfg["RFC2136_NAMESERVER"]; ok {
				cfg["RFC2136_NAMESERVER"] = "127.0.0.1:53"
			}
			if _, ok := cfg["PDNS_API_URL"]; ok {
				cfg["PDNS_API_URL"] = "http://127.0.0.1:8081"
			}
			if _, ok := cfg["TECHNITIUM_SERVER_BASE_URL"]; ok {
				cfg["TECHNITIUM_SERVER_BASE_URL"] = "http://127.0.0.1:5380"
			}
			p, err := s.Solver(cfg)
			if err != nil || p == nil {
				t.Fatalf("provider %s did not build from its own form fields: %v", s.kind, err)
			}
			// secrets must not leak into the process environment afterwards
			for _, f := range s.fields {
				if _, set := os.LookupEnv(f.env); set {
					t.Errorf("%s left in the environment", f.env)
				}
			}
		})
	}
}

func TestMissingRequiredFieldIsRejectedByFormValidation(t *testing.T) {
	d := simpleProviders[0].Descriptor()
	if _, err := d.Validate(map[string]string{}); err == nil {
		t.Fatal("empty form should fail required-field validation")
	}
}

func TestDescriptorsAreWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, d := range plugin.DNSDescriptors() {
		if seen[d.Kind] {
			t.Errorf("duplicate kind %s", d.Kind)
		}
		seen[d.Kind] = true
		if d.Label == "" || len(d.Fields) == 0 {
			t.Errorf("%s: missing label or fields", d.Kind)
		}
	}
	for _, want := range []string{"cloudflare", "route53", "lego", "rfc2136"} {
		if !seen[want] {
			t.Errorf("provider %s not registered", want)
		}
	}
}
