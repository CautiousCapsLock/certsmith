// Package dns registers the DNS-01 provider plugins.
package dns

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/providers/dns"
	"github.com/go-acme/lego/v5/providers/dns/cloudflare"

	"github.com/CautiousCapsLock/certsmith/internal/plugin"
)

func init() {
	plugin.RegisterDNS(cloudflareProvider{})
	plugin.RegisterDNS(legoProvider{})
	for _, s := range simpleProviders {
		plugin.RegisterDNS(s)
	}
}

type cloudflareProvider struct{}

func (cloudflareProvider) Descriptor() plugin.Descriptor {
	return plugin.Descriptor{
		Kind:  "cloudflare",
		Label: "Cloudflare",
		Help:  "Use a scoped API token with Zone:DNS:Edit on the zones you issue for (plus Zone:Zone:Read unless you also set a zone token).",
		Fields: []plugin.Field{
			{Key: "api_token", Label: "API token", Type: "password", Required: true, Secret: true},
			{Key: "zone_token", Label: "Zone token (optional)", Type: "password", Secret: true,
				Help: "Separate token with only Zone:Read, if you prefer to split permissions."},
			{Key: "ttl", Label: "TTL (seconds)", Type: "number", Default: "120"},
			{Key: "propagation_seconds", Label: "Propagation timeout (seconds)", Type: "number", Default: "300",
				Help: "The most CertSmith waits for the record to appear. It continues as soon as it does, so a long limit costs nothing when DNS is quick."},
		},
	}
}

func (cloudflareProvider) Solver(cfg map[string]string) (challenge.Provider, error) {
	c := cloudflare.NewDefaultConfig()
	c.AuthToken = cfg["api_token"]
	c.ZoneToken = cfg["zone_token"]
	if v, err := strconv.Atoi(cfg["ttl"]); err == nil && v >= 120 {
		c.TTL = v
	}
	if v, err := strconv.Atoi(cfg["propagation_seconds"]); err == nil && v > 0 {
		c.PropagationTimeout = time.Duration(v) * time.Second
	}
	return cloudflare.NewDNSProviderConfig(c)
}

// legoProvider exposes every other lego DNS provider by code name. Credentials
// are supplied as the environment variables that provider documents.
type legoProvider struct{}

func (legoProvider) Descriptor() plugin.Descriptor {
	return plugin.Descriptor{
		Kind:  "lego",
		Label: "Other (any lego provider)",
		Help:  "Covers 190+ providers. See go-acme.github.io/lego/dns for the provider code and the environment variables it needs.",
		Fields: []plugin.Field{
			{Key: "provider", Label: "Provider code", Type: "text", Required: true,
				Help: "For example hostinger, infomaniak, selectel, yandex360."},
			{Key: "env", Label: "Environment variables", Type: "textarea", Required: true, Secret: true,
				Help: "One KEY=VALUE per line, exactly as the lego docs list them."},
		},
	}
}

func (legoProvider) Solver(cfg map[string]string) (challenge.Provider, error) {
	env := map[string]string{}
	for _, line := range strings.Split(cfg["env"], "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("bad environment line %q (want KEY=VALUE)", line)
		}
		env[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	code := strings.TrimSpace(cfg["provider"])
	return withEnv(env, func() (challenge.Provider, error) { return dns.NewDNSChallengeProviderByName(code) })
}

// envMu serialises the temporary environment changes lego providers require:
// they read credentials from the process environment when constructed.
var envMu sync.Mutex

// withEnv sets the variables, runs build, then restores the previous environment.
func withEnv(env map[string]string, build func() (challenge.Provider, error)) (challenge.Provider, error) {
	envMu.Lock()
	defer envMu.Unlock()
	for k, v := range env {
		old, had := os.LookupEnv(k)
		defer func() {
			if had {
				os.Setenv(k, old)
			} else {
				os.Unsetenv(k)
			}
		}()
		os.Setenv(k, v)
	}
	return build()
}
