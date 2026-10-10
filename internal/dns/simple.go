package dns

import (
	"strings"

	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/providers/dns"

	"github.com/CautiousCapsLock/certsmith/internal/plugin"
)

// envField is one credential a lego provider reads from its environment. The
// UI shows Label; the environment variable name doubles as the config key.
type envField struct {
	env      string
	label    string
	secret   bool
	optional bool
	def      string
	options  []string
	help     string
}

// simple adapts a lego provider that is configured purely by environment
// variables into a plugin with a proper form, so each provider gets named
// fields instead of a free-text box.
type simple struct {
	kind   string // also the lego provider code
	label  string
	help   string
	fields []envField
}

func (s simple) Descriptor() plugin.Descriptor {
	d := plugin.Descriptor{Kind: s.kind, Label: s.label, Help: s.help}
	for _, f := range s.fields {
		t := "text"
		switch {
		case f.options != nil:
			t = "select"
		case f.secret:
			t = "password"
		}
		d.Fields = append(d.Fields, plugin.Field{
			Key: f.env, Label: f.label, Type: t, Required: !f.optional,
			Secret: f.secret, Default: f.def, Options: f.options, Help: f.help,
		})
	}
	return d
}

func (s simple) Solver(cfg map[string]string) (challenge.Provider, error) {
	env := map[string]string{}
	for _, f := range s.fields {
		if v := strings.TrimSpace(cfg[f.env]); v != "" {
			env[f.env] = v
		}
	}
	return withEnv(env, func() (challenge.Provider, error) { return dns.NewDNSChallengeProviderByName(s.kind) })
}

func tok(env, label string) envField { return envField{env: env, label: label, secret: true} }
func txt(env, label string) envField { return envField{env: env, label: label} }

var simpleProviders = []simple{
	{kind: "route53", label: "Amazon Route 53",
		help: "An IAM user with route53:ChangeResourceRecordSets, ListHostedZonesByName and GetChange on your zone.",
		fields: []envField{
			txt("AWS_ACCESS_KEY_ID", "Access key ID"), tok("AWS_SECRET_ACCESS_KEY", "Secret access key"),
			{env: "AWS_REGION", label: "Region", def: "us-east-1"},
			{env: "AWS_HOSTED_ZONE_ID", label: "Hosted zone ID (optional)", optional: true, help: "Only needed if the zone cannot be found by name."},
		}},
	{kind: "azuredns", label: "Azure DNS",
		help: "A service principal with the DNS Zone Contributor role on the zone's resource group.",
		fields: []envField{
			txt("AZURE_SUBSCRIPTION_ID", "Subscription ID"), txt("AZURE_RESOURCE_GROUP", "Resource group"),
			txt("AZURE_TENANT_ID", "Tenant ID"), txt("AZURE_CLIENT_ID", "Client (application) ID"), tok("AZURE_CLIENT_SECRET", "Client secret"),
		}},
	{kind: "digitalocean", label: "DigitalOcean", fields: []envField{tok("DO_AUTH_TOKEN", "API token (read/write)")}},
	{kind: "hetzner", label: "Hetzner DNS", fields: []envField{tok("HETZNER_API_TOKEN", "API token")}},
	{kind: "godaddy", label: "GoDaddy", fields: []envField{txt("GODADDY_API_KEY", "API key"), tok("GODADDY_API_SECRET", "API secret")}},
	{kind: "namecheap", label: "Namecheap",
		help:   "Namecheap only accepts API calls from allow-listed IPs: add this server's public IP in their dashboard.",
		fields: []envField{txt("NAMECHEAP_API_USER", "API user"), tok("NAMECHEAP_API_KEY", "API key")}},
	{kind: "ovh", label: "OVH",
		fields: []envField{
			{env: "OVH_ENDPOINT", label: "Endpoint", def: "ovh-eu", options: []string{"ovh-eu", "ovh-ca", "ovh-us", "kimsufi-eu", "kimsufi-ca", "soyoustart-eu", "soyoustart-ca"}},
			txt("OVH_APPLICATION_KEY", "Application key"), tok("OVH_APPLICATION_SECRET", "Application secret"), tok("OVH_CONSUMER_KEY", "Consumer key"),
		}},
	{kind: "gandiv5", label: "Gandi LiveDNS", fields: []envField{tok("GANDIV5_PERSONAL_ACCESS_TOKEN", "Personal access token")}},
	{kind: "duckdns", label: "DuckDNS", fields: []envField{tok("DUCKDNS_TOKEN", "Token")}},
	{kind: "porkbun", label: "Porkbun", fields: []envField{txt("PORKBUN_API_KEY", "API key"), tok("PORKBUN_SECRET_API_KEY", "Secret API key")}},
	{kind: "vultr", label: "Vultr", fields: []envField{tok("VULTR_API_KEY", "API key")}},
	{kind: "linode", label: "Linode / Akamai", fields: []envField{tok("LINODE_TOKEN", "API token")}},
	{kind: "desec", label: "deSEC", fields: []envField{tok("DESEC_TOKEN", "API token")}},
	{kind: "bunny", label: "bunny.net", fields: []envField{tok("BUNNY_API_KEY", "API key")}},
	{kind: "ionos", label: "IONOS", fields: []envField{tok("IONOS_API_KEY", "API key (prefix.secret)")}},
	{kind: "netcup", label: "netcup",
		fields: []envField{txt("NETCUP_CUSTOMER_NUMBER", "Customer number"), txt("NETCUP_API_KEY", "API key"), tok("NETCUP_API_PASSWORD", "API password")}},
	{kind: "scaleway", label: "Scaleway", fields: []envField{tok("SCALEWAY_API_TOKEN", "API secret key")}},
	{kind: "dnsimple", label: "DNSimple", fields: []envField{tok("DNSIMPLE_OAUTH_TOKEN", "OAuth token")}},
	{kind: "cloudns", label: "ClouDNS", fields: []envField{txt("CLOUDNS_AUTH_ID", "Auth ID"), tok("CLOUDNS_AUTH_PASSWORD", "Auth password")}},
	{kind: "pdns", label: "PowerDNS",
		help:   "Self-hosted PowerDNS authoritative server with the HTTP API enabled.",
		fields: []envField{txt("PDNS_API_URL", "API URL (e.g. http://ns1.lab:8081)"), tok("PDNS_API_KEY", "API key")}},
	{kind: "technitium", label: "Technitium DNS Server",
		help:   "Self-hosted Technitium server; use an API token for a user allowed to edit the zone.",
		fields: []envField{txt("TECHNITIUM_SERVER_BASE_URL", "Server URL (e.g. http://dns.lab:5380)"), tok("TECHNITIUM_API_TOKEN", "API token")}},
	{kind: "rfc2136", label: "RFC 2136 (BIND / dynamic update)",
		help: "For BIND and other servers that accept TSIG-signed dynamic updates. Allow updates to _acme-challenge records for the key.",
		fields: []envField{
			txt("RFC2136_NAMESERVER", "Nameserver (host:port)"),
			{env: "RFC2136_TSIG_ALGORITHM", label: "TSIG algorithm", def: "hmac-sha256.", options: []string{"hmac-sha256.", "hmac-sha384.", "hmac-sha512.", "hmac-sha1."}},
			txt("RFC2136_TSIG_KEY", "TSIG key name"), tok("RFC2136_TSIG_SECRET", "TSIG secret (base64)"),
		}},
}
