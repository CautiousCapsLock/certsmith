// Package model holds the persisted data types shared by every other package.
package model

import "time"

const (
	DirProduction = "production"
	DirStaging    = "staging"
	DirSelfSigned = "selfsigned" // built-in test CA, for demos and development
)

type SMTP struct {
	Enabled  bool     `json:"enabled"`
	Host     string   `json:"host"`
	Port     int      `json:"port"`
	Security string   `json:"security"` // starttls | tls | none
	Username string   `json:"username"`
	Password string   `json:"password"` // sealed
	From     string   `json:"from"`
	To       []string `json:"to"`
}

type Settings struct {
	ACMEDirectory   string `json:"acme_directory"` // production | staging | selfsigned | https://custom/directory
	ACMEEmail       string `json:"acme_email"`
	RenewBeforeDays int    `json:"renew_before_days"`
	// KeepOnDevice is how many CertSmith certificates a device that keeps old ones holds after a
	// deployment, the one in use included. 0 means the default of 3.
	KeepOnDevice int      `json:"keep_on_device"`
	WarnDays     int      `json:"warn_days"`
	ProbeMinutes int      `json:"probe_minutes"`
	DNSResolvers []string `json:"dns_resolvers"` // e.g. 1.1.1.1:53 for propagation checks
	// DNSCheck is how CertSmith decides the DNS challenge record is published: "check" asks the zone's
	// nameservers; "wait" simply waits DNSWaitSeconds; "auto" (default) asks, unless the network
	// intercepts DNS, where the answers cannot be trusted and it waits instead.
	DNSCheck       string `json:"dns_check"`
	DNSWaitSeconds int    `json:"dns_wait_seconds"`
	NotifySuccess  bool   `json:"notify_success"` // legacy: used only while AlertRouting has never been saved
	// AlertRouting says which kinds of alert go to which channel. nil means it was never chosen, and
	// the defaults apply (every problem to every channel; successes only if NotifySuccess).
	AlertRouting *AlertRouting `json:"alert_routing,omitempty"`
	SMTP         SMTP          `json:"smtp"`
	WebhookURL   string        `json:"webhook_url"` // Slack/Teams/generic JSON alerts
	// UpdateCheckDisabled turns off the daily look for a newer release. It is a "disabled" switch so
	// that the zero value, which every existing installation has, means the check is on.
	UpdateCheckDisabled bool `json:"update_check_disabled"`

	// TrustedProxies are the addresses or networks of reverse proxies in front of CertSmith. Only a
	// connection from one of them is believed when it says which client it forwards (X-Forwarded-For).
	TrustedProxies []string `json:"trusted_proxies,omitempty"`
}

func DefaultSettings() Settings {
	return Settings{
		ACMEDirectory:   DirProduction,
		DNSCheck:        "auto",
		DNSWaitSeconds:  25,
		RenewBeforeDays: 30,
		WarnDays:        14,
		ProbeMinutes:    15,
		SMTP:            SMTP{Port: 587, Security: "starttls"},
	}
}

// Certificate authorities a provider can use. The stored value is empty for Let's Encrypt, so
// providers saved before other CAs were supported keep working unchanged.
const (
	AuthorityLE  = "letsencrypt"
	AuthorityEAB = "eab"
)

// DNSProvider is a certificate provider: where certificates come from (which CA, and the account
// there) and how names are proven (the DNS credentials that publish the DNS-01 record). Every
// provider has DNS credentials, because CertSmith validates with DNS-01 only. The type keeps its
// original name because it is stored under it.
// AlertRouting lists, per channel, the alert types (see notify.Types) that channel receives.
type AlertRouting struct {
	Email   []string `json:"email"`
	Webhook []string `json:"webhook"`
}

// AuditEntry is one administrative action: who did what to what, from where. It is kept apart from
// the certificate events, which are about what CertSmith itself did.
type AuditEntry struct {
	Time    time.Time `json:"time"`
	User    string    `json:"user"`              // who; empty when CertSmith did it on its own
	IP      string    `json:"ip,omitempty"`      // where from (behind a reverse proxy: the address it reported)
	Action  string    `json:"action"`            // short and machine-friendly, e.g. user.create
	Subject string    `json:"subject,omitempty"` // what it was done to
	Detail  string    `json:"detail,omitempty"`
}

type DNSProvider struct {
	ID     string            `json:"id"`
	Name   string            `json:"name"`
	Kind   string            `json:"kind"` // the DNS provider type, e.g. cloudflare
	Config map[string]string `json:"config"`

	// Authority is "" (Let's Encrypt, using the directory chosen in Settings) or AuthorityEAB: a CA
	// that needs an External Account Binding, such as ZeroSSL or Sectigo. The fields below belong to
	// that case.
	Authority string `json:"authority,omitempty"`
	CA        string `json:"ca,omitempty"`        // which preset was chosen (zerossl, sectigo, ..., custom); informational
	Directory string `json:"directory,omitempty"` // the CA's ACME directory URL
	EABKid    string `json:"eab_kid,omitempty"`   // key identifier from the CA
	EABHMAC   string `json:"eab_hmac,omitempty"`  // MAC key from the CA, base64url; sealed
	Email     string `json:"email,omitempty"`     // account email at that CA; empty uses the one in Settings
}

// IsEAB reports whether the provider is a CA that needs External Account Binding.
func (p DNSProvider) IsEAB() bool { return p.Authority == AuthorityEAB }

// SourceImport marks a certificate that was uploaded rather than issued.
const SourceImport = "import"

type Certificate struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Domains    []string `json:"domains"` // may include wildcards
	DNSID      string   `json:"dns_id"`  // the DNS credentials that validate the names (DNS-01)
	KeyType    string   `json:"key_type"`
	Enabled    bool     `json:"enabled"`
	AutoRenew  bool     `json:"auto_renew"`
	ForceIssue bool     `json:"force_issue,omitempty"`
	// Source says where the certificate comes from. "" is the normal case: CertSmith issues it over ACME.
	// SourceImport means someone supplied the certificate and its key: CertSmith deploys it, watches
	// it and alerts on its expiry, but never issues or renews it. A replacement is uploaded instead.
	Source     string    `json:"source,omitempty"`
	ImportedAt time.Time `json:"imported_at,omitzero"`
	// PropagationSeconds caps how long to wait for the DNS-01 record to become
	// visible; 0 uses the provider's default.
	PropagationSeconds int `json:"propagation_seconds"`

	// state
	Serial        string    `json:"serial"`
	Issuer        string    `json:"issuer"`
	IssuedDomains []string  `json:"issued_domains"`
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
	LastAttempt   time.Time `json:"last_attempt"`
	LastError     string    `json:"last_error"`
	Issuing       bool      `json:"issuing"` // an issuance is running right now
	Stage         string    `json:"stage"`   // what a running issuance is doing right now, in words
	// IssuedDirectory is the ACME directory the current certificate came from. A certificate from
	// staging is useless in production and vice versa, so changing the directory in Settings
	// reissues it (and it is then deployed like any renewal).
	IssuedDirectory string `json:"issued_directory"`
	// CancelledAt is set when the user stopped an issuance. The scheduler leaves
	// the certificate alone for a while afterwards instead of restarting it.
	CancelledAt time.Time `json:"cancelled_at"`
}

type ProbeResult struct {
	Addr      string    `json:"addr"`
	Serial    string    `json:"serial"`
	Subject   string    `json:"subject"`
	Issuer    string    `json:"issuer"`
	NotAfter  time.Time `json:"not_after"`
	Match     bool      `json:"match"` // served serial == expected serial
	Error     string    `json:"error"`
	CheckedAt time.Time `json:"checked_at"`
	Bad       int       `json:"bad"` // consecutive failed or mismatching checks
	// ChainLen is how many certificates the server sent. A certificate issued by a CA but sent
	// alone (ChainLen 1, not self-signed) is missing its intermediate, so clients that cannot
	// fetch it themselves will not trust it.
	ChainLen   int  `json:"chain_len"`
	SelfSigned bool `json:"self_signed"`
}

type Target struct {
	ID      string            `json:"id"`
	Name    string            `json:"name"`
	Kind    string            `json:"kind"`
	CertID  string            `json:"cert_id"` // empty => monitor-only
	Enabled bool              `json:"enabled"`
	Config  map[string]string `json:"config"`

	// state
	DeployedSerial string `json:"deployed_serial"`
	// AutoDeploy is switched on by the first successful deployment. Until then a newly
	// issued certificate is NOT pushed to the device: the first deployment changes
	// configuration on a real device, so it is always a deliberate click. Afterwards
	// renewals are deployed automatically. Changing where or how it deploys switches it off again.
	AutoDeploy bool `json:"auto_deploy"`
	// Paused suspends automatic deployment to this target. Renewals are still issued, just not
	// pushed to the device until it is resumed (it then catches up by itself).
	Paused bool `json:"paused"`
	// DeployedSHA256 is the fingerprint of the certificate CertSmith installed.
	// The device is trusted when it presents exactly that certificate, even if it
	// is addressed by IP and the name would not match.
	DeployedSHA256 string        `json:"deployed_sha256"`
	DeployedAt     time.Time     `json:"deployed_at"`
	LastAttempt    time.Time     `json:"last_attempt"`
	LastError      string        `json:"last_error"`
	Message        string        `json:"message"`
	Probes         []ProbeResult `json:"probes"`
	Deploying      bool          `json:"deploying"` // a deployment is running right now
}

// APICall is one request CertSmith sent to a device, kept so people can see exactly what was done.
// Request and response bodies are never recorded (they carry certificates, keys and tokens): only
// what was asked, of where, and how the device answered.
type APICall struct {
	Time   time.Time `json:"time"`
	Op     string    `json:"op"`               // deploy | test
	Method string    `json:"method"`           // HTTP method
	Host   string    `json:"host"`             // host:port
	Path   string    `json:"path"`             // URL path, and query with secret values removed
	Detail string    `json:"detail,omitempty"` // what the call asked for, when the URL alone does not say (JSON-RPC)
	Status int       `json:"status"`           // HTTP status; 0 when no answer came back
	Millis int64     `json:"ms"`
	Error  string    `json:"error,omitempty"` // transport failure, such as a timeout or untrusted certificate
	// Answer is what the device said about the request, when that is more than the HTTP status:
	// FortiManager and FortiAnalyzer answer HTTP 200 and put the real result ("code -3 Object does
	// not exist") inside. Failed marks a call the device refused whatever its HTTP status.
	Answer string `json:"answer,omitempty"`
	Failed bool   `json:"failed,omitempty"`
}

type Event struct {
	Time    time.Time `json:"time"`
	Level   string    `json:"level"` // info | warn | error
	Subject string    `json:"subject"`
	Message string    `json:"message"`
}

// User is a person who can sign in. There are no roles: every user can do everything.
type User struct {
	Name    string    `json:"name"`
	Hash    string    `json:"hash"` // bcrypt
	Created time.Time `json:"created"`

	// the latest sign-in through the sign-in page (a script using HTTP basic authentication does not count)
	LastLogin     time.Time `json:"last_login,omitzero"`
	LastLoginFrom string    `json:"last_login_from,omitempty"` // as in the audit log: the address, and the proxy it came through

	// SessionsFrom is when the user last signed out: a session cookie issued before it is no longer
	// accepted, so signing out ends a stolen cookie as well as the browser's own.
	SessionsFrom time.Time `json:"sessions_from,omitzero"`
}

// PendingDNS is a TXT record CertSmith created for a DNS test and has not yet confirmed removed.
// It is kept so that a crash or restart in the middle of a test cannot silently leave a record
// in someone's zone: the UI shows it until it is gone.
type PendingDNS struct {
	ID       string    `json:"id"`
	Provider string    `json:"provider"`
	Fqdn     string    `json:"fqdn"`
	Value    string    `json:"value"`
	Since    time.Time `json:"since"`
	Note     string    `json:"note"`
}

type DB struct {
	PendingDNS   []PendingDNS         `json:"pending_dns"`
	Settings     Settings             `json:"settings"`
	AdminHash    string               `json:"admin_hash,omitempty"` // legacy single password, migrated to Users on load
	Users        []User               `json:"users"`
	DNSProviders []DNSProvider        `json:"dns_providers"`
	Certificates []Certificate        `json:"certificates"`
	Targets      []Target             `json:"targets"`
	Events       []Event              `json:"events"`
	Audit        []AuditEntry         `json:"audit"`
	Alerts       map[string]time.Time `json:"alerts"` // active alert key -> last sent
}

// DefaultKeepOnDevice is how many CertSmith certificates a device keeps by default: the one in use and
// the two before it, so a deployment can be rolled back by choosing the previous one on the device.
const DefaultKeepOnDevice = 3

// KeepOnDeviceOrDefault is the setting, or the default when it has never been set.
func KeepOnDeviceOrDefault(n int) int {
	if n < 1 {
		return DefaultKeepOnDevice
	}
	return n
}
