// Package plugin defines the extension points: DNS providers and deployment targets.
//
// Every plugin publishes a Descriptor. The web UI renders its forms from the
// descriptor and the server uses it to know which config keys are secrets, so
// adding a plugin needs no UI or storage changes.
package plugin

import (
	"context"
	"crypto/x509"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v5/challenge"
)

// Choice is one tick box in a "checks" field.
type Choice struct {
	Value string `json:"value"`
	Label string `json:"label"`
	Help  string `json:"help,omitempty"`
}

type Field struct {
	Key      string   `json:"key"`
	Label    string   `json:"label"`
	Type     string   `json:"type"` // text | password | textarea | bool | number | select | checks
	Help     string   `json:"help,omitempty"`
	Default  string   `json:"default,omitempty"`
	Required bool     `json:"required,omitempty"`
	Secret   bool     `json:"secret,omitempty"` // encrypted at rest, masked in the API
	Options  []string `json:"options,omitempty"`
	// Choices are the tick boxes of a "checks" field; the stored value is the
	// comma-separated list of ticked values.
	Choices []Choice `json:"choices,omitempty"`
	// Row groups fields that are drawn side by side on one line.
	Row string `json:"row,omitempty"`
	// ShowIf hides the field unless another field matches: "key=value", or
	// "key~value" when key is a checks field containing value.
	ShowIf string `json:"show_if,omitempty"`
	// Advanced fields are tucked into a collapsed section.
	Advanced bool `json:"advanced,omitempty"`
}

// CallDoc documents one API call a target plugin makes, for the "API calls" page in the web
// interface. Every call a plugin sends is also recorded as it happens; this is the explanation of
// what each is for and when it is sent, so people can judge the plugin before they run it.
type CallDoc struct {
	Op      string `json:"op"`             // test | deploy
	Method  string `json:"method"`         // HTTP method, or JSON-RPC method for FortiManager
	Path    string `json:"path"`           // URL path, <angle brackets> for values filled in
	Purpose string `json:"purpose"`        // what it is for
	When    string `json:"when,omitempty"` // the condition under which it is sent, if not always
	Changes bool   `json:"changes"`        // true when it modifies the device
}

type Descriptor struct {
	Kind   string `json:"kind"`
	Vendor string `json:"vendor,omitempty"` // groups targets in the UI's first drop-down
	// Hidden types are left out of the general "Add target" list. They are created from
	// somewhere more specific (for instance the Settings page) and still work as targets.
	Hidden bool    `json:"hidden,omitempty"`
	Label  string  `json:"label"`
	Help   string  `json:"help,omitempty"`
	Fields []Field `json:"fields"`
	// Calls lists the API calls the plugin makes, in the order it makes them.
	Calls []CallDoc `json:"calls,omitempty"`
	// AutoVerify, when set, makes the UI (and engine) check host:port without the
	// user typing it. AutoVerifyWhen optionally limits that to a ticked capability
	// ("key~value"), so a device is not probed for a certificate it does not use there.
	AutoVerify     bool   `json:"auto_verify,omitempty"`
	AutoVerifyWhen string `json:"auto_verify_when,omitempty"`
	AutoVerifyPort string `json:"auto_verify_port,omitempty"`
}

func (d Descriptor) SecretKeys() map[string]bool {
	m := map[string]bool{}
	for _, f := range d.Fields {
		if f.Secret {
			m[f.Key] = true
		}
	}
	return m
}

// Validate checks required fields and applies defaults, returning a new map.
func (d Descriptor) Validate(cfg map[string]string) (map[string]string, error) {
	out := map[string]string{}
	for k, v := range cfg {
		out[k] = v
	}
	for _, f := range d.Fields {
		if strings.TrimSpace(out[f.Key]) == "" {
			out[f.Key] = f.Default
		}
		if f.Required && strings.TrimSpace(out[f.Key]) == "" {
			return nil, fmt.Errorf("%s is required", f.Label)
		}
	}
	return out, nil
}

// KeepOld is how many older CertSmith certificates a device-cleaning plugin leaves on the device after
// a deployment. The engine passes the Settings value as "_keep_total" (the certificates to keep, the
// one just deployed included). Without it (an older caller) the target's own "keep_old", then 2.
func KeepOld(cfg map[string]string) int {
	if n, err := strconv.Atoi(strings.TrimSpace(cfg["_keep_total"])); err == nil && n >= 1 {
		return n - 1
	}
	if n, err := strconv.Atoi(strings.TrimSpace(cfg["keep_old"])); err == nil && n >= 0 {
		return n
	}
	return 2
}

// Bundle is an issued certificate ready for deployment.
type Bundle struct {
	Name      string
	Domains   []string
	Leaf      *x509.Certificate
	CertPEM   []byte // leaf only
	ChainPEM  []byte // intermediates only
	FullChain []byte // leaf + intermediates
	KeyPEM    []byte
	Serial    string
	NotBefore time.Time
	NotAfter  time.Time
}

// DNSProvider builds a lego DNS-01 solver from stored (already decrypted) config.
type DNSProvider interface {
	Descriptor() Descriptor
	Solver(cfg map[string]string) (challenge.Provider, error)
}

// Target deploys a Bundle to a device or service.
type Target interface {
	Descriptor() Descriptor
	// Deploy installs the bundle and returns a human-readable summary.
	Deploy(ctx context.Context, cfg map[string]string, b *Bundle) (string, error)
	// Test checks connectivity and credentials without changing anything.
	Test(ctx context.Context, cfg map[string]string) (string, error)
}

// Prober is implemented by targets that know which TLS endpoints show the
// certificate they manage, so those are checked without being configured twice.
type Prober interface {
	DefaultProbes(cfg map[string]string) []string
}

var (
	mu      sync.RWMutex
	dnsReg  = map[string]DNSProvider{}
	tgtReg  = map[string]Target{}
	opts    Options
	optsSet bool
)

// Options are process-wide switches plugins may consult.
type Options struct {
	AllowCommands bool   // permit targets that execute local commands
	UITLSDir      string // where the web interface's certificate lives; empty when it runs without TLS
	UIListen      string // the web interface's listen address
}

func SetOptions(o Options) { mu.Lock(); opts, optsSet = o, true; mu.Unlock() }
func GetOptions() Options  { mu.RLock(); defer mu.RUnlock(); return opts }

func RegisterDNS(p DNSProvider) {
	mu.Lock()
	defer mu.Unlock()
	dnsReg[p.Descriptor().Kind] = p
}

func RegisterTarget(t Target) {
	mu.Lock()
	defer mu.Unlock()
	tgtReg[t.Descriptor().Kind] = t
}

func DNS(kind string) (DNSProvider, bool) {
	mu.RLock()
	defer mu.RUnlock()
	p, ok := dnsReg[kind]
	return p, ok
}

func TargetFor(kind string) (Target, bool) {
	mu.RLock()
	defer mu.RUnlock()
	t, ok := tgtReg[kind]
	return t, ok
}

func DNSDescriptors() []Descriptor {
	mu.RLock()
	defer mu.RUnlock()
	var out []Descriptor
	for _, p := range dnsReg {
		out = append(out, p.Descriptor())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Label < out[j].Label })
	return out
}

func TargetDescriptors() []Descriptor {
	mu.RLock()
	defer mu.RUnlock()
	var out []Descriptor
	for _, t := range tgtReg {
		out = append(out, t.Descriptor())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Label < out[j].Label })
	return out
}

// Lines splits a multi-line config value into trimmed, non-empty, non-comment lines.
func Lines(s string) []string {
	var out []string
	for _, l := range strings.FieldsFunc(s, func(r rune) bool { return r == '\n' || r == ',' }) {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}
