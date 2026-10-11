package targets

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"github.com/CautiousCapsLock/certsmith/internal/plugin"
)

func init() { plugin.RegisterTarget(fortiGate{}) }

type fortiGate struct{}

// ---- capabilities ----------------------------------------------------------------
//
// A capability is one place a FortiGate can use a certificate. Each is declared
// on its own: which FortiOS objects and fields it touches, in its own small API
// calls. Adding a place, or fixing one that a new FortiOS version changed, means
// editing a single entry here; the UI tick boxes are generated from this table.

type fgBinding struct {
	path, mkey, field string
	list              bool // the field is a list of {name: ...} entries rather than a string
	// entry, for a list, is the certificate the administrator chose to replace: only that entry
	// changes and the rest of the list is kept (see wantFor).
	entry string
}

func (b fgBinding) String() string {
	if b.mkey != "" {
		return b.path + "/" + b.mkey + ":" + b.field
	}
	return b.path + ":" + b.field
}

type fgCapability struct {
	ID    string
	Label string
	Help  string
	// last capabilities are applied after the others: switching the admin GUI
	// certificate restarts the HTTPS service, which can interrupt later calls.
	last bool
	// bindings returns the API objects this capability updates.
	bindings func(cfg map[string]string) ([]fgBinding, error)
}

func one(b fgBinding) func(map[string]string) ([]fgBinding, error) {
	return func(map[string]string) ([]fgBinding, error) { return []fgBinding{b}, nil }
}

var fgCapabilities = []fgCapability{
	{ID: "admin-gui", Label: "Admin GUI (HTTPS management)", last: true,
		Help:     "The certificate shown when you browse to the FortiGate's web interface.",
		bindings: one(fgBinding{"system/global", "", "admin-server-cert", false, ""})},
	{ID: "ssl-vpn", Label: "SSL VPN portal",
		Help:     "Not available on models and releases where SSL VPN was removed.",
		bindings: one(fgBinding{"vpn.ssl/settings", "", "servercert", false, ""})},
	{ID: "auth-portal", Label: "Captive / authentication portal",
		bindings: one(fgBinding{"user/setting", "", "auth-cert", false, ""})},
	{ID: "ipsec", Label: "IPsec VPN (IKE phase 1)",
		Help: "Enter the phase 1 interface names below.",
		bindings: func(cfg map[string]string) ([]fgBinding, error) {
			names := plugin.Lines(cfg["ipsec_phase1"])
			if len(names) == 0 {
				return nil, fmt.Errorf("IPsec: enter at least one phase 1 name")
			}
			var out []fgBinding
			for _, n := range names {
				out = append(out, fgBinding{"vpn.ipsec/phase1-interface", n, "certificate", true, ""})
			}
			return out, nil
		}},
}

// customBindings parses the advanced "path;mkey;field[;list]" lines. Earlier
// versions also accepted the preset names here, so those still work.
func customBindings(text string) ([]fgBinding, error) {
	var out []fgBinding
	for _, line := range plugin.Lines(text) {
		switch {
		case line == "admin-gui", line == "ssl-vpn", line == "auth-portal":
			for _, c := range fgCapabilities {
				if c.ID == line {
					bs, _ := c.bindings(nil)
					out = append(out, bs...)
				}
			}
		case strings.HasPrefix(line, "ipsec:"):
			out = append(out, fgBinding{"vpn.ipsec/phase1-interface", strings.TrimPrefix(line, "ipsec:"), "certificate", true, ""})
		default:
			parts := strings.Split(line, ";")
			if len(parts) < 3 || len(parts) > 4 || parts[0] == "" || parts[2] == "" {
				return nil, fmt.Errorf("custom binding %q: want path;mkey;field[;list]", line)
			}
			out = append(out, fgBinding{path: parts[0], mkey: parts[1], field: parts[2], list: len(parts) == 4 && parts[3] == "list"})
		}
	}
	return out, nil
}

// plannedCap is a capability with the concrete API objects it will touch.
type plannedCap struct {
	id, label string
	last      bool
	bindings  []fgBinding
}

// plan turns the ticked boxes (and advanced custom bindings) into an ordered list.
func plan(cfg map[string]string) ([]plannedCap, error) {
	ticked := map[string]bool{}
	for _, v := range plugin.Lines(cfg["uses"]) {
		ticked[v] = true
	}
	var out []plannedCap
	for _, c := range fgCapabilities {
		if !ticked[c.ID] {
			continue
		}
		bs, err := c.bindings(cfg)
		if err != nil {
			return nil, err
		}
		out = append(out, plannedCap{c.ID, c.Label, c.last, bs})
	}
	zs, err := parseZTNA(cfg["ztna"])
	if err != nil {
		return nil, err
	}
	if len(zs) > 0 {
		var bs []fgBinding
		for _, z := range zs {
			bs = append(bs, z.binding())
		}
		out = append(out, plannedCap{"ztna", "ZTNA servers", false, bs})
	}
	if cb, err := customBindings(cfg["bindings"]); err != nil {
		return nil, err
	} else if len(cb) > 0 {
		out = append(out, plannedCap{"custom", "Custom bindings", false, cb})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("tick at least one place to use the certificate")
	}
	sort.SliceStable(out, func(i, j int) bool { return !out[i].last && out[j].last })
	return out, nil
}

func (fortiGate) Descriptor() plugin.Descriptor {
	var choices []plugin.Choice
	for _, c := range fgCapabilities {
		choices = append(choices, plugin.Choice{Value: c.ID, Label: c.Label, Help: c.Help})
	}
	fields := connFields("443", "Management address, e.g. fw1.lab.example")
	fields = append(fields,
		plugin.Field{Key: "token", Label: "REST API token", Type: "password", Required: true, Secret: true,
			Help: "Create a REST API admin whose profile can read and write certificates and the objects ticked below, and restrict it to this server's address under Trusted Hosts."},
		plugin.Field{Key: "uses", Label: "Use this certificate for", Type: "checks", Default: "admin-gui", Choices: choices},
		// the ZTNA servers chosen for replacement; filled by the "Look for ZTNA servers" panel
		plugin.Field{Key: "ztna", Type: "hidden"},
		// the release the device last reported (set by the ZTNA panel), so the SSL VPN tick can be switched off at once
		plugin.Field{Key: "fos_version", Type: "hidden"},
		plugin.Field{Key: "ipsec_phase1", Label: "IPsec phase 1 names", Type: "text", ShowIf: "uses~ipsec",
			Help: "Comma separated, as named under VPN > IPsec Tunnels."},
		verifyField,
		plugin.Field{Advanced: true, Key: "vdom", Label: "VDOM", Type: "text", Default: "root"},
		plugin.Field{Advanced: true, Key: "cert_prefix", Label: "Certificate name prefix", Type: "text", Default: "certsmith", Required: true,
			Help: "Certificates are imported as <prefix>-<name>-<yyyymmdd>-<serial4>, where <name> is CertSmith's name for the certificate, shortened to fit FortiOS's 35 characters (the shorter the prefix and the name, the more of it shows). Older ones sharing the prefix are pruned."},
		plugin.Field{Advanced: true, Key: "import_format", Label: "Import format", Type: "select", Options: []string{"pkcs12", "pem"}, Default: "pkcs12",
			Help: "pkcs12 carries the intermediate chain; pem uploads the full chain as the certificate file. Switch if your FortiOS version rejects one."},
		plugin.Field{Advanced: true, Key: "install_chain", Label: "Install the issuing CA certificates", Type: "bool", Default: "true",
			Help: "A FortiGate only sends the full certificate chain if the intermediate CA is in its own CA store. Leave this on unless you manage CA certificates yourself."},
		plugin.Field{Advanced: true, Key: "bindings", Label: "Custom bindings", Type: "textarea",
			Help: "One per line: path;mkey;field[;list], e.g. vpn.ssl/settings;;servercert. For places not covered by the tick boxes."},
	)
	return plugin.Descriptor{
		Kind:           "fortigate",
		Vendor:         "Fortinet",
		Label:          "FortiGate (FortiOS REST API)",
		Help:           "Imports the certificate, applies it to each selected function and each ZTNA server chosen (a separate API call each, rolled back if any call fails), and removes unreferenced older copies.",
		Fields:         append(fields, tlsFields...),
		Calls:          fgCallDocs(),
		AutoVerify:     true,
		AutoVerifyWhen: "uses~admin-gui",
		AutoVerifyPort: "443",
		Discover:       true,
	}
}

// fgCallDocs describes every REST call the plugin makes. All carry ?vdom=<vdom> and the API token
// as a bearer header. The per-capability rows come from the capability table, so a new tick box
// documents itself.
func fgCallDocs() []plugin.CallDoc {
	// same order as plan(): the places that restart a service (the admin GUI) come last
	caps := append([]fgCapability(nil), fgCapabilities...)
	sort.SliceStable(caps, func(i, j int) bool { return !caps[i].last && caps[j].last })
	docs := []plugin.CallDoc{
		{Op: "test", Method: "GET", Path: "/api/v2/monitor/system/status", Purpose: "Proves the address and token work, and reads the model, version and serial."},
	}
	for _, c := range caps {
		bs, _ := c.bindings(map[string]string{"ipsec_phase1": "<name>"})
		for _, b := range bs {
			docs = append(docs, plugin.CallDoc{Op: "test", Method: "GET", Path: "/api/v2/cmdb/" + fgPath(b),
				Purpose: "Checks the token can read where " + c.Label + " keeps its certificate (field " + b.field + ").", When: c.Label + " ticked"})
		}
	}
	docs = append(docs,
		plugin.CallDoc{Op: "test", Method: "GET", Path: "/api/v2/cmdb/firewall/vip", Purpose: "Lists the ZTNA virtual IPs (type access-proxy) and the certificate each uses, for the ZTNA section of this dialog.", When: "“Look for ZTNA servers” pressed"},
		plugin.CallDoc{Op: "test", Method: "GET", Path: "/api/v2/cmdb/firewall/access-proxy-virtual-host", Purpose: "Lists the ZTNA virtual hosts and the certificate each uses.", When: "“Look for ZTNA servers” pressed"},
		plugin.CallDoc{Op: "test", Method: "GET", Path: "/api/v2/cmdb/firewall/access-proxy", Purpose: "FortiOS 7.6 only: which ZTNA server each virtual IP and host belongs to, to label them.", When: "“Look for ZTNA servers” pressed, on 7.6"},
	)
	docs = append(docs,
		plugin.CallDoc{Op: "deploy", Method: "GET", Path: "/api/v2/cmdb/vpn.certificate/local/<name>", Purpose: "Asks whether this exact certificate was already imported, so a retry does not import it twice."},
		plugin.CallDoc{Op: "deploy", Method: "GET", Path: "/api/v2/cmdb/vpn.certificate/local?with_meta=1", Purpose: "Looks for this same certificate already on the device under another name (an earlier release named it differently), so that copy is used: FortiOS refuses to import a certificate that is already there.", When: "it is not there under the expected name"},
		plugin.CallDoc{Op: "deploy", Method: "POST", Path: "/api/v2/monitor/vpn-certificate/local/import", Changes: true,
			Purpose: "Imports the certificate and its private key (as a PKCS#12 bundle, or PEM if you chose that) under the name <prefix>-<name>-<date>-<serial>."},
		plugin.CallDoc{Op: "deploy", Method: "PUT", Path: "/api/v2/cmdb/vpn.certificate/local/<name>", Changes: true,
			Purpose: "Adds a note to the certificate saying what it is (CertSmith's name for it, its names and its expiry), so it can be told apart on the device.", When: "the certificate was just imported"},
		plugin.CallDoc{Op: "deploy", Method: "GET", Path: "/api/v2/cmdb/vpn.certificate/ca", Purpose: "Lists the CA certificates the FortiGate already has.", When: "“Install the issuing CA certificates” is on"},
		plugin.CallDoc{Op: "deploy", Method: "GET", Path: "/api/v2/cmdb/vpn.certificate/ca/<name>", Purpose: "Reads each CA that was added by a user, because the list above leaves out the certificates themselves; this is how an already installed CA is recognised.", When: "the device lists user-added CAs"},
		plugin.CallDoc{Op: "deploy", Method: "POST", Path: "/api/v2/monitor/vpn-certificate/ca/import", Changes: true,
			Purpose: "Installs the issuing CA (the intermediate, never the root) so the FortiGate sends the whole chain.", When: "the issuing CA is not there yet"},
	)
	docs = append(docs,
		plugin.CallDoc{Op: "deploy", Method: "GET", Path: "/api/v2/monitor/system/status", Purpose: "Reads the FortiOS version, so the SSL VPN setting is not sent to a release (7.6 and later) that has none.", When: "SSL VPN portal ticked"})
	for _, c := range caps {
		bs, _ := c.bindings(map[string]string{"ipsec_phase1": "<name>"})
		for _, b := range bs {
			docs = append(docs,
				plugin.CallDoc{Op: "deploy", Method: "GET", Path: "/api/v2/cmdb/" + fgPath(b), Purpose: "Reads the current " + b.field + " so it can be restored if a later step fails.", When: c.Label + " ticked"},
				plugin.CallDoc{Op: "deploy", Method: "PUT", Path: "/api/v2/cmdb/" + fgPath(b), Changes: true, Purpose: "Switches " + b.field + " to the new certificate.", When: c.Label + " ticked, and not already using it"})
		}
	}
	// ZTNA servers the administrator chose (see fortigate_ztna.go). Only the chosen entry of a list changes.
	for _, z := range []struct{ kind, path string }{{"VIP", "firewall/vip/<name>"}, {"virtual host", "firewall/access-proxy-virtual-host/<name>"}} {
		docs = append(docs,
			plugin.CallDoc{Op: "deploy", Method: "GET", Path: "/api/v2/cmdb/" + z.path, Purpose: "Reads the certificate list of a ZTNA " + z.kind + " you chose, so only your chosen entry is replaced and the list can be restored if a later step fails.", When: "a ZTNA server was chosen"},
			plugin.CallDoc{Op: "deploy", Method: "PUT", Path: "/api/v2/cmdb/" + z.path, Changes: true, Purpose: "Replaces the chosen certificate entry of the ZTNA " + z.kind + " with the new certificate, keeping any other entries.", When: "a ZTNA server was chosen, and not already using the new certificate"})
	}
	docs = append(docs,
		plugin.CallDoc{Op: "deploy", Method: "PUT", Path: "(the places above)", Changes: true, Purpose: "If any switch fails, the earlier ones are put back to the values read before.", When: "a switch failed"},
		plugin.CallDoc{Op: "deploy", Method: "GET", Path: "/api/v2/cmdb/vpn.certificate/local?with_meta=1", Purpose: "Lists CertSmith's older certificates with how many things still use each."},
		plugin.CallDoc{Op: "deploy", Method: "DELETE", Path: "/api/v2/cmdb/vpn.certificate/local/<old name>", Changes: true,
			Purpose: "Removes old CertSmith certificates beyond the number to keep (Settings, Certificates to keep on each device). Only ones nothing uses, and only names that start with your prefix.", When: "there are more old copies than \"Certificates to keep on each device\" (Settings) allows"},
	)
	return docs
}

func fgPath(b fgBinding) string {
	if b.mkey != "" {
		return b.path + "/" + b.mkey
	}
	return b.path
}

func (fortiGate) APIEndpoint(cfg map[string]string) string { return hostPort(cfg, "443") }

// DefaultProbes: the admin GUI certificate is served on the management address,
// so that is checked automatically. Other capabilities (an SSL VPN on a
// different interface or port) are not guessed: add them under "Verify".
func (fortiGate) DefaultProbes(cfg map[string]string) []string {
	for _, v := range plugin.Lines(cfg["uses"]) {
		if v == "admin-gui" {
			return []string{hostPort(cfg, "443")}
		}
	}
	return nil
}

// ---- REST client ------------------------------------------------------------------

type fgClient struct {
	base  string
	vdom  string
	token string
	hc    *http.Client
}

func newFGClient(cfg map[string]string) (*fgClient, error) {
	hp := hostPort(cfg, "443")
	hc, err := httpClient(hp, cfg, 45*time.Second)
	if err != nil {
		return nil, err
	}
	vdom := cfg["vdom"]
	if vdom == "" {
		vdom = "root"
	}
	return &fgClient{base: "https://" + hp, vdom: vdom, token: cfg["token"], hc: hc}, nil
}

// call performs one REST call and decodes the JSON body into out (if non-nil).
func (c *fgClient) call(ctx context.Context, method, path string, q url.Values, body, out any) error {
	if q == nil {
		q = url.Values{}
	}
	q.Set("vdom", c.vdom)
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path+"?"+q.Encode(), rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode/100 != 2 {
		var e struct {
			CLIError string `json:"cli_error"`
			Error    *int   `json:"error"`
		}
		_ = json.Unmarshal(raw, &e)
		whole := strings.TrimSpace(string(raw))
		if len(whole) > 300 {
			whole = whole[:300]
		}
		// the verbose log keeps what the device said word for word; the error shown on screen is the short form
		plugin.Annotate(ctx, whole, true)
		ae := &apiError{Status: resp.StatusCode, Msg: e.CLIError}
		if e.Error != nil {
			ae.Code, ae.HasCode = *e.Error, true
		}
		if ae.Msg == "" {
			if ae.HasCode {
				ae.Msg = fmt.Sprintf("FortiOS error %d", ae.Code)
			} else {
				ae.Msg = whole
			}
		}
		return ae
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

func (c *fgClient) callRetry(ctx context.Context, method, path string, q url.Values, body, out any) error {
	return retryNet(ctx, 5, 3*time.Second, func() error { return c.call(ctx, method, path, q, body, out) })
}

// ---- per-object API calls (the building blocks of every capability) ---------------

func (c *fgClient) objPath(b fgBinding) string {
	p := "/api/v2/cmdb/" + b.path
	if b.mkey != "" {
		p += "/" + url.PathEscape(b.mkey)
	}
	return p
}

// readBinding returns the raw JSON of the bound field.
func (c *fgClient) readBinding(ctx context.Context, b fgBinding) (json.RawMessage, error) {
	var resp struct {
		Results json.RawMessage `json:"results"`
	}
	if err := c.callRetry(ctx, http.MethodGet, c.objPath(b), nil, nil, &resp); err != nil {
		return nil, err
	}
	res := bytes.TrimSpace(resp.Results)
	if len(res) > 0 && res[0] == '[' { // table object: array of one
		var arr []map[string]json.RawMessage
		if err := json.Unmarshal(res, &arr); err != nil || len(arr) == 0 {
			return nil, fmt.Errorf("object not found")
		}
		return arr[0][b.field], nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(res, &obj); err != nil {
		return nil, err
	}
	return obj[b.field], nil
}

func (c *fgClient) writeBinding(ctx context.Context, b fgBinding, value json.RawMessage) error {
	body := map[string]json.RawMessage{b.field: value}
	return c.callRetry(ctx, http.MethodPut, c.objPath(b), nil, body, nil)
}

func (b fgBinding) valueFor(name string) json.RawMessage {
	if b.list {
		v, _ := json.Marshal([]map[string]string{{"name": name}})
		return v
	}
	v, _ := json.Marshal(name)
	return v
}

// sameCertificate finds a certificate CertSmith already put on the device that is the one named by
// want, whatever label it carries: names end in the date and the last digits of the serial. It
// returns its name, or "" when there is none (or the device could not be asked).
func (c *fgClient) sameCertificate(ctx context.Context, prefix, want string) string {
	key := fgNameOrder(want)
	if key == want { // not in the <date>-<serial> form: nothing to compare
		return ""
	}
	certs, err := c.listCerts(ctx, prefix)
	if err != nil {
		return ""
	}
	for _, ce := range certs {
		if ce.name != want && fgNameOrder(ce.name) == key {
			return ce.name
		}
	}
	return ""
}

func (c *fgClient) certExists(ctx context.Context, name string) (bool, error) {
	err := c.callRetry(ctx, http.MethodGet, "/api/v2/cmdb/vpn.certificate/local/"+url.PathEscape(name), nil, nil, nil)
	var ae *apiError
	if err != nil && asAPIError(err, &ae) && ae.Status == http.StatusNotFound {
		plugin.Annotate(ctx, "not imported yet, which is the normal answer the first time", false)
		return false, nil
	}
	return err == nil, err
}

func asAPIError(err error, target **apiError) bool {
	for err != nil {
		if ae, ok := err.(*apiError); ok {
			*target = ae
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

func (c *fgClient) importCert(ctx context.Context, name string, b *plugin.Bundle, format string) error {
	body := map[string]any{"certname": name, "scope": "global"}
	switch format {
	case "pem":
		body["type"] = "regular"
		body["file_content"] = base64.StdEncoding.EncodeToString(b.FullChain)
		body["key_file_content"] = base64.StdEncoding.EncodeToString(b.KeyPEM)
	default:
		key, err := parseKey(b.KeyPEM)
		if err != nil {
			return err
		}
		pw := make([]byte, 12)
		_, _ = rand.Read(pw)
		password := hex.EncodeToString(pw)
		p12, err := pkcs12.Modern.Encode(key, b.Leaf, chainCerts(b.ChainPEM), password)
		if err != nil {
			return fmt.Errorf("build pkcs12: %w", err)
		}
		body["type"] = "pkcs12"
		body["file_content"] = base64.StdEncoding.EncodeToString(p12)
		body["password"] = password
	}
	return c.callRetry(ctx, http.MethodPost, "/api/v2/monitor/vpn-certificate/local/import", nil, body, nil)
}

type fgCertRef struct {
	name string
	refs int // -1 when unknown
}

func (c *fgClient) listCerts(ctx context.Context, prefix string) ([]fgCertRef, error) {
	var resp struct {
		Results []map[string]any `json:"results"`
	}
	q := url.Values{"with_meta": {"1"}}
	if err := c.callRetry(ctx, http.MethodGet, "/api/v2/cmdb/vpn.certificate/local", q, nil, &resp); err != nil {
		return nil, err
	}
	var out []fgCertRef
	for _, r := range resp.Results {
		n, _ := r["name"].(string)
		if !strings.HasPrefix(n, prefix+"-") {
			continue
		}
		refs := -1
		if v, ok := r["q_ref"].(float64); ok {
			refs = int(v)
		}
		out = append(out, fgCertRef{n, refs})
	}
	return out, nil
}

// ---- Test: checks the connection and every ticked capability separately ----------------

func (fortiGate) Test(ctx context.Context, cfg map[string]string) (string, error) {
	c, err := newFGClient(cfg)
	if err != nil {
		return "", err
	}
	var st struct {
		Version string `json:"version"`
		Build   int    `json:"build"`
		Serial  string `json:"serial"`
		Results struct {
			Hostname string `json:"hostname"`
		} `json:"results"`
	}
	if err := c.call(ctx, http.MethodGet, "/api/v2/monitor/system/status", nil, nil, &st); err != nil {
		return "", err
	}
	caps, err := plan(cfg)
	if err != nil {
		return "", err
	}
	var parts, failed []string
	for _, pc := range caps {
		if pc.id == "ssl-vpn" && sslVPNRemoved(st.Version) {
			parts = append(parts, "ssl-vpn n/a on "+st.Version+" (ignored)")
			continue
		}
		ok := true
		for _, b := range pc.bindings {
			if _, err := c.readBinding(ctx, b); err != nil {
				ok = false
				failed = append(failed, fmt.Sprintf("%s (%s): %v", pc.label, b, err))
				break
			}
		}
		if ok {
			parts = append(parts, pc.id+" ok")
		} else {
			parts = append(parts, pc.id+" FAILED")
		}
	}
	head := fmt.Sprintf("%s %s build %d (%s): %s", st.Results.Hostname, st.Version, st.Build, st.Serial, strings.Join(parts, ", "))
	if len(failed) > 0 {
		return "", fmt.Errorf("%s - %s", head, strings.Join(failed, "; "))
	}
	return head, nil
}

// ---- Deploy ------------------------------------------------------------------------------

func (f fortiGate) Deploy(ctx context.Context, cfg map[string]string, b *plugin.Bundle) (string, error) {
	// once the admin GUI switches to the new certificate the API presents it, so trust it for the rest of this run
	cfg = withDeployedPin(cfg, b)
	c, err := newFGClient(cfg)
	if err != nil {
		return "", err
	}
	caps, err := plan(cfg)
	if err != nil {
		return "", err
	}
	prefix := strings.TrimSpace(cfg["cert_prefix"])
	if prefix == "" {
		prefix = "certsmith"
	}
	name := fgCertName(prefix, b.Name, b, 35)

	exists, err := c.certExists(ctx, name)
	if err != nil {
		return "", fmt.Errorf("check existing certificate: %w", err)
	}
	if !exists {
		// The same certificate may be on the device under another name: an earlier release named it
		// without the label, or the label has changed. FortiOS refuses to import a certificate that is
		// already there (error -328), so the copy that is there is used.
		if other := c.sameCertificate(ctx, prefix, name); other != "" {
			name, exists = other, true
		}
	}
	if !exists {
		if err := c.importCert(ctx, name, b, cfg["import_format"]); err != nil {
			if isDuplicateCA(err) { // refused as a duplicate: it is there under a name that could not be told apart
				if other := c.sameCertificate(ctx, prefix, name); other != "" {
					name, exists = other, true
				}
			}
			if !exists {
				return "", fmt.Errorf("import certificate %s: %w", name, err)
			}
		}
	}
	if !exists {
		// a note on the device saying what this certificate is (best effort: the name alone is cut to fit)
		note := fmt.Sprintf("CertSmith: %s (%s), expires %s", b.Name, strings.Join(b.Domains, ", "), b.NotAfter.UTC().Format("2006-01-02"))
		if len(note) > 120 {
			note = note[:120]
		}
		_ = c.call(ctx, http.MethodPut, "/api/v2/cmdb/vpn.certificate/local/"+url.PathEscape(name), nil, map[string]string{"comments": note}, nil)
	}

	chainNote := ""
	if cfg["install_chain"] != "false" {
		chainNote = "; " + c.ensureChain(ctx, b)
	}

	// Switch each capability in turn, remembering previous values so that a
	// failure part-way rolls everything back to how it was.
	type prev struct {
		b   fgBinding
		old json.RawMessage
	}
	var done []prev
	rollback := func() {
		for i := len(done) - 1; i >= 0; i-- {
			if len(done[i].old) > 0 {
				_ = c.writeBinding(ctx, done[i].b, done[i].old)
			}
		}
	}
	var report []string
	// SSL VPN is gone from FortiOS 7.6: its setting does not exist there, so a stored tick is skipped
	version := ""
	for _, pc := range caps {
		if pc.id == "ssl-vpn" {
			var st struct {
				Version string `json:"version"`
			}
			if err := c.call(ctx, http.MethodGet, "/api/v2/monitor/system/status", nil, nil, &st); err == nil {
				version = st.Version
			}
			break
		}
	}
	for _, pc := range caps {
		if pc.id == "ssl-vpn" && sslVPNRemoved(version) {
			report = append(report, "ssl-vpn skipped (not in FortiOS 7.6 and later)")
			continue
		}
		changed := false
		for _, bd := range pc.bindings {
			old, err := c.readBinding(ctx, bd)
			if err != nil {
				rollback()
				return "", fmt.Errorf("%s: read %s: %w", pc.label, bd, err)
			}
			want, err := bd.wantFor(old, name, prefix)
			if err != nil {
				rollback()
				return "", fmt.Errorf("%s: %w (all changes rolled back)", pc.label, err)
			}
			if jsonEqual(old, want) {
				continue
			}
			done = append(done, prev{bd, old})
			if err := c.writeBinding(ctx, bd, want); err != nil {
				rollback()
				return "", fmt.Errorf("%s: set %s: %w (all changes rolled back)", pc.label, bd, err)
			}
			changed = true
		}
		if changed {
			report = append(report, pc.id+" updated")
		} else {
			report = append(report, pc.id+" already current")
		}
	}

	// prune old copies that nothing references
	deleted := 0
	keep := plugin.KeepOld(cfg)
	if certs, err := c.listCerts(ctx, prefix); err == nil {
		var old []fgCertRef
		for _, ce := range certs {
			if ce.name != name {
				old = append(old, ce)
			}
		}
		sort.Slice(old, func(i, j int) bool { // newest first, by the date and serial the name ends with
			ki, kj := fgNameOrder(old[i].name), fgNameOrder(old[j].name)
			if ki != kj {
				return ki > kj
			}
			return old[i].name > old[j].name
		})
		for i, ce := range old {
			if i < keep || ce.refs != 0 {
				continue
			}
			if c.callRetry(ctx, http.MethodDelete, "/api/v2/cmdb/vpn.certificate/local/"+url.PathEscape(ce.name), nil, nil, nil) == nil {
				deleted++
			}
		}
	}
	verb := "imported as"
	if exists {
		verb = "already on the device as"
	}
	return fmt.Sprintf("%s %s; %s; pruned %d old cert(s)%s", verb, name, strings.Join(report, ", "), deleted, chainNote), nil
}

// ensureChain installs the certificate's issuing CAs (intermediates) in the FortiGate's CA
// store. A FortiGate builds the chain it sends from its own CA store, so without the
// intermediate it sends the bare certificate and browsers that cannot fetch the missing
// piece show it as untrusted. Roots are left alone: clients already have them. It never
// fails the deployment: the certificate works either way, just less widely.
func (c *fgClient) ensureChain(ctx context.Context, b *plugin.Bundle) string {
	var want []*x509.Certificate
	for _, ca := range chainCerts(b.ChainPEM) {
		if !bytes.Equal(ca.RawIssuer, ca.RawSubject) { // skip self-signed roots
			want = append(want, ca)
		}
	}
	if len(want) == 0 {
		return "no issuing CA to install"
	}

	have := c.installedCAs(ctx)

	installed, present := 0, 0
	var problems []string
	for _, ca := range want {
		if have[sha256.Sum256(ca.Raw)] {
			present++
			continue
		}
		body := map[string]any{
			"import_method": "file", "scope": "global",
			"file_content": base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})),
		}
		if err := c.callRetry(ctx, http.MethodPost, "/api/v2/monitor/vpn-certificate/ca/import", nil, body, nil); err != nil {
			if isDuplicateCA(err) { // already there (e.g. imported by hand or under a name we did not look at)
				plugin.Annotate(ctx, "already installed (the device reports a duplicate)", false)
				present++
				continue
			}
			name := ca.Subject.CommonName
			if name == "" {
				name = "an issuing CA"
			}
			problems = append(problems, fmt.Sprintf("%s: %v", name, err))
			continue
		}
		installed++
	}
	switch {
	case len(problems) > 0:
		return fmt.Sprintf("could not install the issuing CA (%s): browsers may show the certificate as untrusted until it is installed by hand", strings.Join(problems, "; "))
	case installed > 0:
		return fmt.Sprintf("installed %d issuing CA certificate(s) so the full chain is sent", installed)
	default:
		return "issuing CA already installed"
	}
}

// fgErrDuplicate is the error FortiOS returns when a certificate being imported is already in the store.
const fgErrDuplicate = -328

func isDuplicateCA(err error) bool {
	var ae *apiError
	return asAPIError(err, &ae) && ae.HasCode && ae.Code == fgErrDuplicate
}

// installedCAs returns the fingerprints of the CA certificates already in the device's CA store that
// CertSmith could have put there. The list call names every CA (a FortiGate has over a hundred built
// in) but, on current FortiOS, leaves each certificate's body empty, so the ones added by a user are
// read one by one; the built-in ones are never CertSmith's and are skipped.
func (c *fgClient) installedCAs(ctx context.Context) map[[32]byte]bool {
	have := map[[32]byte]bool{}
	add := func(text string) {
		for _, pc := range chainCerts([]byte(text)) {
			have[sha256.Sum256(pc.Raw)] = true
		}
	}
	var list struct {
		Results []struct {
			Name   string `json:"name"`
			Source string `json:"source"`
			CA     string `json:"ca"`
		} `json:"results"`
	}
	if err := c.callRetry(ctx, http.MethodGet, "/api/v2/cmdb/vpn.certificate/ca", nil, nil, &list); err != nil {
		return have
	}
	for _, r := range list.Results {
		switch {
		case strings.TrimSpace(r.CA) != "":
			add(r.CA)
		case r.Source == "user" && r.Name != "":
			var one struct {
				Results []struct {
					CA string `json:"ca"`
				} `json:"results"`
			}
			if err := c.callRetry(ctx, http.MethodGet, "/api/v2/cmdb/vpn.certificate/ca/"+url.PathEscape(r.Name), nil, nil, &one); err == nil && len(one.Results) > 0 {
				add(one.Results[0].CA)
			}
		}
	}
	return have
}

func jsonEqual(a, b json.RawMessage) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	// list bindings: compare only the names, FortiOS adds extra keys (q_origin_key)
	return fmt.Sprint(normNames(x)) == fmt.Sprint(normNames(y))
}

func normNames(v any) any {
	arr, ok := v.([]any)
	if !ok {
		return v
	}
	var out []any
	for _, e := range arr {
		if m, ok := e.(map[string]any); ok {
			out = append(out, m["name"])
		} else {
			out = append(out, e)
		}
	}
	return out
}
