package targets

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/CautiousCapsLock/certsmith/internal/plugin"
)

// FortiManager and FortiAnalyzer share a JSON-RPC API (/jsonrpc) and the same
// FortiOS-derived CLI tree, so one implementation serves both. Verified on 7.4
// hardware and against the 7.6.7 API reference. The object paths and field names
// are configurable so a release that differs can be handled without a rebuild.
func init() {
	plugin.RegisterTarget(fortiMgr{kind: "fortimanager", label: "FortiManager (JSON-RPC)"})
	plugin.RegisterTarget(fortiMgr{kind: "fortianalyzer", label: "FortiAnalyzer (JSON-RPC)"})
}

type fortiMgr struct{ kind, label string }

func (f fortiMgr) Descriptor() plugin.Descriptor {
	fields := connFields("443", "Management address")
	fields = append(fields, []plugin.Field{
		{Key: "token", Label: "API token", Type: "password", Required: true, Secret: true,
			Help: "Create an API user (System Settings > Administrators) with Read-Write on System Settings and an RPC-permitted profile; token auth needs 7.2.2 or later."},
		verifyField,
		{Advanced: true, Key: "cert_prefix", Label: "Certificate name prefix", Type: "text", Default: "certsmith", Required: true},
		{Advanced: true, Key: "cert_path", Label: "Certificate object path", Type: "text", Default: fmgCertPath,
			Help: "JSON-RPC URL of the local-certificate table (config system certificate local). Adjust if your version differs."},
		{Advanced: true, Key: "cert_field", Label: "Certificate field", Type: "text", Default: "certificate"},
		{Advanced: true, Key: "key_field", Label: "Private key field", Type: "text", Default: "private-key"},
		{Advanced: true, Key: "extra_json", Label: "Extra certificate fields (JSON, optional)", Type: "textarea",
			Help: `Merged into the object, e.g. {"password":""} if your version requires it.`},
		{Advanced: true, Key: "bind_path", Label: "Binding object path", Type: "text", Default: fmgBindPath,
			Help: "Where the web admin certificate is chosen (config system admin setting)."},
		{Advanced: true, Key: "bind_field", Label: "Binding field", Type: "text", Default: fmgBindField,
			Help: "The setting that names the certificate. Some releases spell it with a hyphen; CertSmith tries that spelling too."},
		{Advanced: true, Key: "install_chain", Label: "Install the issuing CA certificates", Type: "bool", Default: "true",
			Help: "The device only sends the full chain if the intermediate CA is in its own CA store. Leave this on unless you manage CA certificates yourself."},
		{Advanced: true, Key: "keep_old", Label: "Old certificates to keep", Type: "number", Default: "2"},
	}...)
	product := "FortiManager"
	if f.kind == "fortianalyzer" {
		product = "FortiAnalyzer"
	}
	return plugin.Descriptor{
		Kind:   f.kind,
		Vendor: "Fortinet",
		Label:  f.label,
		Help:   "Uploads the certificate to " + product + ", installs its issuing CA so the full chain is sent, and sets it as the web administration server certificate.",
		Fields: append(fields, tlsFields...),
		Calls: []plugin.CallDoc{
			// paths are the defaults (the 7.6.7 API reference); each can be changed under Advanced
			{Op: "test", Method: "get", Path: "/sys/status", Purpose: "Proves the address and token work, and reads the hostname, version and platform."},
			{Op: "test", Method: "get", Path: fmgCertPath, Purpose: "Checks the token can read the local certificate table."},
			{Op: "test", Method: "get", Path: fmgBindPath, Purpose: "Checks the token can read the admin settings and that the certificate setting (" + fmgBindField + ") exists on this version, and shows the certificate in use now."},

			{Op: "deploy", Method: "get", Path: fmgBindPath, Purpose: "Reads the current admin server certificate before anything is uploaded. It proves the setting exists on this version (a wrong path stops here with nothing left behind) and is the value restored if the switch fails."},
			{Op: "deploy", Method: "get", Path: fmgCertPath + "/<name>", Purpose: "Asks whether this exact certificate was already uploaded (a retry after an interruption). \u201cObject does not exist\u201d is the normal answer the first time."},
			{Op: "deploy", Method: "add", Path: fmgCertPath, Changes: true, Purpose: "Uploads the certificate chain and private key as a new local certificate named <prefix>-<date>-<serial>.", When: "it is not there yet"},
			{Op: "deploy", Method: "update", Path: fmgCertPath + "/<name>", Changes: true, Purpose: "Overwrites a certificate of the same name left by an interrupted deployment.", When: "it is already there"},
			{Op: "deploy", Method: "get", Path: "/cli/global/system/certificate/ca", Purpose: "Lists the CA certificates the device already has.", When: "\u201cInstall the issuing CA certificates\u201d is on"},
			{Op: "deploy", Method: "add", Path: "/cli/global/system/certificate/ca", Changes: true, Purpose: "Installs an issuing CA (an intermediate, never a root) so the device sends the whole chain. Sent once per missing CA: Let's Encrypt's chain normally has two.", When: "the CA is not there yet"},
			{Op: "deploy", Method: "set", Path: fmgBindPath, Changes: true, Purpose: "Makes the new certificate the one the web admin interface presents. The web service restarts as this takes effect, so the connection is often cut; CertSmith repeats the request until the device answers."},
			{Op: "deploy", Method: "set", Path: fmgBindPath, Changes: true, Purpose: "Puts the previous certificate back.", When: "the switch failed"},
			{Op: "deploy", Method: "get", Path: fmgCertPath, Purpose: "Lists CertSmith's older certificates (names starting with your prefix)."},
			{Op: "deploy", Method: "delete", Path: fmgCertPath + "/<old name>", Changes: true, Purpose: "Removes older CertSmith certificates beyond the number to keep.", When: "there are more than \u201cOld certificates to keep\u201d"},
		},
		// the certificate is the one served by the management GUI
		AutoVerify: true, AutoVerifyPort: "443",
	}
}

func (f fortiMgr) APIEndpoint(cfg map[string]string) string { return hostPort(cfg, "443") }

func (f fortiMgr) DefaultProbes(cfg map[string]string) []string {
	return []string{hostPort(cfg, "443")}
}

type rpcClient struct {
	url   string
	token string
	hc    *http.Client
	id    int
}

func newRPC(cfg map[string]string) (*rpcClient, error) {
	host := hostPort(cfg, "443")
	hc, err := httpClient(host, cfg, 60*time.Second)
	if err != nil {
		return nil, err
	}
	return &rpcClient{url: "https://" + host + "/jsonrpc", token: cfg["token"], hc: hc}, nil
}

// call sends one JSON-RPC request and returns result[0].data.
func (c *rpcClient) call(ctx context.Context, method, path string, data any) (json.RawMessage, error) {
	c.id++
	param := map[string]any{"url": path}
	if data != nil {
		param["data"] = data
	}
	body, _ := json.Marshal(map[string]any{"id": c.id, "method": method, "params": []any{param}})
	var out json.RawMessage
	err := retryNet(ctx, 4, 3*time.Second, func() error {
		req, err := http.NewRequestWithContext(plugin.WithDetail(ctx, method+" "+path), http.MethodPost, c.url, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+c.token)
		resp, err := c.hc.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		if resp.StatusCode/100 != 2 {
			plugin.Annotate(ctx, strings.TrimSpace(string(raw)), true)
			return &apiError{Status: resp.StatusCode, Msg: strings.TrimSpace(string(raw))}
		}
		var r struct {
			Result []struct {
				Status struct {
					Code    int    `json:"code"`
					Message string `json:"message"`
				} `json:"status"`
				URL  string          `json:"url"`
				Data json.RawMessage `json:"data"`
			} `json:"result"`
		}
		if err := json.Unmarshal(raw, &r); err != nil {
			return &apiError{Status: resp.StatusCode, Msg: "unparseable response: " + err.Error()}
		}
		if len(r.Result) == 0 {
			return &apiError{Status: resp.StatusCode, Msg: "empty result"}
		}
		plugin.Annotate(ctx, fmt.Sprintf("code %d %s", r.Result[0].Status.Code, r.Result[0].Status.Message), r.Result[0].Status.Code != 0)
		if s := r.Result[0].Status; s.Code != 0 {
			return &apiError{Status: resp.StatusCode, Msg: fmt.Sprintf("%s %s: code %d %s", method, path, s.Code, s.Message), Code: s.Code, HasCode: true}
		}
		out = r.Result[0].Data
		return nil
	})
	return out, err
}

// JSON-RPC status codes that matter here.
const (
	rpcNotFound = -3 // the object does not exist
	rpcExists   = -2 // the object already exists
)

func isRPC(err error, code int) bool {
	var ae *apiError
	return asAPIError(err, &ae) && ae.HasCode && ae.Code == code
}

// uploadCert creates the certificate, or replaces it if one of that name is already there.
// "set" only works on an object that exists, so a new certificate is created with "add" on the
// table; an existing one (a retry of an interrupted deployment) is overwritten with "update".
func (c *rpcClient) uploadCert(ctx context.Context, certPath, name string, obj map[string]any) error {
	one := strings.TrimRight(certPath, "/") + "/" + name
	exists := true
	if _, err := c.call(ctx, "get", one, nil); err != nil {
		if !isRPC(err, rpcNotFound) {
			return err
		}
		plugin.Annotate(ctx, "not there yet, which is the normal answer the first time", false)
		exists = false
	}
	if exists {
		_, err := c.call(ctx, "update", one, obj)
		return err
	}
	_, err := c.call(ctx, "add", certPath, obj)
	if isRPC(err, rpcExists) { // appeared in between: overwrite it
		_, err = c.call(ctx, "update", one, obj)
	}
	return err
}

func (f fortiMgr) Test(ctx context.Context, cfg map[string]string) (string, error) {
	c, err := newRPC(cfg)
	if err != nil {
		return "", err
	}
	d, err := c.call(ctx, "get", "/sys/status", nil)
	if err != nil {
		return "", err
	}
	var st map[string]any
	_ = json.Unmarshal(d, &st)
	if _, err := c.call(ctx, "get", certPathOf(cfg), nil); err != nil {
		return "", fmt.Errorf("status ok but cannot read certificate table: %w", err)
	}
	bindPath, bindField := bindOf(cfg)
	cur, field, err := c.readBinding(ctx, bindPath, bindField)
	if err != nil {
		return "", fmt.Errorf("status ok but cannot read the admin settings (%s): %w", bindPath, err)
	}
	return fmt.Sprintf("%v %v (%v); web admin certificate in use: %v (%s)", st["Hostname"], st["Version"], st["Platform Type"], cur, field), nil
}

// fmgCertPath is where FortiManager and FortiAnalyzer keep local certificates ("config system
// certificate local" in the CLI). Versions before 0.8.2 defaulted to a path without "system",
// which these products answer with "Object does not exist", so that stored value is read as this.
const (
	fmgCertPath       = "/cli/global/system/certificate/local"
	fmgLegacyCertPath = "/cli/global/certificate/local"
)

func certPathOf(cfg map[string]string) string {
	p := orDefault(cfg["cert_path"], fmgCertPath)
	if strings.TrimRight(p, "/") == fmgLegacyCertPath {
		return fmgCertPath
	}
	return p
}

// Where the web admin certificate is chosen, per the 7.6.7 API reference for both products:
// "config system admin setting" / admin_server_cert (note the underscore). Versions before 0.8.2
// defaulted to system/global with a hyphenated name, which does not exist; that stored pair is
// read as this one.
const (
	fmgBindPath        = "/cli/global/system/admin/setting"
	fmgBindField       = "admin_server_cert"
	fmgLegacyBindPath  = "/cli/global/system/global"
	fmgLegacyBindField = "admin-server-cert"
)

func bindOf(cfg map[string]string) (path, field string) {
	path, field = orDefault(cfg["bind_path"], fmgBindPath), orDefault(cfg["bind_field"], fmgBindField)
	if strings.TrimRight(path, "/") == fmgLegacyBindPath && field == fmgLegacyBindField {
		return fmgBindPath, fmgBindField
	}
	return path, field
}

// readBinding reads the settings object and returns the current value of the certificate setting.
// Releases differ in how they spell it (admin_server_cert, admin-server-cert), so if the configured
// name is absent but the other spelling is there, that one is used; the name that was found is returned.
func (c *rpcClient) readBinding(ctx context.Context, path, field string) (any, string, error) {
	d, err := c.call(ctx, "get", path, nil)
	if err != nil {
		return nil, field, err
	}
	var m map[string]any
	if err := json.Unmarshal(d, &m); err != nil {
		return nil, field, fmt.Errorf("unexpected answer for %s: %w", path, err)
	}
	if v, ok := m[field]; ok {
		return v, field, nil
	}
	alt := strings.NewReplacer("_", "-").Replace(field)
	if alt == field {
		alt = strings.NewReplacer("-", "_").Replace(field)
	}
	if v, ok := m[alt]; ok {
		return v, alt, nil
	}
	return nil, field, nil // not shown (a default value may be left out): let the device judge the write
}

// caPathOf is the CA table that sits next to the local certificate table
// (.../system/certificate/local -> .../system/certificate/ca).
func caPathOf(certPath string) string {
	p := strings.TrimRight(certPath, "/")
	if strings.HasSuffix(p, "/local") {
		return strings.TrimSuffix(p, "/local") + "/ca"
	}
	return "/cli/global/system/certificate/ca"
}

// caName is the table entry name for a CA: readable, safe characters only, and short.
func caName(c *x509.Certificate) string {
	cn := c.Subject.CommonName
	if cn == "" {
		cn = "ca"
	}
	var b strings.Builder
	for _, r := range cn {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	name := "certsmith-ca-" + b.String()
	if len(name) > 35 {
		name = name[:35]
	}
	return name
}

// ensureChain installs the certificate's issuing CAs (intermediates) in the device's CA store, as the
// FortiGate plugin does: the device builds the chain it sends from that store, so without the
// intermediate it sends the bare certificate. Roots are left alone. It never fails the deployment.
func (c *rpcClient) ensureChain(ctx context.Context, certPath string, b *plugin.Bundle) string {
	var want []*x509.Certificate
	for _, ca := range chainCerts(b.ChainPEM) {
		if !bytes.Equal(ca.RawIssuer, ca.RawSubject) { // skip self-signed roots
			want = append(want, ca)
		}
	}
	if len(want) == 0 {
		return "no issuing CA to install"
	}
	caPath := caPathOf(certPath)
	have := map[[32]byte]bool{}
	names := map[string]bool{}
	if d, err := c.call(ctx, "get", caPath, nil); err == nil {
		var rows []map[string]any
		if json.Unmarshal(d, &rows) == nil {
			for _, r := range rows {
				if n, _ := r["name"].(string); n != "" {
					names[n] = true
				}
				// the certificate is a string, or a list of lines, depending on the release
				var text string
				switch v := r["ca"].(type) {
				case string:
					text = v
				case []any:
					for _, l := range v {
						text += fmt.Sprint(l) + "\n"
					}
				}
				// the device stores multi-line values quoted: "-----BEGIN CERTIFICATE-----\n...", which a
				// PEM reader does not accept until the quote marks are gone
				for _, pc := range chainCerts([]byte(strings.ReplaceAll(text, `"`, ""))) {
					have[sha256.Sum256(pc.Raw)] = true
				}
			}
		}
	}
	installed, present := 0, 0
	var problems []string
	for _, ca := range want {
		if have[sha256.Sum256(ca.Raw)] {
			present++
			continue
		}
		name := caName(ca)
		for i := 2; names[name]; i++ { // same name, different certificate: keep both
			name = fmt.Sprintf("%.31s-%d", caName(ca), i)
		}
		names[name] = true
		obj := map[string]any{"name": name, "ca": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}))}
		if _, err := c.call(ctx, "add", caPath, obj); err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", ca.Subject.CommonName, err))
			continue
		}
		installed++
	}
	switch {
	case len(problems) > 0:
		return fmt.Sprintf("could not install the issuing CA (%s): clients may see the chain as incomplete until it is installed by hand", strings.Join(problems, "; "))
	case installed > 0:
		return fmt.Sprintf("installed %d issuing CA certificate(s) so the full chain is sent", installed)
	default:
		return "issuing CA already installed"
	}
}

func orDefault(s, d string) string {
	if strings.TrimSpace(s) == "" {
		return d
	}
	return s
}

func (f fortiMgr) Deploy(ctx context.Context, cfg map[string]string, b *plugin.Bundle) (string, error) {
	cfg = withDeployedPin(cfg, b)
	c, err := newRPC(cfg)
	if err != nil {
		return "", err
	}
	prefix := orDefault(cfg["cert_prefix"], "certsmith")
	name := certName(prefix, b, 35)
	certPath := certPathOf(cfg)
	bindPath, bindField := bindOf(cfg)

	obj := map[string]any{
		"name": name,
		orDefault(cfg["cert_field"], "certificate"): string(b.FullChain),
		orDefault(cfg["key_field"], "private-key"):  string(b.KeyPEM),
	}
	if extra := strings.TrimSpace(cfg["extra_json"]); extra != "" {
		var m map[string]any
		if err := json.Unmarshal([]byte(extra), &m); err != nil {
			return "", fmt.Errorf("extra_json: %w", err)
		}
		for k, v := range m {
			obj[k] = v
		}
	}
	// Read the setting first, before anything is uploaded: it proves the setting is reachable on this
	// version (a wrong path stops here, leaving nothing behind) and is the value to restore on failure.
	oldVal, bindField, err := c.readBinding(ctx, bindPath, bindField)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", bindPath, err)
	}
	if err := c.uploadCert(ctx, certPath, name, obj); err != nil {
		return "", fmt.Errorf("upload certificate: %w", err)
	}

	// Install the issuing CA before the switch: changing the admin certificate restarts the web
	// service, and it should come back already knowing the intermediate it has to send.
	chainNote := ""
	if cfg["install_chain"] != "false" {
		chainNote = "; " + c.ensureChain(ctx, certPath, b)
	}
	if _, err := c.call(ctx, "set", bindPath, map[string]any{bindField: name}); err != nil {
		if oldVal != nil {
			_, _ = c.call(ctx, "set", bindPath, map[string]any{bindField: oldVal})
		}
		return "", fmt.Errorf("set %s: %w", bindField, err)
	}

	deleted := 0
	keep := 2
	if n, err := strconv.Atoi(cfg["keep_old"]); err == nil && n >= 0 {
		keep = n
	}
	if d, err := c.call(ctx, "get", certPath, nil); err == nil {
		var rows []map[string]any
		if json.Unmarshal(d, &rows) == nil {
			var names []string
			for _, r := range rows {
				if n, _ := r["name"].(string); strings.HasPrefix(n, prefix+"-") && n != name {
					names = append(names, n)
				}
			}
			sort.Sort(sort.Reverse(sort.StringSlice(names)))
			for i, n := range names {
				if i < keep {
					continue
				}
				if _, err := c.call(ctx, "delete", certPath+"/"+n, nil); err == nil {
					deleted++
				}
			}
		}
	}
	return fmt.Sprintf("uploaded as %s and set %s; pruned %d old%s", name, bindField, deleted, chainNote), nil
}

var _ = errors.New
