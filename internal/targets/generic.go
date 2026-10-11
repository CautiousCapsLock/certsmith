package targets

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/CautiousCapsLock/certsmith/internal/plugin"
)

func init() {
	plugin.RegisterTarget(webhookTarget{})
	plugin.RegisterTarget(filesTarget{})
	plugin.RegisterTarget(watchTarget{})
}

// ---- webhook ---------------------------------------------------------------

type webhookTarget struct{}

func (webhookTarget) Descriptor() plugin.Descriptor {
	fields := []plugin.Field{
		{Key: "url", Label: "URL", Type: "text", Required: true},
		{Key: "auth_header", Label: "Authorization header value (optional)", Type: "password", Secret: true,
			Help: "Sent as the Authorization header, e.g. 'Bearer abc123'."},
		{Key: "include_key", Label: "Include private key in payload", Type: "bool", Default: "false"},
		verifyField,
	}
	return plugin.Descriptor{
		Kind:   "webhook",
		Vendor: "Generic",
		Label:  "Webhook (HTTP POST)",
		Help:   "Sends an HTTP POST containing {name, domains, serial, not_after, fullchain_pem[, key_pem]} as JSON, for systems without a dedicated target.",
		Fields: append(fields, tlsFields...),
		Calls: []plugin.CallDoc{
			{Op: "test", Method: "-", Path: "(none)", Purpose: "Nothing is sent: a test request would reach your endpoint and might act on it."},
			{Op: "deploy", Method: "POST", Path: "<your URL>", Changes: true,
				Purpose: "Sends the JSON payload described above. The URL is not shown in the call log because it may contain a secret."},
		},
	}
}

func (webhookTarget) APIEndpoint(cfg map[string]string) string {
	u, err := url.Parse(strings.TrimSpace(cfg["url"]))
	if err != nil || u.Hostname() == "" || u.Scheme != "https" {
		return ""
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return net.JoinHostPort(u.Hostname(), port)
}

func (webhookTarget) Test(ctx context.Context, cfg map[string]string) (string, error) {
	return "webhook configured (no test request sent: it would reach your endpoint)", nil
}

func (webhookTarget) Deploy(ctx context.Context, cfg map[string]string, b *plugin.Bundle) (string, error) {
	u := strings.TrimSpace(cfg["url"])
	pu, err := url.Parse(u)
	if err != nil || pu.Host == "" || (pu.Scheme != "https" && pu.Scheme != "http") {
		return "", fmt.Errorf("the URL must start with https:// (or http://) and name a host")
	}
	if pu.Scheme != "https" && isTrue(cfg["include_key"]) {
		return "", fmt.Errorf("refusing to send the private key over plain HTTP: use an https:// URL, or untick \"Include private key in payload\"")
	}
	hc, err := httpClient(pu.Host, cfg, 30*time.Second)
	if err != nil {
		return "", err
	}
	// An answer that is a redirect is not followed: the payload (a key, when it is included) would go on to
	// a place the configured URL does not name, perhaps over plain HTTP. It is reported as a failure below.
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	payload := map[string]any{
		"name": b.Name, "domains": b.Domains, "serial": b.Serial,
		"not_after": b.NotAfter.Format(time.RFC3339), "fullchain_pem": string(b.FullChain),
	}
	if isTrue(cfg["include_key"]) {
		payload["key_pem"] = string(b.KeyPEM)
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(plugin.HidePath(ctx), http.MethodPost, u, bytes.NewReader(body)) // the URL may be a secret
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if h := cfg["auth_header"]; h != "" {
		req.Header.Set("Authorization", h)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
	}
	return fmt.Sprintf("webhook accepted (HTTP %d)", resp.StatusCode), nil
}

// ---- files -----------------------------------------------------------------

type filesTarget struct{}

func (filesTarget) Descriptor() plugin.Descriptor {
	fields := []plugin.Field{
		{Key: "dir", Label: "Directory", Type: "text", Required: true, Help: "Writes fullchain.pem, cert.pem, chain.pem and key.pem here."},
		{Key: "mode", Label: "Key file mode (octal)", Type: "text", Default: "0640"},
		{Key: "command", Label: "Post-deploy command (optional)", Type: "text",
			Help: "Run after the files are written, e.g. 'systemctl reload nginx'. Disabled unless CERTSMITH_ALLOW_COMMANDS=1 is set for the server."},
		verifyField,
	}
	return plugin.Descriptor{
		Kind:   "files",
		Vendor: "Generic",
		Label:  "Local files (+ optional command)",
		Help:   "Writes the certificate files to a directory on this server, for services on the same host or on a mounted share.",
		Fields: fields,
		Calls: []plugin.CallDoc{
			{Op: "test", Method: "-", Path: "(local)", Purpose: "Checks the directory can be written. No network calls."},
			{Op: "deploy", Method: "-", Path: "(local)", Changes: true, Purpose: "Writes fullchain.pem, cert.pem, chain.pem and key.pem to the directory, then runs your command if one is set. No network calls."},
		},
	}
}

func (filesTarget) Test(ctx context.Context, cfg map[string]string) (string, error) {
	st, err := os.Stat(cfg["dir"])
	if err != nil {
		return "", err
	}
	if !st.IsDir() {
		return "", fmt.Errorf("%s is not a directory", cfg["dir"])
	}
	return "directory exists", nil
}

func (filesTarget) Deploy(ctx context.Context, cfg map[string]string, b *plugin.Bundle) (string, error) {
	dir := cfg["dir"]
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	var keyMode os.FileMode = 0o640
	if m := strings.TrimSpace(cfg["mode"]); m != "" {
		var v uint32
		if _, err := fmt.Sscanf(m, "%o", &v); err == nil {
			keyMode = os.FileMode(v)
		}
	}
	for name, d := range map[string]struct {
		data []byte
		mode os.FileMode
	}{
		"fullchain.pem": {b.FullChain, 0o644}, "cert.pem": {b.CertPEM, 0o644},
		"chain.pem": {b.ChainPEM, 0o644}, "key.pem": {b.KeyPEM, keyMode},
	} {
		tmp := filepath.Join(dir, "."+name+".tmp")
		// Never write through a name someone else put there (a link, a stale file): remove it, then create
		// the file anew and exclusively, so a key cannot be written to a path planted in a shared directory.
		_ = os.Remove(tmp)
		f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, d.mode)
		if err != nil {
			return "", err
		}
		if _, err := f.Write(d.data); err != nil {
			f.Close()
			_ = os.Remove(tmp)
			return "", err
		}
		if err := f.Close(); err != nil {
			_ = os.Remove(tmp)
			return "", err
		}
		if err := os.Chmod(tmp, d.mode); err != nil { // the umask may have narrowed it
			_ = os.Remove(tmp)
			return "", err
		}
		if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
			return "", err
		}
	}
	msg := "files written to " + dir
	if cmd := strings.TrimSpace(cfg["command"]); cmd != "" {
		if !plugin.GetOptions().AllowCommands {
			return msg, fmt.Errorf("files written, but running commands is disabled (set CERTSMITH_ALLOW_COMMANDS=1)")
		}
		cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		c := exec.CommandContext(cctx, "/bin/sh", "-c", cmd)
		c.Env = commandEnv(dir, b.Serial)
		if out, err := c.CombinedOutput(); err != nil {
			return msg, fmt.Errorf("command failed: %v: %s", err, strings.TrimSpace(string(out)))
		}
		msg += "; command ok"
	}
	return msg, nil
}

// commandEnv is the environment of a post-deploy command: CertSmith's own, without the master key and the
// seed password (a command has no use for them, and a command that logs its environment must not leak them),
// plus where the files are and which certificate they hold.
func commandEnv(dir, serial string) []string {
	var env []string
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "CERTSMITH_MASTER_KEY=") || strings.HasPrefix(kv, "CERTSMITH_ADMIN_PASSWORD=") {
			continue
		}
		env = append(env, kv)
	}
	return append(env, "CERTSMITH_CERT_DIR="+dir, "CERTSMITH_SERIAL="+serial)
}

// ---- watch (monitor only) ----------------------------------------------------

type watchTarget struct{}

func (watchTarget) Descriptor() plugin.Descriptor {
	return plugin.Descriptor{
		Kind:   "watch",
		Vendor: "Generic",
		Label:  "Monitor only (no deployment)",
		Help:   "Checks the certificate served at each address and alerts on expiry or a mismatch. Nothing is deployed.",
		Fields: []plugin.Field{{Key: "verify", Label: "Addresses to watch", Type: "textarea", Required: true, Help: "host:port, one per line."}},
		Calls: []plugin.CallDoc{
			{Op: "test", Method: "-", Path: "(none)", Purpose: "Nothing to test. The live checks below make a TLS connection, not an API call."},
		},
	}
}

func (watchTarget) Test(context.Context, map[string]string) (string, error) { return "ok", nil }
func (watchTarget) Deploy(context.Context, map[string]string, *plugin.Bundle) (string, error) {
	return "monitor only", nil
}
