// Package targets registers the deployment plugins (FortiGate, FortiManager,
// FortiAnalyzer, Proxmox VE, webhook, files).
package targets

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/CautiousCapsLock/certsmith/internal/plugin"
)

// verifyField is appended to every target: addresses the engine probes over TLS
// after deployment (and periodically) to see what is really being served.
var verifyField = plugin.Field{
	Key: "verify", Label: "Verify addresses", Type: "textarea",
	Help: "Optional extra host:port endpoints to check, one per line (for example an SSL VPN on another port).",
}

// connFields are the Host and Port inputs shown side by side on one row.
func connFields(defaultPort, hostHelp string) []plugin.Field {
	return []plugin.Field{
		{Key: "host", Label: "Host", Type: "text", Required: true, Row: "conn", Help: hostHelp},
		{Key: "port", Label: "Port", Type: "number", Default: defaultPort, Row: "conn"},
	}
}

// hostPort joins the separate host and port fields. A "host:port" typed into
// the host field (the format earlier versions used) keeps working.
func hostPort(cfg map[string]string, defaultPort string) string {
	host := strings.TrimSpace(cfg["host"])
	port := strings.TrimSpace(cfg["port"])
	if h, p, err := net.SplitHostPort(host); err == nil { // "host:port" typed into the host box
		host = h
		if port == "" {
			port = p
		}
	}
	if port == "" {
		port = defaultPort
	}
	host = strings.Trim(host, "[]")
	return net.JoinHostPort(host, port)
}

// tlsFields hold how the API connection is trusted. They are hidden: people never
// type them. When a device presents a certificate that cannot be verified, the UI
// shows its details and asks whether to trust it, and that answer is stored as
// pin_sha256. The others only keep configurations saved by earlier versions working.
var tlsFields = []plugin.Field{
	{Key: "pin_sha256", Type: "hidden"},
	{Key: "ca_pem", Type: "hidden"},
	{Key: "server_name", Type: "hidden"},
	{Key: "insecure", Type: "hidden"},
}

// pinSet collects the certificate fingerprints that are trusted for this device:
// the one the user confirmed (pin_sha256) and the one CertSmith itself deployed
// (_trusted_sha256), so the API keeps working when the device starts serving the
// certificate we installed, even when it is addressed by IP.
func pinSet(cfg map[string]string) map[string]bool {
	out := map[string]bool{}
	for _, k := range []string{"pin_sha256", "_trusted_sha256"} {
		for _, p := range strings.FieldsFunc(cfg[k], func(r rune) bool { return r == ',' || r == ' ' || r == '\n' }) {
			if p = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(p), ":", "")); p != "" {
				out[p] = true
			}
		}
	}
	return out
}

// withDeployedPin returns cfg plus trust for the certificate about to be installed.
func withDeployedPin(cfg map[string]string, b *plugin.Bundle) map[string]string {
	out := make(map[string]string, len(cfg)+1)
	for k, v := range cfg {
		out[k] = v
	}
	sum := sha256.Sum256(b.Leaf.Raw)
	out["_trusted_sha256"] = strings.TrimSpace(out["_trusted_sha256"] + "," + hex.EncodeToString(sum[:]))
	return out
}

func isTrue(s string) bool { return s == "true" || s == "1" || s == "on" }

// httpClient builds a client honouring the tlsFields options. A matching pin OR
// a normal chain verification is accepted, so deployments that replace the
// device's own certificate keep working without reconfiguration.
func httpClient(host string, cfg map[string]string, timeout time.Duration) (*http.Client, error) {
	h := host
	if hh, _, err := net.SplitHostPort(host); err == nil {
		h = hh
	}
	serverName := cfg["server_name"]
	if serverName == "" {
		serverName = h
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName}
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	if ca := strings.TrimSpace(cfg["ca_pem"]); ca != "" {
		if !pool.AppendCertsFromPEM([]byte(ca)) {
			return nil, errors.New("ca_pem contains no valid certificate")
		}
	}
	pins := pinSet(cfg)
	switch {
	case isTrue(cfg["insecure"]):
		tc.InsecureSkipVerify = true
	case len(pins) > 0:
		tc.InsecureSkipVerify = true // replaced by the callback below
		tc.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("no peer certificate")
			}
			if sum := sha256.Sum256(raw[0]); pins[hex.EncodeToString(sum[:])] {
				return nil
			}
			leaf, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return err
			}
			inter := x509.NewCertPool()
			for _, r := range raw[1:] {
				if c, err := x509.ParseCertificate(r); err == nil {
					inter.AddCert(c)
				}
			}
			_, err = leaf.Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter, DNSName: serverName})
			return err
		}
	default:
		tc.RootCAs = pool
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: tracing{&http.Transport{TLSClientConfig: tc, DisableKeepAlives: true}},
	}, nil
}

// tracing records every request into the trace carried by the request's context (see
// plugin.Trace), so the API calls a plugin makes can be shown to the user without each plugin
// having to report them.
type tracing struct{ next http.RoundTripper }

func (t tracing) RoundTrip(req *http.Request) (*http.Response, error) {
	start := time.Now()
	resp, err := t.next.RoundTrip(req)
	status := 0
	if resp != nil {
		status = resp.StatusCode
	}
	plugin.Record(req.Context(), req.Method, req.URL, status, time.Since(start), err)
	return resp, err
}

// retryNet retries fn on transport-level failures (connection refused/reset,
// timeouts) — expected briefly when a device restarts its web service after a
// certificate change. HTTP error statuses are never retried.
func retryNet(ctx context.Context, attempts int, delay time.Duration, fn func() error) error {
	var err error
	for i := 0; i < attempts; i++ {
		if err = fn(); err == nil {
			return nil
		}
		var ae *apiError
		if errors.As(err, &ae) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
	}
	return err
}

type apiError struct {
	Status int
	Msg    string
	// Code is the status code inside a JSON-RPC answer (FortiManager, FortiAnalyzer), whose HTTP
	// status is 200 even when the request failed. HasCode is false for plain HTTP errors.
	Code    int
	HasCode bool
}

func (e *apiError) Error() string { return fmt.Sprintf("HTTP %d: %s", e.Status, e.Msg) }

func certName(prefix string, b *plugin.Bundle, max int) string {
	suffix := "-" + b.NotBefore.UTC().Format("20060102") + "-" + b.Serial[max0(len(b.Serial)-4):]
	if len(prefix)+len(suffix) > max {
		prefix = prefix[:max-len(suffix)]
	}
	return prefix + suffix
}

func max0(n int) int {
	if n < 0 {
		return 0
	}
	return n
}

// parseKey decodes a PEM private key (PKCS#1, PKCS#8 or SEC1).
func parseKey(keyPEM []byte) (any, error) {
	blk, _ := pem.Decode(keyPEM)
	if blk == nil {
		return nil, errors.New("no PEM private key")
	}
	if k, err := x509.ParsePKCS8PrivateKey(blk.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(blk.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParseECPrivateKey(blk.Bytes); err == nil {
		return k, nil
	}
	return nil, errors.New("unsupported private key format")
}

func chainCerts(chainPEM []byte) []*x509.Certificate {
	var out []*x509.Certificate
	rest := chainPEM
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			return out
		}
		if c, err := x509.ParseCertificate(blk.Bytes); err == nil {
			out = append(out, c)
		}
	}
}
