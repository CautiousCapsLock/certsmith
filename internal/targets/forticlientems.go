package targets

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/CautiousCapsLock/certsmith/internal/plugin"
)

func init() { plugin.RegisterTarget(forticlientEMS{}) }

// forticlientEMS watches a FortiClient EMS server. EMS (7.4) has no documented API for installing
// a server certificate, so nothing is deployed: the certificate is imported in the EMS console and
// CertSmith checks, on the web console port and on the port FortiClient endpoints connect to, that
// the server is serving it, and says when it is not.
type forticlientEMS struct{}

const emsClientPortDefault = "8013"

func (forticlientEMS) Descriptor() plugin.Descriptor {
	return plugin.Descriptor{
		Kind:   "forticlientems",
		Vendor: "Fortinet",
		Label:  "FortiClient EMS (manual import, monitored)",
		Help: "FortiClient EMS has no API for installing a server certificate, so CertSmith cannot deploy to it. " +
			"Import the certificate in the EMS console. CertSmith then checks the web console and the port " +
			"FortiClient endpoints connect to, and alerts when either serves a different certificate, an " +
			"incomplete chain, or one that is about to expire.",
		Manual: true,
		Fields: append(connFields("443", "e.g. ems.lab.example"), []plugin.Field{
			{Key: "client_port", Label: "FortiClient connection port", Type: "number", Default: emsClientPortDefault,
				Help: "The port FortiClient endpoints connect to (8013 by default). Enter 0 to check only the web console."},
			verifyField,
		}...),
		Calls: []plugin.CallDoc{
			{Op: "test", Method: "-", Path: "(none)", Purpose: "No API call is made. The live checks make a TLS connection to the console and client ports and read the certificate each serves."},
		},
		AutoVerify: true, AutoVerifyPort: "443",
	}
}

func (forticlientEMS) APIEndpoint(cfg map[string]string) string { return hostPort(cfg, "443") }

// DefaultProbes: the web console, and the port the FortiClient endpoints use.
func (forticlientEMS) DefaultProbes(cfg map[string]string) []string {
	out := []string{hostPort(cfg, "443")}
	port := strings.TrimSpace(cfg["client_port"])
	if port == "" {
		port = emsClientPortDefault
	}
	if port != "0" {
		h, _, err := net.SplitHostPort(hostPort(cfg, "443"))
		if err == nil {
			out = append(out, net.JoinHostPort(h, port))
		}
	}
	return out
}

// Test connects to each port and reports what it serves. It changes nothing and sends no request.
func (p forticlientEMS) Test(ctx context.Context, cfg map[string]string) (string, error) {
	var parts []string
	var failed []string
	for _, addr := range p.DefaultProbes(cfg) {
		d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 8 * time.Second}, Config: &tls.Config{InsecureSkipVerify: true}} // only the certificate is read
		c, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", addr, err))
			continue
		}
		state := c.(*tls.Conn).ConnectionState()
		_ = c.Close()
		if len(state.PeerCertificates) == 0 {
			failed = append(failed, addr+": no certificate was presented")
			continue
		}
		leaf := state.PeerCertificates[0]
		parts = append(parts, fmt.Sprintf("%s serves %s (expires %s)", addr, leaf.Subject.CommonName, leaf.NotAfter.Format("2006-01-02")))
	}
	if len(failed) > 0 {
		return "", errors.New(strings.Join(failed, "; "))
	}
	return strings.Join(parts, "; "), nil
}

// Deploy is refused: there is nothing CertSmith can send. The target is never armed for automatic
// deployment, so this is reached only if somebody asks for it directly.
func (forticlientEMS) Deploy(context.Context, map[string]string, *plugin.Bundle) (string, error) {
	return "", errors.New("FortiClient EMS has no API for installing a server certificate: import the certificate in the EMS console. CertSmith checks that the server is serving it")
}
