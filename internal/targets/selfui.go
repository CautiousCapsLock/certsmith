package targets

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/CautiousCapsLock/certsmith/internal/plugin"
)

func init() { plugin.RegisterTarget(selfUI{}) }

// selfUI installs a certificate for CertSmith's own web page. The server reads its
// certificate from files and reloads them when they change, so renewals take effect
// for new connections without a restart. It is for people who do not have a reverse
// proxy in front of CertSmith.
type selfUI struct{}

const (
	uiCertFile = "fullchain.pem"
	uiKeyFile  = "key.pem"
)

func (selfUI) Descriptor() plugin.Descriptor {
	return plugin.Descriptor{
		Kind:   "selfui",
		Vendor: "CertSmith",
		Hidden: true, // offered on the Settings page only, not in the general list of new targets
		Label:  "This server (web interface)",
		Help: "Presents this certificate on CertSmith's own web interface in place of the self-signed certificate, and keeps it renewed. " +
			"The page must be opened by a name that appears in the certificate. New connections use it immediately.",
		// no fields of its own: the page is checked automatically at the address it is served on
		Fields: []plugin.Field{},
		Calls: []plugin.CallDoc{
			{Op: "test", Method: "-", Path: "(local)", Purpose: "Checks the certificate folder can be written. No network calls."},
			{Op: "deploy", Method: "-", Path: "(local)", Changes: true, Purpose: "Replaces this server's own certificate files; new connections use them at once. No network calls."},
		},
	}
}

func uiDir() (string, error) {
	d := plugin.GetOptions().UITLSDir
	if d == "" {
		return "", fmt.Errorf("the web interface is running without TLS (-no-tls), so there is no certificate to replace")
	}
	return d, nil
}

func (selfUI) Test(ctx context.Context, cfg map[string]string) (string, error) {
	dir, err := uiDir()
	if err != nil {
		return "", err
	}
	f, err := os.CreateTemp(dir, ".write-test-*")
	if err != nil {
		return "", fmt.Errorf("cannot write to %s: %w", dir, err)
	}
	name := f.Name()
	f.Close()
	_ = os.Remove(name)
	return "ready: the certificate in " + dir + " will be replaced", nil
}

// DefaultProbes: the page itself, checked on this machine whatever name it is reached by.
func (selfUI) DefaultProbes(map[string]string) []string {
	listen := plugin.GetOptions().UIListen
	host, port, err := net.SplitHostPort(listen)
	if err != nil || port == "" {
		return nil
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return []string{net.JoinHostPort(host, port)}
}

func (selfUI) Deploy(ctx context.Context, cfg map[string]string, b *plugin.Bundle) (string, error) {
	dir, err := uiDir()
	if err != nil {
		return "", err
	}
	// key first, certificate last: the server reloads when the certificate file changes
	for _, f := range []struct {
		name string
		data []byte
		mode os.FileMode
	}{{uiKeyFile, b.KeyPEM, 0o600}, {uiCertFile, b.FullChain, 0o644}} {
		tmp := filepath.Join(dir, "."+f.name+".new")
		if err := os.WriteFile(tmp, f.data, f.mode); err != nil {
			return "", err
		}
		if err := os.Rename(tmp, filepath.Join(dir, f.name)); err != nil {
			return "", err
		}
	}
	return "installed for the web interface; new connections use it now", nil
}
