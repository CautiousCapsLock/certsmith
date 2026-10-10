package targets

import (
	"context"
	"crypto/tls"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CautiousCapsLock/certsmith/internal/plugin"
	"github.com/CautiousCapsLock/certsmith/internal/uitls"
)

func TestSelfUIReplacesTheWebInterfaceCertificateWhichIsThenServed(t *testing.T) {
	dir := t.TempDir()
	loader, err := uitls.New(dir) // the bootstrap self-signed certificate
	if err != nil {
		t.Fatal(err)
	}
	before := loader.Fingerprint()
	plugin.SetOptions(plugin.Options{UITLSDir: dir, UIListen: "0.0.0.0:8443"})
	t.Cleanup(func() { plugin.SetOptions(plugin.Options{}) })

	if _, err := (selfUI{}).Test(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	b := testBundle(t)
	if _, err := (selfUI{}).Deploy(context.Background(), nil, b); err != nil {
		t.Fatal(err)
	}

	after := loader.Fingerprint()
	if after == "" || after == before {
		t.Fatalf("the running server must serve the new certificate without a restart (before %s, after %s)", before, after)
	}
	// the files on disk are a valid, matching pair
	if _, err := tls.LoadX509KeyPair(filepath.Join(dir, "fullchain.pem"), filepath.Join(dir, "key.pem")); err != nil {
		t.Fatalf("installed pair is not valid: %v", err)
	}
	if st, _ := os.Stat(filepath.Join(dir, "key.pem")); st.Mode().Perm() != 0o600 {
		t.Fatalf("private key mode %v", st.Mode().Perm())
	}
}

func TestSelfUIWithoutTLSExplainsItself(t *testing.T) {
	plugin.SetOptions(plugin.Options{UITLSDir: ""})
	if _, err := (selfUI{}).Test(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "without TLS") {
		t.Fatalf("got %v", err)
	}
}

func TestSelfUIProbesTheLocalListener(t *testing.T) {
	plugin.SetOptions(plugin.Options{UITLSDir: "x", UIListen: "0.0.0.0:8443"})
	t.Cleanup(func() { plugin.SetOptions(plugin.Options{}) })
	if got := (selfUI{}).DefaultProbes(nil); len(got) != 1 || got[0] != "127.0.0.1:8443" {
		t.Fatalf("got %v", got)
	}
	plugin.SetOptions(plugin.Options{UITLSDir: "x", UIListen: "10.0.0.5:9443"})
	if got := (selfUI{}).DefaultProbes(nil); got[0] != "10.0.0.5:9443" {
		t.Fatalf("got %v", got)
	}
}
