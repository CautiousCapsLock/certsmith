package targets

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/CautiousCapsLock/certsmith/internal/acme"
	"github.com/CautiousCapsLock/certsmith/internal/plugin"
)

// realisticBundle builds root -> intermediate -> leaf, the shape Let's Encrypt delivers,
// and returns the bundle plus the intermediate's PEM.
func realisticBundle(t *testing.T) (*plugin.Bundle, []byte) {
	t.Helper()
	mk := func(cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, ca bool) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		serial, _ := rand.Int(rand.Reader, big.NewInt(1<<60))
		tpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: cn},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(1, 0, 0), IsCA: ca, BasicConstraintsValid: true}
		if ca {
			tpl.KeyUsage = x509.KeyUsageCertSign
		} else {
			tpl.DNSNames = []string{"fw.lab.example"}
			tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		}
		signer, signKey := tpl, key
		if parent != nil {
			signer, signKey = parent, parentKey
		}
		der, err := x509.CreateCertificate(rand.Reader, tpl, signer, &key.PublicKey, signKey)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	root, rootKey, rootPEM := mk("Test Root", nil, nil, true)
	inter, interKey, interPEM := mk("Test Intermediate R1", root, rootKey, true)
	_, leafKey, leafPEM := mk("fw.lab.example", inter, interKey, false)
	kder, _ := x509.MarshalECPrivateKey(leafKey)
	b, err := acme.BundleFromPEM("t", []string{"fw.lab.example"}, append(append(leafPEM, interPEM...), rootPEM...),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}))
	if err != nil {
		t.Fatal(err)
	}
	return b, interPEM
}

func TestDeployInstallsTheIntermediateSoTheFullChainIsSent(t *testing.T) {
	f := newFakeFGT(t)
	b, interPEM := realisticBundle(t)
	msg, err := fortiGate{}.Deploy(context.Background(), capCfg(f, "admin-gui"), b)
	if err != nil {
		t.Fatal(err)
	}
	if f.caImport != 1 {
		t.Fatalf("expected exactly the intermediate to be installed (the self-signed root is skipped), got %d imports", f.caImport)
	}
	for _, pemText := range f.cas {
		if strings.TrimSpace(pemText) != strings.TrimSpace(string(interPEM)) {
			t.Fatal("what was installed is not the intermediate certificate")
		}
	}
	if !strings.Contains(msg, "installed 1 issuing CA") {
		t.Fatalf("the report should say so: %s", msg)
	}
}

func TestTheIntermediateIsNotInstalledTwice(t *testing.T) {
	f := newFakeFGT(t)
	b, _ := realisticBundle(t)
	cfg := capCfg(f, "admin-gui")
	if _, err := (fortiGate{}).Deploy(context.Background(), cfg, b); err != nil {
		t.Fatal(err)
	}
	msg, err := fortiGate{}.Deploy(context.Background(), cfg, b)
	if err != nil {
		t.Fatal(err)
	}
	if f.caImport != 1 || !strings.Contains(msg, "already installed") {
		t.Fatalf("a repeat deploy must recognise the installed CA: imports=%d msg=%s", f.caImport, msg)
	}
}

func TestInstallingTheChainCanBeSwitchedOff(t *testing.T) {
	f := newFakeFGT(t)
	b, _ := realisticBundle(t)
	cfg := capCfg(f, "admin-gui")
	cfg["install_chain"] = "false"
	if _, err := (fortiGate{}).Deploy(context.Background(), cfg, b); err != nil {
		t.Fatal(err)
	}
	if f.caImport != 0 {
		t.Fatalf("CA certificates were installed although the option was off")
	}
}

func TestAFailedCAInstallDoesNotFailTheDeployment(t *testing.T) {
	f := newFakeFGT(t)
	f.failCA = true
	b, _ := realisticBundle(t)
	msg, err := fortiGate{}.Deploy(context.Background(), capCfg(f, "admin-gui"), b)
	if err != nil {
		t.Fatalf("the certificate itself is fine: the deployment must not fail over the chain: %v", err)
	}
	if !strings.Contains(msg, "could not install the issuing CA") {
		t.Fatalf("but the report must say the chain is missing: %s", msg)
	}
	if f.values["system/global:admin-server-cert"] == "Fortinet_Factory" {
		t.Fatal("the certificate should still have been switched on")
	}
}

func TestRootsAreNeverInstalled(t *testing.T) {
	f := newFakeFGT(t)
	b := testBundle(t) // test CA is a self-signed root: leaf + root only
	msg, err := fortiGate{}.Deploy(context.Background(), capCfg(f, "admin-gui"), b)
	if err != nil {
		t.Fatal(err)
	}
	if f.caImport != 0 || !strings.Contains(msg, "no issuing CA to install") {
		t.Fatalf("a bare root must not be pushed into the device: imports=%d msg=%s", f.caImport, msg)
	}
}

// Current FortiOS lists its CA store without the certificates themselves (and lists its
// hundred-odd built-in CAs). A redeploy must still recognise what it installed earlier, not import
// it again and report a failure.
func TestAnAlreadyInstalledCAIsRecognisedEvenThoughTheListHidesTheCertificate(t *testing.T) {
	f := newFakeFGT(t)
	f.realCAs = true
	b, _ := realisticBundle(t)
	cfg := capCfg(f, "admin-gui")
	if msg, err := (fortiGate{}).Deploy(context.Background(), cfg, b); err != nil || !strings.Contains(msg, "installed 1 issuing CA") {
		t.Fatalf("first deploy: %q %v", msg, err)
	}
	tr := plugin.NewTrace("deploy")
	msg, err := (fortiGate{}).Deploy(plugin.WithTrace(context.Background(), tr), cfg, b)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(msg, "already installed") || strings.Contains(msg, "could not") {
		t.Fatalf("a redeploy must say the CA is already there: %s", msg)
	}
	if f.caImport != 1 {
		t.Fatalf("the CA was imported %d times", f.caImport)
	}
	// it read the user-added CA, and only that one (not the built-in ones)
	reads := 0
	for _, c := range tr.Calls() {
		if c.Method == "GET" && strings.HasPrefix(c.Path, "/api/v2/cmdb/vpn.certificate/ca/") {
			reads++
			if strings.Contains(c.Path, "Fortinet_CA") {
				t.Fatal("read a built-in CA")
			}
		}
	}
	if reads != 1 {
		t.Fatalf("read %d individual CAs", reads)
	}
	inDocumentedOrder(t, (fortiGate{}).Descriptor().Calls, "deploy", tr.Calls())
}

// If the device says "duplicate" (-328) for a CA we did not recognise, it is there already:
// that is not a failure either.
func TestADuplicateCAAnswerIsNotReportedAsAFailure(t *testing.T) {
	f := newFakeFGT(t)
	f.realCAs = true
	b, interPEM := realisticBundle(t)
	f.cas["CA_Cert_9"] = string(interPEM) // installed, but under a source the list does not flag as user
	// make the list hide it entirely so the plugin cannot recognise it
	f.hideUserCAs = true
	msg, err := (fortiGate{}).Deploy(context.Background(), capCfg(f, "admin-gui"), b)
	if err != nil || strings.Contains(msg, "could not") || !strings.Contains(msg, "already installed") {
		t.Fatalf("msg=%q err=%v", msg, err)
	}
}
