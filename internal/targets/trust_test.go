package targets

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/CautiousCapsLock/certsmith/internal/plugin"
)

func verifyingCfg(f *fakeFGT) map[string]string {
	cfg := capCfg(f, "admin-gui")
	delete(cfg, "insecure") // real verification, as a user would have it
	return cfg
}

func TestUntrustedCertificateIsDetectedAndConfirmingItFixesTheConnection(t *testing.T) {
	f := newFakeFGT(t) // serves a self-signed certificate, like a FortiGate before it has a real one
	ctx := context.Background()
	cfg := verifyingCfg(f)

	_, err := fortiGate{}.Test(ctx, cfg)
	if err == nil || !plugin.IsTLSTrustError(err) {
		t.Fatalf("a self-signed certificate must surface as a trust error the UI can act on, got %v", err)
	}

	// what the UI shows the user before they decide
	info, err := plugin.FetchCert(ctx, fortiGate{}.APIEndpoint(cfg))
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(f.srv.Certificate().Raw)
	if info.Fingerprint != hex.EncodeToString(want[:]) {
		t.Fatalf("fingerprint %s is not the certificate the device presented", info.Fingerprint)
	}
	if !info.SelfSigned || info.Expired || info.Subject == "" {
		t.Fatalf("details shown to the user are wrong: %+v", info)
	}

	// "Trust this certificate" stores the fingerprint; the same connection now works
	cfg["pin_sha256"] = strings.ToUpper(info.Fingerprint) // case and colons must not matter
	if _, err := (fortiGate{}).Test(ctx, cfg); err != nil {
		t.Fatalf("after trusting the certificate: %v", err)
	}
	colon := ""
	for i := 0; i < len(info.Fingerprint); i += 2 {
		colon += info.Fingerprint[i:i+2] + ":"
	}
	cfg["pin_sha256"] = strings.TrimSuffix(colon, ":")
	if _, err := (fortiGate{}).Test(ctx, cfg); err != nil {
		t.Fatalf("colon-separated fingerprint should work: %v", err)
	}
}

func TestAChangedCertificateIsNotSilentlyTrusted(t *testing.T) {
	f := newFakeFGT(t)
	cfg := verifyingCfg(f)
	cfg["pin_sha256"] = strings.Repeat("0", 64) // trusted an earlier certificate; the device now presents another
	_, err := fortiGate{}.Test(context.Background(), cfg)
	if err == nil || !plugin.IsTLSTrustError(err) {
		t.Fatalf("a different certificate than the one trusted must be rejected as untrusted, got %v", err)
	}
}

func TestTheCertificateWeDeployedIsTrusted(t *testing.T) {
	f := newFakeFGT(t)
	cfg := verifyingCfg(f)
	sum := sha256.Sum256(f.srv.Certificate().Raw)
	cfg["_trusted_sha256"] = hex.EncodeToString(sum[:])
	if _, err := (fortiGate{}).Test(context.Background(), cfg); err != nil {
		t.Fatalf("a device serving the certificate CertSmith installed must be trusted even by IP: %v", err)
	}
}

func TestWithDeployedPinAddsTheNewLeaf(t *testing.T) {
	b := testBundle(t)
	cfg := withDeployedPin(map[string]string{"pin_sha256": "aa", "_trusted_sha256": "bb"}, b)
	sum := sha256.Sum256(b.Leaf.Raw)
	got := pinSet(cfg)
	for _, want := range []string{"aa", "bb", hex.EncodeToString(sum[:])} {
		if !got[want] {
			t.Errorf("pin set %v lacks %s", got, want)
		}
	}
}

func TestPlainNetworkErrorsAreNotTrustErrors(t *testing.T) {
	f := newFakeFGT(t)
	cfg := verifyingCfg(f)
	cfg["port"] = "1" // nothing listens there
	_, err := fortiGate{}.Test(context.Background(), cfg)
	if err == nil || plugin.IsTLSTrustError(err) {
		t.Fatalf("a refused connection is not a certificate problem: %v", err)
	}
}

func TestTLSFieldsAreHiddenInTheForm(t *testing.T) {
	for _, f := range tlsFields {
		if f.Type != "hidden" {
			t.Errorf("%s should not be shown to people", f.Key)
		}
	}
}
