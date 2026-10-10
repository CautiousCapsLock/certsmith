package uitls

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func readCert(t *testing.T, dir string) *x509.Certificate {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, CertFile))
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(b)
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRegenerateReplacesTheCertificateAndAKeyThatMatchesIt(t *testing.T) {
	dir := t.TempDir()
	l, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	before, fpBefore := readCert(t, dir), l.Fingerprint()

	time.Sleep(20 * time.Millisecond) // the loader watches the file's modification time
	if err := Regenerate(dir); err != nil {
		t.Fatal(err)
	}
	after := readCert(t, dir)
	if after.SerialNumber.Cmp(before.SerialNumber) == 0 {
		t.Error("the serial number did not change")
	}
	if _, err := tls.LoadX509KeyPair(filepath.Join(dir, CertFile), filepath.Join(dir, KeyFile)); err != nil {
		t.Errorf("the new certificate and key do not match: %v", err)
	}
	if got := l.Fingerprint(); got == "" || got == fpBefore {
		t.Error("a running loader did not pick up the new certificate")
	}
	if !IsBootstrap(after) {
		t.Error("a regenerated certificate must still be recognised as CertSmith's own")
	}
	if want := time.Now().AddDate(lifetimeYears, 0, 0); after.NotAfter.Before(want.Add(-time.Hour)) {
		t.Errorf("valid until %v, want about %v", after.NotAfter, want)
	}
	st, _ := os.Stat(filepath.Join(dir, KeyFile))
	if st.Mode().Perm() != 0o600 {
		t.Errorf("key mode %v", st.Mode().Perm())
	}
	for _, f := range []string{KeyFile + ".new", CertFile + ".new"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err == nil {
			t.Errorf("%s was left behind", f)
		}
	}
}

func TestRenewIfDue(t *testing.T) {
	now := time.Now()
	soon := t.TempDir()
	if err := generateUntil(soon, now.Add(10*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	old := readCert(t, soon)
	renewed, err := RenewIfDue(soon, 30*24*time.Hour, now)
	if err != nil || !renewed {
		t.Fatalf("renewed=%v err=%v, want a renewal ten days before expiry", renewed, err)
	}
	if got := readCert(t, soon); got.SerialNumber.Cmp(old.SerialNumber) == 0 || got.NotAfter.Sub(now) < 4*365*24*time.Hour {
		t.Errorf("not replaced by a fresh certificate: %v", got.NotAfter)
	}

	expired := t.TempDir()
	if err := generateUntil(expired, now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if renewed, err := RenewIfDue(expired, 30*24*time.Hour, now); err != nil || !renewed {
		t.Errorf("an expired certificate must be renewed: %v %v", renewed, err)
	}

	plenty := t.TempDir()
	if err := generateUntil(plenty, now.AddDate(2, 0, 0)); err != nil {
		t.Fatal(err)
	}
	if renewed, err := RenewIfDue(plenty, 30*24*time.Hour, now); err != nil || renewed {
		t.Errorf("a certificate with two years left was renewed: %v %v", renewed, err)
	}
}

// A certificate someone supplied (or CertSmith issued for the page) must never be replaced by a
// self-signed one, however close to expiry it is.
func TestARealCertificateIsNeverReplaced(t *testing.T) {
	dir := t.TempDir()
	if err := generateUntil(t.TempDir(), time.Now()); err != nil { // (exercise the helper)
		t.Fatal(err)
	}
	// a self-signed certificate that is NOT CertSmith's: another organisation
	foreign, key := selfSigned(t, "Somebody Else Ltd", time.Now().Add(24*time.Hour))
	if err := os.WriteFile(filepath.Join(dir, CertFile), foreign, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, KeyFile), key, 0o600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(dir, CertFile))
	renewed, err := RenewIfDue(dir, 30*24*time.Hour, time.Now())
	if err != nil || renewed {
		t.Fatalf("renewed=%v err=%v", renewed, err)
	}
	after, _ := os.ReadFile(filepath.Join(dir, CertFile))
	if string(before) != string(after) {
		t.Fatal("a certificate that is not CertSmith's own was overwritten")
	}
	if IsBootstrap(readCert(t, dir)) {
		t.Error("another organisation's self-signed certificate must not count as the bootstrap one")
	}
}

func TestAFreshCertificateCoversThisMachine(t *testing.T) {
	dir := t.TempDir()
	if err := generate(dir); err != nil {
		t.Fatal(err)
	}
	if m := Missing(readCert(t, dir)); len(m) != 0 {
		t.Errorf("a certificate made just now lists names this machine has but it does not cover: %v", m)
	}
	// a certificate made elsewhere (other host name, other addresses) reports what it lacks
	other, _ := selfSigned(t, BootstrapOrg, time.Now().Add(time.Hour))
	blk, _ := pem.Decode(other)
	c, _ := x509.ParseCertificate(blk.Bytes)
	if host, _ := os.Hostname(); host != "" && len(Missing(c)) == 0 {
		t.Error("a certificate for a different machine should report the host name it does not cover")
	}
}

func selfSigned(t *testing.T, org string, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()
	dir := t.TempDir()
	if err := generateUntil(dir, notAfter); err != nil {
		t.Fatal(err)
	}
	// re-sign the same key under another organisation, for a name no machine has
	key, err := os.ReadFile(filepath.Join(dir, KeyFile))
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(key)
	priv, err := x509.ParseECPrivateKey(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<60))
	tpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "elsewhere.invalid", Organization: []string{org}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter, DNSNames: []string{"elsewhere.invalid"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), key
}
