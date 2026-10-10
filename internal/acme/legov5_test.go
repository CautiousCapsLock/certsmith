package acme

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// lego v5 drops the common name unless asked and writes PKCS#8 keys. Both would change what is
// stored and what the device plug-ins receive, so the issuer puts them back.
func TestAnIssuedCertificateKeepsItsCommonNameAndTheKeyFormatCertSmithAlwaysStored(t *testing.T) {
	for _, kt := range []string{"ec256", "rsa3072"} {
		ca := newMockCA(t, "kid-1", testMAC)
		ca.prevalidated = true
		iss := &Issuer{DataDir: t.TempDir()}
		r := orderRequest(ca, []string{"app.example.com", "*.example.com"})
		r.KeyType = kt
		b, err := iss.Issue(context.Background(), r)
		if err != nil {
			t.Fatal(err)
		}
		if got := b.Leaf.Subject.CommonName; got != "app.example.com" {
			t.Errorf("%s: common name = %q, want the first name", kt, got)
		}
		blk, _ := pem.Decode(b.KeyPEM)
		want := map[string]string{"ec256": "EC PRIVATE KEY", "rsa3072": "RSA PRIVATE KEY"}[kt]
		if blk == nil {
			t.Fatalf("%s: no key PEM", kt)
		}
		if blk.Type != want {
			t.Errorf("%s: key PEM type = %q, want %q", kt, blk.Type, want)
		}
	}
}

func TestAnAccountSavedByVersion4IsStillRecognisedAndWrittenInTheSameShape(t *testing.T) {
	// registration.json as written by every earlier release
	legacy := []byte(`{"body":{"status":"valid","contact":["mailto:a@example.com"],"termsOfServiceAgreed":true},"uri":"https://ca.example/acme/acct/42"}`)
	reg := loadRegistration(legacy)
	if reg == nil || reg.Location != "https://ca.example/acme/acct/42" || reg.Status != "valid" || len(reg.Contact) != 1 {
		t.Fatalf("legacy registration read as %+v", reg)
	}
	out, err := marshalRegistration(reg)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(out, &m); err != nil || m["body"] == nil || string(m["uri"]) != `"https://ca.example/acme/acct/42"` {
		t.Fatalf("rewritten as %s (%v): must keep the body/uri shape so a rollback still finds the account", out, err)
	}
	if loadRegistration([]byte(`{"body":{}}`)) != nil || loadRegistration([]byte(`not json`)) != nil {
		t.Error("a file without an account URL must not count as registered")
	}
}

func TestAnExistingAccountIsReusedAfterTheUpgrade(t *testing.T) {
	ca := newMockCA(t, "kid-1", testMAC)
	dir := t.TempDir()
	iss := &Issuer{DataDir: dir}
	if _, err := iss.CheckAccount(context.Background(), eabRequest(ca, "kid-1", testMAC)); err != nil {
		t.Fatal(err)
	}
	// the file on disk must be in the legacy shape...
	files, _ := filepath.Glob(filepath.Join(dir, "acme", "*", "registration.json"))
	if len(files) != 1 {
		t.Fatalf("registration files: %v", files)
	}
	b, _ := os.ReadFile(files[0])
	if loadRegistration(b) == nil {
		t.Fatalf("not in the legacy shape: %s", b)
	}
	// ...and a second run finds the account instead of making another
	msg, err := iss.CheckAccount(context.Background(), eabRequest(ca, "kid-1", testMAC))
	if err != nil || len(ca.accounts()) != 1 {
		t.Fatalf("second check: %q %v, accounts=%d", msg, err, len(ca.accounts()))
	}
}

func TestTheIssuanceLogKeepsThePlainLineFormat(t *testing.T) {
	var buf strings.Builder
	l := slog.New(newLineHandler(&buf))
	l.Info("Obtaining bundled SAN certificate.", slog.String("domains", "a.example.com"))
	l.Debug("noise")
	l.Warn("careful")
	got := buf.String()
	re := regexp.MustCompile(`(?m)^\d{4}/\d\d/\d\d \d\d:\d\d:\d\d \[INFO\] Obtaining bundled SAN certificate\. domains=a\.example\.com\n\d{4}/\d\d/\d\d \d\d:\d\d:\d\d \[WARN\] careful\n$`)
	if !re.MatchString(got) {
		t.Fatalf("log = %q", got)
	}
}
