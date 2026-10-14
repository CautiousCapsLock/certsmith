package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/CautiousCapsLock/certsmith/internal/model"
)

// mockCA is just enough of an ACME server to create an account, and to check the External Account
// Binding the way a CA does: the binding is a JWS over the account key, signed with HMAC-SHA256
// using the MAC key the CA issued for the key identifier.
type mockCA struct {
	srv  *httptest.Server
	kid  string
	mac  []byte // the key the CA issued
	mu   sync.Mutex
	acct []mockAccount

	// the order flow: whether this CA has already validated the account's domains, and what it saw
	prevalidated bool
	idents       []string
	orders       int
	challenged   bool // a challenge was handed out (the domains were not pre-validated)
	issued       bool
	caCert       *x509.Certificate
	caKey        *ecdsa.PrivateKey
	chainPEM     []byte

	// dns-persist-01 (see persist_test.go): when persist is set, authorisations offer that challenge
	// (and dns-01) and are validated against the records txt returns, as a CA reads DNS.
	persist     bool
	issuerName  string
	txt         func(name string) []string
	authzStatus map[int]string // by authorisation number: "valid" or "invalid" once answered
	answered    []string       // challenge types the client answered, in order
}

type mockAccount struct {
	HadEAB    bool
	EABKid    string
	EABValid  bool
	Contact   []string
	AccountOK bool
}

func newMockCA(t *testing.T, kid, macB64URL string) *mockCA {
	t.Helper()
	mac, err := base64.RawURLEncoding.DecodeString(macB64URL)
	if err != nil {
		t.Fatal(err)
	}
	m := &mockCA{kid: kid, mac: mac}
	m.caKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Mock Issuing CA"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().AddDate(5, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &m.caKey.PublicKey, m.caKey)
	if err != nil {
		t.Fatal(err)
	}
	m.caCert, _ = x509.ParseCertificate(caDER)
	m.srv = httptest.NewTLSServer(http.HandlerFunc(m.serve)) // an ACME client refuses a plain-HTTP CA
	t.Cleanup(m.srv.Close)
	// lego trusts the extra CA named in this variable, which is how its own tests reach a test CA
	pemFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(pemFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: m.srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LEGO_CA_CERTIFICATES", pemFile)
	return m
}

func (m *mockCA) dir() string { return m.srv.URL + "/directory" }

func b64(s string) []byte { b, _ := base64.RawURLEncoding.DecodeString(s); return b }

func (m *mockCA) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", "nonce-"+strings.ReplaceAll(r.URL.Path, "/", "-"))
	switch r.URL.Path {
	case "/directory":
		_ = json.NewEncoder(w).Encode(map[string]any{
			"newNonce": m.srv.URL + "/nonce", "newAccount": m.srv.URL + "/acct", "newOrder": m.srv.URL + "/order",
			"revokeCert": m.srv.URL + "/revoke", "keyChange": m.srv.URL + "/keychange",
			"meta": map[string]any{"externalAccountRequired": true},
		})
	case "/nonce":
		w.WriteHeader(http.StatusNoContent)
	case "/acct":
		var jws struct{ Protected, Payload, Signature string }
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &jws)
		var acct struct {
			Contact []string `json:"contact"`
			EAB     *struct {
				Protected, Payload, Signature string
			} `json:"externalAccountBinding"`
		}
		_ = json.Unmarshal(b64(jws.Payload), &acct)
		a := mockAccount{Contact: acct.Contact}
		if acct.EAB != nil {
			a.HadEAB = true
			var hdr struct{ Alg, Kid, URL string }
			_ = json.Unmarshal(b64(acct.EAB.Protected), &hdr)
			a.EABKid = hdr.Kid
			h := hmac.New(sha256.New, m.mac)
			h.Write([]byte(acct.EAB.Protected + "." + acct.EAB.Payload))
			a.EABValid = hdr.Alg == "HS256" && hdr.Kid == m.kid && hdr.URL == m.srv.URL+"/acct" &&
				hmac.Equal(h.Sum(nil), b64(acct.EAB.Signature))
		}
		a.AccountOK = a.HadEAB && a.EABValid
		m.mu.Lock()
		m.acct = append(m.acct, a)
		m.mu.Unlock()
		if !a.AccountOK {
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{"type": "urn:ietf:params:acme:error:unauthorized", "detail": "the external account binding is not valid"})
			return
		}
		w.Header().Set("Location", m.srv.URL+"/acct/1")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "valid", "contact": acct.Contact})
	case "/order":
		m.mu.Lock()
		defer m.mu.Unlock()
		var jws struct{ Payload string }
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &jws)
		var req struct {
			Identifiers []struct{ Type, Value string } `json:"identifiers"`
		}
		_ = json.Unmarshal(b64(jws.Payload), &req)
		m.idents, m.orders = nil, m.orders+1
		var authz []string
		for i, id := range req.Identifiers {
			m.idents = append(m.idents, id.Value)
			authz = append(authz, m.srv.URL+"/authz/"+strconvI(i+1))
		}
		status := "pending"
		if m.prevalidated {
			status = "ready"
		}
		w.Header().Set("Location", m.srv.URL+"/order/1")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": status, "identifiers": req.Identifiers, "authorizations": authz, "finalize": m.srv.URL + "/finalize/1"})
	case "/finalize/1":
		m.mu.Lock()
		defer m.mu.Unlock()
		var jws struct{ Payload string }
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &jws)
		var fin struct {
			CSR string `json:"csr"`
		}
		_ = json.Unmarshal(b64(jws.Payload), &fin)
		m.issued = true
		_ = m.sign(b64(fin.CSR))
		_ = json.NewEncoder(w).Encode(m.orderJSON("valid"))
	case "/order/1":
		m.mu.Lock()
		defer m.mu.Unlock()
		_ = json.NewEncoder(w).Encode(m.orderJSON(map[bool]string{true: "valid", false: "pending"}[m.issued]))
	case "/chall/1-persist", "/chall/2-persist", "/chall/3-persist", "/chall/1-dns", "/chall/2-dns", "/chall/3-dns":
		m.answerChallenge(w, r)
	case "/cert/1":
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		_, _ = w.Write(m.chainPEM)
	default:
		if strings.HasPrefix(r.URL.Path, "/authz/") {
			m.mu.Lock()
			defer m.mu.Unlock()
			n := int(r.URL.Path[len("/authz/")] - '0')
			value, wildcard := m.idents[n-1], false
			if strings.HasPrefix(value, "*.") {
				value, wildcard = value[2:], true
			}
			a := map[string]any{"status": "valid", "identifier": map[string]string{"type": "dns", "value": value}, "wildcard": wildcard}
			if m.persist {
				m.challenged = true
				a["status"] = "pending"
				if st := m.authzStatus[n]; st != "" {
					a["status"] = st
				}
				a["challenges"] = []map[string]any{
					{"type": "dns-persist-01", "url": m.srv.URL + "/chall/" + strconvI(n) + "-persist", "status": "pending",
						"accounturi": m.srv.URL + "/acct/1", "issuer-domain-names": []string{m.issuerName}},
					{"type": "dns-01", "url": m.srv.URL + "/chall/" + strconvI(n) + "-dns", "status": "pending", "token": "token-" + strconvI(n)},
				}
			} else if !m.prevalidated {
				m.challenged = true
				a["status"] = "pending"
				a["challenges"] = []map[string]any{{"type": "dns-01", "url": m.srv.URL + "/chall/" + strconvI(n), "status": "pending", "token": "token-" + strconvI(n)}}
			}
			_ = json.NewEncoder(w).Encode(a)
			return
		}
		http.NotFound(w, r)
	}
}

func strconvI(n int) string { return string(rune('0' + n)) }

// answerChallenge is the CA reading DNS when the client says it is ready.
func (m *mockCA) answerChallenge(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rest := strings.TrimPrefix(r.URL.Path, "/chall/")
	n := int(rest[0] - '0')
	typ := "dns-01"
	if strings.HasSuffix(rest, "-persist") {
		typ = "dns-persist-01"
	}
	m.answered = append(m.answered, typ)
	value, wildcard := m.idents[n-1], false
	if strings.HasPrefix(value, "*.") {
		value, wildcard = value[2:], true
	}
	ok := false
	switch typ {
	case "dns-persist-01":
		for _, v := range m.txt("_validation-persist." + value) {
			ok = ok || m.persistRecordOK(v, wildcard)
		}
	default: // any answer at all counts: the mock does not compute key authorisations
		ok = len(m.txt("_acme-challenge."+value)) > 0
	}
	status := "valid"
	body := map[string]any{"type": typ, "url": m.srv.URL + r.URL.Path}
	if !ok {
		status = "invalid"
		body["error"] = map[string]any{"type": "urn:ietf:params:acme:error:unauthorized", "detail": "No valid TXT record found for " + typ}
	}
	body["status"] = status
	if m.authzStatus == nil {
		m.authzStatus = map[int]string{}
	}
	m.authzStatus[n] = status
	w.Header().Set("Link", "<"+m.srv.URL+"/authz/"+strconvI(n)+">;rel=\"up\"")
	_ = json.NewEncoder(w).Encode(body)
}

// persistRecordOK is the CA's own rule for a dns-persist-01 record: its issuer, this account, the
// wildcard policy for a wildcard, and an end date that has not passed.
func (m *mockCA) persistRecordOK(v string, wildcard bool) bool {
	parts := strings.Split(v, ";")
	if strings.TrimSpace(parts[0]) != m.issuerName {
		return false
	}
	params := map[string]string{}
	for _, p := range parts[1:] {
		k, val, _ := strings.Cut(strings.TrimSpace(p), "=")
		params[strings.ToLower(k)] = val
	}
	if params["accounturi"] != m.srv.URL+"/acct/1" {
		return false
	}
	if wildcard && !strings.EqualFold(params["policy"], "wildcard") {
		return false
	}
	if u := params["persistuntil"]; u != "" {
		ts, err := strconv.ParseInt(u, 10, 64)
		if err != nil || time.Now().Unix() > ts {
			return false
		}
	}
	return true
}

func (m *mockCA) orderJSON(status string) map[string]any {
	o := map[string]any{"status": status, "finalize": m.srv.URL + "/finalize/1"}
	if status == "valid" {
		o["certificate"] = m.srv.URL + "/cert/1"
	}
	return o
}

// sign issues a certificate for the CSR lego sent, from the mock CA's own key.
func (m *mockCA) sign(csrDER []byte) error {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return err
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: serial, Subject: csr.Subject, DNSNames: csr.DNSNames,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(0, 3, 0),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, m.caCert, csr.PublicKey, m.caKey)
	if err != nil {
		return err
	}
	m.chainPEM = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: m.caCert.Raw})...)
	return nil
}

func (m *mockCA) accounts() []mockAccount {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]mockAccount(nil), m.acct...)
}

// MAC keys as a CA issues them: long, base64url
var (
	testMAC  = base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef0123456789abcdef"))
	otherMAC = base64.RawURLEncoding.EncodeToString([]byte("fedcba9876543210fedcba9876543210fedcba9876543210"))
)

func eabRequest(m *mockCA, kid, hmacKey string) Request {
	return Request{
		Directory: m.dir(), Email: "eab@example.com", EAB: &EAB{Kid: kid, HMAC: hmacKey},
		Settings: model.Settings{ACMEEmail: "settings@example.com", ACMEDirectory: model.DirProduction}, KeyType: "ec256",
	}
}

func TestAnAccountIsCreatedAtTheCAWithAValidExternalAccountBinding(t *testing.T) {
	ca := newMockCA(t, "kid-1", testMAC)
	iss := &Issuer{DataDir: t.TempDir()}
	msg, err := iss.CheckAccount(context.Background(), eabRequest(ca, "kid-1", testMAC))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(msg, "account created at "+ca.dir()) {
		t.Fatalf("msg = %q", msg)
	}
	accts := ca.accounts()
	if len(accts) != 1 || !accts[0].HadEAB || !accts[0].EABValid || accts[0].EABKid != "kid-1" {
		t.Fatalf("the CA saw %+v: the binding must name the key id and carry a valid HMAC signature", accts)
	}
	if len(accts[0].Contact) != 1 || accts[0].Contact[0] != "mailto:eab@example.com" {
		t.Fatalf("contact = %v: the provider's email, not the Settings one, belongs to this account", accts[0].Contact)
	}
	// the account is remembered: checking again does not register a second one
	msg, err = iss.CheckAccount(context.Background(), eabRequest(ca, "kid-1", testMAC))
	if err != nil || !strings.HasPrefix(msg, "account already set up") || len(ca.accounts()) != 1 {
		t.Fatalf("second check: %q %v accounts=%d", msg, err, len(ca.accounts()))
	}
}

func TestTheHMACKeyIsAcceptedHoweverTheCAShowsIt(t *testing.T) {
	std := strings.NewReplacer("-", "+", "_", "/").Replace(testMAC) + "=" // standard alphabet, padded
	for name, key := range map[string]string{"standard base64 with padding": std, "surrounding spaces": "  " + testMAC + "\n"} {
		ca := newMockCA(t, "kid-1", testMAC)
		iss := &Issuer{DataDir: t.TempDir()}
		if _, err := iss.CheckAccount(context.Background(), eabRequest(ca, "kid-1", key)); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if a := ca.accounts(); len(a) != 1 || !a[0].EABValid {
			t.Fatalf("%s: the CA did not accept the binding: %+v", name, a)
		}
	}
}

func TestAWrongHMACKeyIsRejectedAndNothingIsRemembered(t *testing.T) {
	ca := newMockCA(t, "kid-1", testMAC)
	dir := t.TempDir()
	iss := &Issuer{DataDir: dir}
	_, err := iss.CheckAccount(context.Background(), eabRequest(ca, "kid-1", otherMAC))
	if err == nil || !strings.Contains(err.Error(), "register ACME account") {
		t.Fatalf("err = %v", err)
	}
	if a := ca.accounts(); len(a) != 1 || a[0].AccountOK {
		t.Fatalf("the CA should have seen and refused one attempt: %+v", a)
	}
	// nothing was saved as registered, so correcting the key and trying again works
	var saved []string
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, _ error) error {
		if !d.IsDir() && filepath.Base(p) == "registration.json" {
			saved = append(saved, p)
		}
		return nil
	})
	if len(saved) != 0 {
		t.Fatalf("a failed registration was remembered: %v", saved)
	}
	if _, err := iss.CheckAccount(context.Background(), eabRequest(ca, "kid-1", testMAC)); err != nil {
		t.Fatalf("retry with the right key: %v", err)
	}
}

func TestAnHMACKeyThatIsNotBase64IsRefusedBeforeAnythingIsSent(t *testing.T) {
	ca := newMockCA(t, "kid-1", testMAC)
	iss := &Issuer{DataDir: t.TempDir()}
	if _, err := iss.CheckAccount(context.Background(), eabRequest(ca, "kid-1", "not base64 at all!!")); err == nil || !strings.Contains(err.Error(), "not valid base64") {
		t.Fatalf("err = %v", err)
	}
	if len(ca.accounts()) != 0 {
		t.Fatal("the CA should not have been contacted for a key that cannot be decoded")
	}
}

// An EAB account belongs to the key it was made with: new credentials at the same CA are a new account.
func TestChangingTheEABKeyMakesANewAccount(t *testing.T) {
	ca := newMockCA(t, "kid-1", testMAC)
	iss := &Issuer{DataDir: t.TempDir()}
	if _, err := iss.CheckAccount(context.Background(), eabRequest(ca, "kid-1", testMAC)); err != nil {
		t.Fatal(err)
	}
	ca.kid = "kid-2" // the user generated new credentials at the CA
	if _, err := iss.CheckAccount(context.Background(), eabRequest(ca, "kid-2", testMAC)); err != nil {
		t.Fatal(err)
	}
	a := ca.accounts()
	if len(a) != 2 || a[1].EABKid != "kid-2" || !a[1].EABValid {
		t.Fatalf("accounts = %+v", a)
	}
}

func TestAccountEmailFallsBackToSettingsWhenTheProviderHasNone(t *testing.T) {
	ca := newMockCA(t, "kid-1", testMAC)
	iss := &Issuer{DataDir: t.TempDir()}
	r := eabRequest(ca, "kid-1", testMAC)
	r.Email = ""
	if _, err := iss.CheckAccount(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if c := ca.accounts()[0].Contact; len(c) != 1 || c[0] != "mailto:settings@example.com" {
		t.Fatalf("contact = %v", c)
	}
	r2 := eabRequest(ca, "kid-1", testMAC)
	r2.Email, r2.Settings.ACMEEmail = "", ""
	if _, err := (&Issuer{DataDir: t.TempDir()}).CheckAccount(context.Background(), r2); err == nil || !strings.Contains(err.Error(), "ACME account email") {
		t.Fatalf("with no email anywhere: %v", err)
	}
}

func TestNormalizeHMACAndValidDirectory(t *testing.T) {
	long := strings.Repeat("ab+/", 12) // 48 characters: a plausible length, in the standard alphabet
	if got, err := NormalizeHMAC(" " + long + "== \n"); err != nil || got != strings.Repeat("ab-_", 12) {
		t.Fatalf("got %q %v", got, err)
	}
	if _, err := NormalizeHMAC("abcd"); err == nil || !strings.Contains(err.Error(), "too short") {
		t.Fatalf("a key far shorter than any CA issues must be refused with a clear message: %v", err)
	}
	for _, bad := range []string{"", "   ", "***"} {
		if _, err := NormalizeHMAC(bad); err == nil {
			t.Errorf("%q should be refused", bad)
		}
	}
	for _, ok := range []string{"https://acme.zerossl.com/v2/DV90", " https://ca.example/dir "} {
		if err := ValidDirectory(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "http://ca.example/dir", "acme.zerossl.com", "https://"} {
		if err := ValidDirectory(bad); err == nil {
			t.Errorf("%q should be refused", bad)
		}
	}
	for _, p := range CAPresets {
		if p.ID != CustomCA {
			if err := ValidDirectory(p.Directory); err != nil {
				t.Errorf("preset %s: %v", p.ID, err)
			}
		}
	}
}

// ---- providers without DNS credentials ----------------------------------------------------

func orderRequest(m *mockCA, domains []string) Request {
	r := eabRequest(m, "kid-1", testMAC)
	r.Name, r.Domains, r.Solver = "cert", domains, NoChallenge{}
	return r
}

// A CA that has validated the account's domains ahead of time hands out already-valid
// authorizations, so a provider with no DNS credentials can still get a certificate.
func TestACertificateIsIssuedWithNoDNSCredentialsWhenTheCAHasValidatedTheDomains(t *testing.T) {
	ca := newMockCA(t, "kid-1", testMAC)
	ca.prevalidated = true
	iss := &Issuer{DataDir: t.TempDir()}
	b, err := iss.Issue(context.Background(), orderRequest(ca, []string{"app.example.com", "*.example.com"}))
	if err != nil {
		t.Fatal(err)
	}
	if a := ca.accounts(); len(a) != 1 || !a[0].EABValid {
		t.Fatalf("the account must be created with the binding: %+v", a)
	}
	if ca.challenged {
		t.Fatal("no challenge should have been needed")
	}
	if got := b.Leaf.DNSNames; len(got) != 2 {
		t.Fatalf("certificate names = %v", got)
	}
	if b.Leaf.Issuer.CommonName != "Mock Issuing CA" || len(b.Serial) == 0 || b.KeyPEM == nil {
		t.Fatalf("bundle = %+v", b)
	}
}

// A CA that wants a challenge cannot be answered without DNS credentials: it fails at once, and says why.
func TestACAThatAsksForAChallengeFailsClearlyWhenThereAreNoDNSCredentials(t *testing.T) {
	ca := newMockCA(t, "kid-1", testMAC)
	iss := &Issuer{DataDir: t.TempDir()}
	_, err := iss.Issue(context.Background(), orderRequest(ca, []string{"app.example.com"}))
	if err == nil {
		t.Fatal("expected a failure")
	}
	for _, want := range []string{"no DNS credentials", "app.example.com", "validate the name in your CA account"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q: %v", want, err)
		}
	}
	if ca.issued {
		t.Fatal("nothing should have been issued")
	}
}

func TestOnlyCAsThatCanPreValidateAllowAProviderWithoutDNS(t *testing.T) {
	for id, want := range map[string]bool{"sectigo": true, CustomCA: true, "zerossl": false, "google": false} {
		if got := PreValidates(id); got != want {
			t.Errorf("PreValidates(%q) = %v, want %v", id, got, want)
		}
	}
	if !PreValidates("never-heard-of-it") {
		t.Error("a CA that is not a preset is the user's own: do not forbid it")
	}
	if CALabel("zerossl") != "ZeroSSL" || CALabel("x") != "x" {
		t.Error("CALabel")
	}
}
