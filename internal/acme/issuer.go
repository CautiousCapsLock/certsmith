package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/go-acme/lego/v5/certificate"
	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/challenge/dns01"
	"github.com/go-acme/lego/v5/lego"
	legolog "github.com/go-acme/lego/v5/log"
	"github.com/go-acme/lego/v5/registration"

	"github.com/CautiousCapsLock/certsmith/internal/model"
	"github.com/CautiousCapsLock/certsmith/internal/plugin"
)

type Issuer struct{ DataDir string }

type Request struct {
	// SettleFor, when set, replaces the check of the nameservers with a fixed wait (see waiter).
	SettleFor time.Duration
	// Log, if set, receives lego's ACME log (verbose, as it happens) in addition to stderr.
	Log      io.Writer
	Name     string
	Domains  []string
	KeyType  string // rsa2048 | rsa3072 | rsa4096 | ec256 | ec384
	Settings model.Settings
	Solver   challenge.Provider // DNS-01 solver; a certificate cannot be issued without one (except by the built-in test CA)

	// Persist, when set, validates names with the standing dns-persist-01 record instead of a DNS-01
	// record written on each issuance. Solver is then only the fallback, for when the record is not
	// in DNS (NoChallenge, or nil, means there is none).
	Persist *Persist
	// PropagationWait bounds the wait for a published record to be visible everywhere (0: two minutes).
	PropagationWait time.Duration
	// OnFallback is told why dns-persist-01 was given up for DNS-01.
	OnFallback func(reason error)

	// A provider for another CA overrides the Let's Encrypt settings: Directory replaces
	// Settings.ACMEDirectory, Email replaces Settings.ACMEEmail, and EAB, when set, registers the
	// account with External Account Binding.
	Directory string
	Email     string
	EAB       *EAB
}

// NoChallenge is the DNS-01 solver of a provider that has no DNS credentials. A CA that has already
// validated a name in the account never asks for a challenge, so it is never called. If the CA does
// ask, it fails the issuance with an explanation instead of leaving the CA waiting for a record.
type NoChallenge struct{}

func (NoChallenge) Present(_ context.Context, domain, token, keyAuth string) error {
	return fmt.Errorf("the CA asked for a DNS challenge for %s, but this provider has no DNS credentials: "+
		"validate the name in your CA account first, or add DNS credentials to the provider", domain)
}

func (NoChallenge) CleanUp(_ context.Context, domain, token, keyAuth string) error { return nil }

// EAB is the External Account Binding a CA issued: the key identifier and the MAC key (base64url).
type EAB struct{ Kid, HMAC string }

func (r Request) directory() string {
	if r.Directory != "" {
		return r.Directory
	}
	return r.Settings.ACMEDirectory
}

func (r Request) email() string {
	if e := strings.TrimSpace(r.Email); e != "" {
		return e
	}
	return strings.TrimSpace(r.Settings.ACMEEmail)
}

// issueMu serialises issuances. lego logs through a process-wide logger and
// providers read credentials from the process environment, so concurrent runs
// would mix their output; ACME rate limits favour going one at a time anyway.
var issueMu sync.Mutex

func (i *Issuer) Issue(ctx context.Context, r Request) (*plugin.Bundle, error) {
	issueMu.Lock()
	defer issueMu.Unlock()
	if r.Log != nil {
		prev := legolog.Default()
		legolog.SetDefault(slog.New(newLineHandler(io.MultiWriter(os.Stderr, r.Log))))
		defer legolog.SetDefault(prev)
	}
	if len(r.Domains) == 0 {
		return nil, errors.New("no domains")
	}
	if r.directory() == model.DirSelfSigned {
		return i.issueSelfSigned(r)
	}
	if r.Solver == nil && r.Persist == nil {
		return nil, errors.New("no DNS provider chosen: CertSmith validates names with DNS-01, so a certificate needs DNS credentials")
	}
	return i.issueACME(ctx, r)
}

func directoryURL(s string) string {
	switch s {
	case model.DirProduction, "":
		return lego.DirectoryURLLetsEncrypt
	case model.DirStaging:
		return lego.DirectoryURLLetsEncryptStaging
	}
	return s
}

func keyType(s string) certcrypto.KeyType {
	switch s {
	case "ec256":
		return certcrypto.EC256
	case "ec384":
		return certcrypto.EC384
	case "rsa3072":
		return certcrypto.RSA3072
	case "rsa4096":
		return certcrypto.RSA4096
	}
	return certcrypto.RSA2048
}

// errCancelled is what an aborted DNS wait reports; the engine recognises a
// user stop by the cancelled context, not by this text.
var errCancelled = errors.New("cancelled by user")

// ctxTransport refuses to start any ACME request once the issuance was stopped,
// so a stop cannot be followed by the CA being asked to validate anything.
type ctxTransport struct {
	ctx  context.Context
	next http.RoundTripper
}

func (t ctxTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if err := t.ctx.Err(); err != nil {
		return nil, err
	}
	return t.next.RoundTrip(r)
}

// waiter is attached to lego's DNS propagation wait. lego's wait loop ends as soon as the check
// reports (true, err), which is how it ends at once when the issuance is stopped.
//
// Normally it asks the zone's nameservers whether the record is visible, and logs what each one
// serves every ten seconds: when a provider publishes slowly that timeline is the evidence. When
// settle is set it does not ask at all and simply waits that long. That is for networks that
// intercept DNS: there the "nameserver" answering is a cache that can keep an old answer (even
// "no such name") for minutes, so the check cannot be believed. Let's Encrypt validates from
// outside the network and sees the truth, so a fixed wait for the provider to publish is sound.
type waiter struct {
	ctx     context.Context
	log     io.Writer
	settle  time.Duration
	started time.Time
	last    time.Time
}

func (w *waiter) run(ctx context.Context, domain, fqdn, value string, check dns01.PreCheckFunc) (bool, error) {
	if w.ctx.Err() != nil {
		return true, errCancelled
	}
	if w.started.IsZero() {
		w.started = time.Now()
	}
	if w.settle > 0 {
		if time.Since(w.started) < w.settle {
			return false, nil
		}
		return true, nil
	}
	if w.log != nil && time.Since(w.last) >= 10*time.Second {
		w.last = time.Now()
		observe(w.ctx, w.log, fqdn, value)
	}
	return check(ctx, fqdn, value)
}

func waitHook(ctx context.Context, logw io.Writer, settle time.Duration) dns01.ChallengeOption {
	return dns01.WrapPreCheck((&waiter{ctx: ctx, log: logw, settle: settle}).run)
}

// Intercepted reports whether outbound DNS is being answered on the way by something that is not
// the server asked: a gateway's DNS proxy, a firewall's DNS filter. A clean network never answers a
// query sent to an address where no DNS server lives, so any answer at all gives it away.
func Intercepted(ctx context.Context) (bool, string) {
	for _, addr := range interceptProbes {
		c, cancel := context.WithTimeout(ctx, 2*time.Second)
		r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 2 * time.Second}
			return d.DialContext(ctx, "udp", net.JoinHostPort(addr, interceptPort))
		}}
		_, err := r.LookupTXT(c, "certsmith-interception-check.example.net")
		cancel()
		var de *net.DNSError
		if err == nil || (errors.As(err, &de) && de.IsNotFound) { // an answer, even "no such name"
			return true, addr
		}
	}
	return false, ""
}

// interceptProbes are documentation-only (RFC 5737) addresses: nothing real answers there.
var (
	interceptProbes = []string{"192.0.2.53", "198.51.100.53"}
	interceptPort   = "53"
)

func observe(ctx context.Context, w io.Writer, fqdn, value string) {
	zone, err := dns01.DefaultClient().FindZoneByFqdn(ctx, fqdn)
	if err != nil {
		return
	}
	nss, err := net.LookupNS(strings.TrimSuffix(zone, "."))
	if err != nil {
		return
	}
	for _, ns := range nss {
		host := strings.TrimSuffix(ns.Host, ".")
		vals, err := txtAt(ctx, host, fqdn)
		fmt.Fprintf(w, "%s [CERTSMITH] %s\n", time.Now().Format("2006/01/02 15:04:05"), describeObservation(host, vals, err, value))
	}
}

// describeObservation words what one nameserver returned for the challenge name.
func describeObservation(ns string, vals []string, err error, value string) string {
	switch {
	case err != nil:
		return fmt.Sprintf("DNS check: %s could not be queried: %v", ns, err)
	case contains(vals, value):
		return fmt.Sprintf("DNS check: %s serves %d TXT value(s) and the record for this run IS among them", ns, len(vals))
	case len(vals) == 0:
		return fmt.Sprintf("DNS check: %s serves no TXT record at this name yet", ns)
	default:
		return fmt.Sprintf("DNS check: %s serves %d TXT value(s), but not the record for this run yet", ns, len(vals))
	}
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// txtAt asks one specific nameserver (not a recursive resolver) for the TXT records at a name.
func txtAt(ctx context.Context, server, fqdn string) ([]string, error) {
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		d := net.Dialer{Timeout: 5 * time.Second}
		return d.DialContext(ctx, "udp", net.JoinHostPort(server, "53"))
	}}
	vals, err := r.LookupTXT(ctx, strings.TrimSuffix(fqdn, "."))
	var de *net.DNSError
	if errors.As(err, &de) && de.IsNotFound { // "no such host" here means "no record at that name": an answer, not a failure
		return nil, nil
	}
	return vals, err
}

type legoUser struct {
	email string
	reg   *acme.ExtendedAccount
	key   crypto.Signer
}

func (u *legoUser) GetEmail() string                       { return u.email }
func (u *legoUser) GetRegistration() *acme.ExtendedAccount { return u.reg }
func (u *legoUser) GetPrivateKey() crypto.Signer           { return u.key }

// savedRegistration is registration.json as it has always been written (lego v4's registration.Resource:
// the account object and its URL). It is kept in that shape so a build that went back to an older
// version still finds its accounts.
type savedRegistration struct {
	Body acme.Account `json:"body"`
	URI  string       `json:"uri"`
}

func loadRegistration(b []byte) *acme.ExtendedAccount {
	var sr savedRegistration
	if json.Unmarshal(b, &sr) != nil || sr.URI == "" {
		return nil
	}
	return &acme.ExtendedAccount{Account: sr.Body, Location: sr.URI}
}

func marshalRegistration(r *acme.ExtendedAccount) ([]byte, error) {
	return json.Marshal(savedRegistration{Body: r.Account, URI: r.Location})
}

// account loads or creates the ACME account key for a directory + email (+ EAB key id).
func (i *Issuer) account(dirURL, email, kid string) (*legoUser, string, error) {
	id := dirURL + "|" + email
	if kid != "" { // an EAB account is tied to the key it was created with; the others keep the name they always had
		id += "|" + kid
	}
	sum := sha256.Sum256([]byte(id))
	dir := filepath.Join(i.DataDir, "acme", hex.EncodeToString(sum[:6]))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, "", err
	}
	u := &legoUser{email: email}
	keyPath := filepath.Join(dir, "account.key")
	if b, err := os.ReadFile(keyPath); err == nil {
		blk, _ := pem.Decode(b)
		if blk == nil {
			return nil, "", errors.New("corrupt account key")
		}
		k, err := x509.ParseECPrivateKey(blk.Bytes)
		if err != nil {
			return nil, "", err
		}
		u.key = k
	} else if errors.Is(err, fs.ErrNotExist) {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, "", err
		}
		der, _ := x509.MarshalECPrivateKey(k)
		if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
			return nil, "", err
		}
		u.key = k
	} else {
		return nil, "", err
	}
	if b, err := os.ReadFile(filepath.Join(dir, "registration.json")); err == nil {
		u.reg = loadRegistration(b)
	}
	return u, dir, nil
}

// setup prepares an ACME client for a request: the account key for this CA and email (made on first
// use) and a client bound to the CA's directory.
func (i *Issuer) setup(ctx context.Context, r Request) (*lego.Client, *legoUser, string, error) {
	email := r.email()
	if email == "" {
		return nil, nil, "", errors.New("set an ACME account email in Settings (or on the certificate provider) first")
	}
	dirURL := directoryURL(r.directory())
	kid := ""
	if r.EAB != nil {
		kid = strings.TrimSpace(r.EAB.Kid)
	}
	user, accDir, err := i.account(dirURL, email, kid)
	if err != nil {
		return nil, nil, "", err
	}
	cfg := lego.NewConfig(user)
	cfg.CADirURL = dirURL
	cfg.HTTPClient.Transport = ctxTransport{ctx: ctx, next: cfg.HTTPClient.Transport}
	client, err := lego.NewClient(cfg)
	if err != nil {
		return nil, nil, "", err
	}
	return client, user, accDir, nil
}

// register creates the account at the CA the first time, with External Account Binding when the
// provider has it, and remembers it. It reports whether it had to create it.
func register(ctx context.Context, client *lego.Client, user *legoUser, accDir string, eab *EAB) (bool, error) {
	if user.reg != nil {
		return false, nil
	}
	var reg *acme.ExtendedAccount
	var err error
	if eab != nil {
		hmac, herr := NormalizeHMAC(eab.HMAC)
		if herr != nil {
			return false, herr
		}
		reg, err = client.Registration.RegisterWithExternalAccountBinding(ctx, registration.RegisterEABOptions{
			TermsOfServiceAgreed: true, Kid: strings.TrimSpace(eab.Kid), HmacEncoded: hmac})
	} else {
		reg, err = client.Registration.Register(ctx, registration.RegisterOptions{TermsOfServiceAgreed: true})
	}
	if err != nil {
		return false, fmt.Errorf("register ACME account: %w", err)
	}
	user.reg = reg
	if b, err := marshalRegistration(reg); err == nil {
		_ = os.WriteFile(filepath.Join(accDir, "registration.json"), b, 0o600)
	}
	return true, nil
}

// CheckAccount proves a provider's CA details work without issuing anything: it reaches the CA's
// directory and creates the account (with the EAB credentials, if any), or confirms it exists. The
// account would be created at the first issuance anyway.
func (i *Issuer) CheckAccount(ctx context.Context, r Request) (string, error) {
	issueMu.Lock()
	defer issueMu.Unlock()
	client, user, accDir, err := i.setup(ctx, r)
	if err != nil {
		return "", err
	}
	created, err := register(ctx, client, user, accDir, r.EAB)
	if err != nil {
		return "", err
	}
	if created {
		return "account created at " + directoryURL(r.directory()), nil
	}
	return "account already set up at " + directoryURL(r.directory()), nil
}

func (i *Issuer) issueACME(ctx context.Context, r Request) (*plugin.Bundle, error) {
	if r.Persist != nil {
		b, err := i.obtainPersist(ctx, r)
		if err == nil {
			return b, nil
		}
		if r.Solver == nil || ctx.Err() != nil || errors.Is(err, errCancelled) {
			return nil, err
		}
		if _, none := r.Solver.(NoChallenge); none {
			return nil, err
		}
		// The provider also has DNS credentials, so a record that is not there is not the end of it
		if r.Log != nil {
			fmt.Fprintf(r.Log, "%s [CERTSMITH] dns-persist-01 did not work (%v): falling back to DNS-01 with this provider's DNS credentials\n",
				time.Now().Format("2006/01/02 15:04:05"), err)
		}
		if r.OnFallback != nil {
			r.OnFallback(err)
		}
	}
	return i.obtainDNS01(ctx, r)
}

// obtainDNS01 validates names with DNS-01: it works for plain host names and wildcards alike, and
// needs nothing from this server but outbound access. CertSmith is not a web server.
func (i *Issuer) obtainDNS01(ctx context.Context, r Request) (*plugin.Bundle, error) {
	client, user, accDir, err := i.setup(ctx, r)
	if err != nil {
		return nil, err
	}
	opts := []dns01.ChallengeOption{waitHook(ctx, r.Log, r.SettleFor)}
	// lego reads the resolvers to check propagation through from its default DNS client. Issuances run
	// one at a time (issueMu), so setting it per run is safe, and an empty list means the system's own.
	dnsOpts := dns01.NewOptions()
	dnsOpts.RecursiveNameservers = r.Settings.DNSResolvers
	dns01.SetDefaultClient(dns01.NewClient(dnsOpts))
	if err := client.Challenge.SetDNS01Provider(r.Solver, opts...); err != nil {
		return nil, err
	}
	if _, err := register(ctx, client, user, accDir, r.EAB); err != nil {
		return nil, err
	}
	return obtain(ctx, client, r)
}

// obtain asks the CA for the certificate with whichever solver the client was given, and returns it
// in the form CertSmith stores.
func obtain(ctx context.Context, client *lego.Client, r Request) (*plugin.Bundle, error) {
	res, err := client.Certificate.Obtain(ctx, certificate.ObtainRequest{
		Domains: r.Domains, KeyType: keyType(r.KeyType), Bundle: true,
		// lego v5 asks for a certificate without a common name unless told otherwise; v4 always
		// included the first name, and devices list certificates by it, so keep that
		EnableCommonName: true,
	})
	if err != nil {
		return nil, err
	}
	key, err := legacyKeyPEM(res.PrivateKey)
	if err != nil {
		return nil, err
	}
	return BundleFromPEM(r.Name, r.Domains, res.Certificate, key)
}

// legacyKeyPEM writes a private key in the PEM forms CertSmith has always stored and the device
// plug-ins read: PKCS#1 for RSA and SEC 1 for ECDSA. lego v5 returns PKCS#8 ("PRIVATE KEY") instead.
func legacyKeyPEM(in []byte) ([]byte, error) {
	blk, _ := pem.Decode(in)
	if blk == nil {
		return nil, errors.New("the CA library returned no private key")
	}
	if blk.Type != "PRIVATE KEY" {
		return in, nil // already PKCS#1 or SEC 1
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("read the private key: %w", err)
	}
	switch p := k.(type) {
	case *rsa.PrivateKey:
		return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(p)}), nil
	case *ecdsa.PrivateKey:
		der, err := x509.MarshalECPrivateKey(p)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
	}
	return nil, errors.New("the CA library returned a private key of a type CertSmith does not support")
}

// ---- built-in test CA ----------------------------------------------------

func (i *Issuer) testCA() (*x509.Certificate, crypto.Signer, []byte, error) {
	dir := filepath.Join(i.DataDir, "selfsigned-ca")
	certPath, keyPath := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key")
	if cb, err := os.ReadFile(certPath); err == nil {
		kb, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, nil, nil, err
		}
		cblk, _ := pem.Decode(cb)
		kblk, _ := pem.Decode(kb)
		if cblk == nil || kblk == nil {
			return nil, nil, nil, errors.New("corrupt test CA")
		}
		c, err := x509.ParseCertificate(cblk.Bytes)
		if err != nil {
			return nil, nil, nil, err
		}
		k, err := x509.ParseECPrivateKey(kblk.Bytes)
		if err != nil {
			return nil, nil, nil, err
		}
		return c, k, cb, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, nil, nil, err
	}
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber:          randSerial(),
		Subject:               pkix.Name{CommonName: "CertSmith Test CA (not trusted)", Organization: []string{"CertSmith"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		return nil, nil, nil, err
	}
	c, _ := x509.ParseCertificate(der)
	cpem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	kder, _ := x509.MarshalECPrivateKey(k)
	if err := os.WriteFile(certPath, cpem, 0o644); err != nil {
		return nil, nil, nil, err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o600); err != nil {
		return nil, nil, nil, err
	}
	return c, k, cpem, nil
}

func randSerial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	return n.Add(n, big.NewInt(1))
}

func (i *Issuer) issueSelfSigned(r Request) (*plugin.Bundle, error) {
	ca, caKey, caPEM, err := i.testCA()
	if err != nil {
		return nil, err
	}
	var (
		leafKey crypto.Signer
		keyDER  []byte
		keyType string
	)
	switch r.KeyType {
	case "ec256", "ec384":
		curve := elliptic.P256()
		if r.KeyType == "ec384" {
			curve = elliptic.P384()
		}
		k, _ := ecdsa.GenerateKey(curve, rand.Reader)
		leafKey, keyType = k, "EC PRIVATE KEY"
		keyDER, _ = x509.MarshalECPrivateKey(k)
	default:
		bits := map[string]int{"rsa3072": 3072, "rsa4096": 4096}[r.KeyType]
		if bits == 0 {
			bits = 2048
		}
		k, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, err
		}
		leafKey, keyType = k, "RSA PRIVATE KEY"
		keyDER = x509.MarshalPKCS1PrivateKey(k)
	}
	tpl := &x509.Certificate{
		SerialNumber: randSerial(),
		Subject:      pkix.Name{CommonName: r.Domains[0]},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().AddDate(0, 0, 90),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, d := range r.Domains {
		if ip := net.ParseIP(d); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, d)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, leafKey.Public(), caKey)
	if err != nil {
		return nil, err
	}
	full := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), caPEM...)
	return BundleFromPEM(r.Name, r.Domains, full, pem.EncodeToMemory(&pem.Block{Type: keyType, Bytes: keyDER}))
}
