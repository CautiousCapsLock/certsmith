// Package uitls serves the web UI's TLS certificate from files that are
// generated on first start and re-read when they change, so a "files" target
// can later keep the UI certificate renewed without a restart.
package uitls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io/fs"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	CertFile = "fullchain.pem" // same names the "files" target writes
	KeyFile  = "key.pem"
)

// BootstrapOrg is the organisation of the certificate CertSmith makes for itself. It is how that
// certificate is told from one that someone supplied (or that CertSmith issued for this page).
const BootstrapOrg = "CertSmith (self-signed bootstrap)"

// lifetimeYears is how long a bootstrap certificate is valid. It is long because nobody manages it;
// RenewIfDue replaces it before it runs out.
const lifetimeYears = 5

type Loader struct {
	dir string

	mu    sync.Mutex
	cert  *tls.Certificate
	mtime time.Time
}

// New ensures a certificate exists in dir, generating a self-signed one if not.
func New(dir string) (*Loader, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	l := &Loader{dir: dir}
	if _, err := os.Stat(filepath.Join(dir, CertFile)); errors.Is(err, fs.ErrNotExist) {
		if err := generate(dir); err != nil {
			return nil, err
		}
	}
	if _, err := l.GetCertificate(nil); err != nil {
		return nil, err
	}
	return l, nil
}

// GetCertificate returns the current certificate, reloading it if the file changed.
func (l *Loader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	st, err := os.Stat(filepath.Join(l.dir, CertFile))
	if err != nil {
		if l.cert != nil {
			return l.cert, nil // keep serving the last good certificate
		}
		return nil, err
	}
	if l.cert != nil && st.ModTime().Equal(l.mtime) {
		return l.cert, nil
	}
	c, err := tls.LoadX509KeyPair(filepath.Join(l.dir, CertFile), filepath.Join(l.dir, KeyFile))
	if err != nil {
		if l.cert != nil {
			return l.cert, nil // a half-written replacement must not take the UI down
		}
		return nil, err
	}
	l.cert, l.mtime = &c, st.ModTime()
	return l.cert, nil
}

// Fingerprint is the SHA-256 of the current leaf, for pinning in a reverse proxy.
func (l *Loader) Fingerprint() string {
	c, err := l.GetCertificate(nil)
	if err != nil || len(c.Certificate) == 0 {
		return ""
	}
	sum := sha256.Sum256(c.Certificate[0])
	return hex.EncodeToString(sum[:])
}

// generate writes a new self-signed certificate valid for the default lifetime.
func generate(dir string) error {
	return generateUntil(dir, time.Now().AddDate(lifetimeYears, 0, 0))
}

// Regenerate replaces the certificate and key in dir with a new self-signed pair. It does not look at
// what is there: callers must first check IsBootstrap so a certificate someone supplied is never lost.
// A running Loader picks the new pair up on the next connection.
func Regenerate(dir string) error { return generate(dir) }

// IsBootstrap reports whether c is the self-signed certificate CertSmith made for itself.
func IsBootstrap(c *x509.Certificate) bool {
	if c == nil || !bytesEqual(c.RawIssuer, c.RawSubject) {
		return false
	}
	for _, o := range c.Subject.Organization {
		if o == BootstrapOrg {
			return true
		}
	}
	return false
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// RenewIfDue replaces the bootstrap certificate in dir when it expires within the given time (or has
// expired). A certificate that is not CertSmith's own is never touched. It reports whether it renewed.
func RenewIfDue(dir string, within time.Duration, now time.Time) (bool, error) {
	b, err := os.ReadFile(filepath.Join(dir, CertFile))
	if err != nil {
		return false, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return false, errors.New("no certificate in " + CertFile)
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return false, err
	}
	if !IsBootstrap(c) || c.NotAfter.Sub(now) > within {
		return false, nil
	}
	if err := generate(dir); err != nil {
		return false, err
	}
	return true, nil
}

// machineNames are the names this machine can be reached by: its host name and its IPv4 addresses
// (IPv6 addresses are left out: privacy extensions change them daily and would flag a stale
// certificate all the time).
func machineNames() (dns []string, ips []net.IP) {
	if host, err := os.Hostname(); err == nil && host != "" {
		dns = append(dns, host)
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil && !ipn.IP.IsLoopback() && !ipn.IP.IsLinkLocalUnicast() {
				ips = append(ips, ipn.IP)
			}
		}
	}
	return dns, ips
}

// Missing lists the names of this machine that c does not cover: the host name and IPv4 addresses it
// has now but did not have when the certificate was made.
func Missing(c *x509.Certificate) []string {
	dns, ips := machineNames()
	var out []string
	for _, h := range dns {
		if err := c.VerifyHostname(h); err != nil {
			out = append(out, h)
		}
	}
	for _, ip := range ips {
		if err := c.VerifyHostname(ip.String()); err != nil {
			out = append(out, ip.String())
		}
	}
	return out
}

func generateUntil(dir string, notAfter time.Time) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	host, _ := os.Hostname()
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host, Organization: []string{BootstrapOrg}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	if host != "" {
		tpl.DNSNames = append(tpl.DNSNames, host)
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLinkLocalUnicast() {
				tpl.IPAddresses = append(tpl.IPAddresses, ipn.IP)
			}
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	// Both files are written beside their final names and renamed, key first, so a reader never sees a
	// half-written file and the loader (which watches the certificate file) finds the new key waiting.
	keyTmp, certTmp := filepath.Join(dir, KeyFile+".new"), filepath.Join(dir, CertFile+".new")
	if err := os.WriteFile(keyTmp, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(certTmp, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		_ = os.Remove(keyTmp)
		return err
	}
	if err := os.Rename(keyTmp, filepath.Join(dir, KeyFile)); err != nil {
		_ = os.Remove(keyTmp)
		_ = os.Remove(certTmp)
		return err
	}
	return os.Rename(certTmp, filepath.Join(dir, CertFile))
}
