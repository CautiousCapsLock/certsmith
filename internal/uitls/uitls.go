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

func generate(dir string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	host, _ := os.Hostname()
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host, Organization: []string{"CertSmith (self-signed bootstrap)"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(5, 0, 0),
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
	if err := os.WriteFile(filepath.Join(dir, KeyFile), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, CertFile), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}
