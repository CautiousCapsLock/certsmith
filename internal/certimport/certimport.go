// Package certimport reads a certificate that somebody else issued (a PKCS#12 file, or PEM files) and
// turns it into the bundle CertSmith deploys. Nothing here issues or signs anything: it checks that
// what was supplied is usable, orders the chain, and says what is wrong or doubtful in plain words.
package certimport

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"github.com/CautiousCapsLock/certsmith/internal/acme"
	"github.com/CautiousCapsLock/certsmith/internal/plugin"
)

// MaxBytes bounds one uploaded file. A certificate with its chain and key is a few kilobytes.
const MaxBytes = 256 << 10

// Input is what the person supplied: either a PKCS#12 file with its password, or PEM text.
type Input struct {
	P12      []byte
	Password string
	CertPEM  []byte // the certificate, and optionally its chain after it
	KeyPEM   []byte
	ChainPEM []byte // optional extra CA certificates
}

// Summary is what the web interface shows before and after an import.
type Summary struct {
	Names        []string  `json:"names"`
	Subject      string    `json:"subject"`
	Issuer       string    `json:"issuer"`
	Serial       string    `json:"serial"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	KeyType      string    `json:"key_type"`
	ChainLength  int       `json:"chain_length"`  // CA certificates that will be sent with it
	RootSupplied bool      `json:"root_supplied"` // a self-signed root was in the files (it is not sent)
	Warnings     []string  `json:"warnings"`
}

// Result is a validated import.
type Result struct {
	Bundle  *plugin.Bundle
	Domains []string
	KeyType string
	Issuer  string
	Summary Summary
}

// Parse validates the input and builds the bundle. now is the time expiry is judged against.
func Parse(in Input, now time.Time) (*Result, error) {
	for _, b := range [][]byte{in.P12, in.CertPEM, in.KeyPEM, in.ChainPEM} {
		if len(b) > MaxBytes {
			return nil, fmt.Errorf("a file is larger than %d KB; a certificate with its key is only a few KB", MaxBytes>>10)
		}
	}
	var (
		key  crypto.Signer
		pool []*x509.Certificate
		err  error
	)
	switch {
	case len(in.P12) > 0:
		key, pool, err = fromPKCS12(in.P12, in.Password)
	case len(in.CertPEM) > 0:
		key, pool, err = fromPEM(in)
	default:
		return nil, errors.New("choose a PKCS#12 file, or a certificate file and its private key file")
	}
	if err != nil {
		return nil, err
	}

	// The leaf is the certificate the private key belongs to, wherever it sits in the files.
	leaf := certForKey(pool, key)
	if leaf == nil {
		return nil, errors.New("the private key does not belong to any certificate in the files")
	}
	if leaf.IsCA && !hasServerAuth(leaf) {
		return nil, errors.New("this is a CA certificate, not a server certificate; choose the certificate issued for the server")
	}
	if !leaf.NotAfter.After(now) {
		return nil, fmt.Errorf("the certificate expired on %s", leaf.NotAfter.UTC().Format("2 Jan 2006"))
	}

	keyType, err := keyLabel(key)
	if err != nil {
		return nil, err
	}
	keyPEM, err := encodeKey(key)
	if err != nil {
		return nil, err
	}

	chain, rootSupplied, ignored := order(leaf, pool)
	var warnings []string
	selfSigned := bytes.Equal(leaf.RawIssuer, leaf.RawSubject)
	switch {
	case selfSigned:
		warnings = append(warnings, "This is a self-signed certificate: clients must be told to trust it explicitly.")
	case len(chain) == 0 && rootSupplied:
		warnings = append(warnings, "This certificate was issued directly by the root CA supplied with it. The root is not sent: clients must have that root CA installed as trusted.")
	case len(chain) == 0:
		warnings = append(warnings, "No CA certificate that issued this one was supplied, so devices will send the certificate alone and clients that do not already have its issuing CA will report it as untrusted. Supply the chain to avoid that.")
	}
	if ignored > 0 {
		warnings = append(warnings, fmt.Sprintf("%d certificate(s) in the files are not part of this certificate's chain and were ignored.", ignored))
	}
	if left := leaf.NotAfter.Sub(now); left < 30*24*time.Hour {
		warnings = append(warnings, fmt.Sprintf("It expires in %d days.", int(left.Hours()/24)))
	}
	if leaf.NotBefore.After(now) {
		warnings = append(warnings, "It is not valid until "+leaf.NotBefore.UTC().Format("2 Jan 2006 15:04 UTC")+".")
	}
	if len(leaf.ExtKeyUsage) > 0 && !hasServerAuth(leaf) {
		warnings = append(warnings, "It is not marked for server authentication, so browsers may refuse it.")
	}
	switch leaf.SignatureAlgorithm {
	case x509.SHA1WithRSA, x509.ECDSAWithSHA1, x509.MD5WithRSA:
		warnings = append(warnings, "It is signed with a weak algorithm (SHA-1 or MD5); current clients refuse such certificates.")
	}

	domains := names(leaf)
	if len(domains) == 0 {
		return nil, errors.New("the certificate has no host names (no subject alternative names and no common name)")
	}

	var full bytes.Buffer
	full.Write(pemCert(leaf))
	for _, c := range chain {
		full.Write(pemCert(c))
	}
	b, err := acme.BundleFromPEM("", domains, full.Bytes(), keyPEM)
	if err != nil {
		return nil, err
	}

	issuer := leaf.Issuer.CommonName
	if issuer == "" && len(leaf.Issuer.Organization) > 0 {
		issuer = leaf.Issuer.Organization[0]
	}
	subject := leaf.Subject.CommonName
	if subject == "" {
		subject = domains[0]
	}
	return &Result{
		Bundle: b, Domains: domains, KeyType: keyType, Issuer: issuer,
		Summary: Summary{
			Names: domains, Subject: subject, Issuer: issuer, Serial: b.Serial,
			NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter, KeyType: keyType,
			ChainLength: len(chain), RootSupplied: rootSupplied, Warnings: warnings,
		},
	}, nil
}

func fromPKCS12(data []byte, password string) (crypto.Signer, []*x509.Certificate, error) {
	k, leaf, cas, err := pkcs12.DecodeChain(data, password)
	if err != nil {
		if errors.Is(err, pkcs12.ErrIncorrectPassword) {
			return nil, nil, errors.New("the password for the PKCS#12 file is incorrect")
		}
		return nil, nil, fmt.Errorf("that is not a PKCS#12 file CertSmith can read (%v); a PEM certificate and key can be supplied instead", err)
	}
	signer, ok := k.(crypto.Signer)
	if !ok {
		return nil, nil, errors.New("the PKCS#12 file holds a private key of a type CertSmith does not support")
	}
	return signer, append([]*x509.Certificate{leaf}, cas...), nil
}

func fromPEM(in Input) (crypto.Signer, []*x509.Certificate, error) {
	var pool []*x509.Certificate
	for _, blob := range [][]byte{in.CertPEM, in.ChainPEM} {
		certs, err := parseCerts(blob)
		if err != nil {
			return nil, nil, err
		}
		pool = append(pool, certs...)
	}
	if len(pool) == 0 {
		return nil, nil, errors.New("no certificate was found in the certificate file (it must be PEM text starting with -----BEGIN CERTIFICATE-----)")
	}
	if len(bytes.TrimSpace(in.KeyPEM)) == 0 {
		return nil, nil, errors.New("the private key file is needed with a PEM certificate")
	}
	key, err := parseKey(in.KeyPEM)
	if err != nil {
		return nil, nil, err
	}
	return key, pool, nil
}

func parseCerts(blob []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for rest := blob; ; {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			return out, nil
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("a certificate in the files could not be read: %v", err)
		}
		out = append(out, c)
	}
}

func parseKey(blob []byte) (crypto.Signer, error) {
	for rest := blob; ; {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			return nil, errors.New("no private key was found in the key file (PEM text starting with -----BEGIN PRIVATE KEY----- or similar)")
		}
		if !strings.HasSuffix(blk.Type, "PRIVATE KEY") {
			continue
		}
		if blk.Type == "ENCRYPTED PRIVATE KEY" || strings.Contains(blk.Headers["Proc-Type"], "ENCRYPTED") {
			return nil, errors.New("the private key is encrypted with a passphrase; remove the passphrase first (openssl pkey -in key.pem -out key-plain.pem) or supply a PKCS#12 file instead")
		}
		var k any
		var err error
		switch blk.Type {
		case "RSA PRIVATE KEY":
			k, err = x509.ParsePKCS1PrivateKey(blk.Bytes)
		case "EC PRIVATE KEY":
			k, err = x509.ParseECPrivateKey(blk.Bytes)
		default:
			k, err = x509.ParsePKCS8PrivateKey(blk.Bytes)
		}
		if err != nil {
			return nil, fmt.Errorf("the private key could not be read: %v", err)
		}
		s, ok := k.(crypto.Signer)
		if !ok {
			return nil, errors.New("the private key is of a type CertSmith does not support")
		}
		return s, nil
	}
}

func certForKey(pool []*x509.Certificate, key crypto.Signer) *x509.Certificate {
	want, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil
	}
	for _, c := range pool {
		got, err := x509.MarshalPKIXPublicKey(c.PublicKey)
		if err == nil && bytes.Equal(got, want) {
			return c
		}
	}
	return nil
}

// order walks from the leaf to its issuers through the supplied certificates. It returns the CA
// certificates in the order they are sent (the root is not one of them), whether a self-signed root
// was supplied, and how many supplied certificates are not on the path at all.
func order(leaf *x509.Certificate, pool []*x509.Certificate) (chain []*x509.Certificate, rootSupplied bool, ignored int) {
	used := map[*x509.Certificate]bool{leaf: true}
	cur := leaf
	for i := 0; i < 10; i++ {
		var next *x509.Certificate
		for _, c := range pool {
			if used[c] || !bytes.Equal(c.RawSubject, cur.RawIssuer) {
				continue
			}
			if cur.CheckSignatureFrom(c) == nil {
				next = c
				break
			}
		}
		if next == nil {
			break
		}
		used[next] = true
		if bytes.Equal(next.RawIssuer, next.RawSubject) {
			rootSupplied = true
			break
		}
		chain = append(chain, next)
		cur = next
	}
	for _, c := range pool {
		if !used[c] && !sameCert(c, leaf) {
			ignored++
		}
	}
	return chain, rootSupplied, ignored
}

func sameCert(a, b *x509.Certificate) bool { return bytes.Equal(a.Raw, b.Raw) }

func hasServerAuth(c *x509.Certificate) bool {
	for _, u := range c.ExtKeyUsage {
		if u == x509.ExtKeyUsageServerAuth || u == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}

func names(c *x509.Certificate) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, d := range c.DNSNames {
		add(d)
	}
	for _, ip := range c.IPAddresses {
		add(ip.String())
	}
	if len(out) == 0 {
		add(c.Subject.CommonName)
	}
	return out
}

func keyLabel(k crypto.Signer) (string, error) {
	switch p := k.Public().(type) {
	case *rsa.PublicKey:
		bits := p.N.BitLen()
		if bits < 2048 {
			return "", fmt.Errorf("an RSA key of %d bits is too weak to be accepted (2048 or more is required)", bits)
		}
		return fmt.Sprintf("rsa%d", bits), nil
	case *ecdsa.PublicKey:
		switch p.Curve {
		case elliptic.P256():
			return "ec256", nil
		case elliptic.P384():
			return "ec384", nil
		case elliptic.P521():
			return "ec521", nil
		}
	}
	return "", errors.New("the private key is of a type CertSmith does not support (use RSA, or ECDSA on P-256, P-384 or P-521)")
}

// encodeKey writes the key in the PEM forms CertSmith's issued certificates use, which the device
// plug-ins read: PKCS#1 for RSA and SEC 1 for ECDSA.
func encodeKey(k crypto.Signer) ([]byte, error) {
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
	return nil, errors.New("the private key is of a type CertSmith does not support")
}

func pemCert(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}
