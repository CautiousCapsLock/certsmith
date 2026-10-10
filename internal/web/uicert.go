package web

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"time"

	"github.com/CautiousCapsLock/certsmith/internal/plugin"
	"github.com/CautiousCapsLock/certsmith/internal/uitls"
)

// bootstrapOrg is what the certificate CertSmith makes for itself on first start carries as its
// organisation, which is how a self-signed certificate of its own is told from one someone supplied.
const bootstrapOrg = "CertSmith (self-signed bootstrap)"

// UICert describes the certificate this web page is serving, for the Settings page.
type UICert struct {
	// TLS is false when CertSmith serves plain HTTP behind a reverse proxy: the proxy owns the certificate.
	TLS         bool      `json:"tls"`
	SelfSigned  bool      `json:"self_signed"`
	Bootstrap   bool      `json:"bootstrap"` // the self-signed certificate CertSmith created itself
	Subject     string    `json:"subject,omitempty"`
	Issuer      string    `json:"issuer,omitempty"`
	Names       []string  `json:"names,omitempty"`
	NotBefore   time.Time `json:"not_before,omitzero"`
	NotAfter    time.Time `json:"not_after,omitzero"`
	Fingerprint string    `json:"fingerprint,omitempty"` // SHA-256 of the certificate, hex
	Error       string    `json:"error,omitempty"`
}

func commonOrOrg(n interface{ String() string }, cn string, org []string) string {
	switch {
	case cn != "":
		return cn
	case len(org) > 0:
		return org[0]
	}
	return n.String()
}

// uiCertInfo reads the certificate file the page is served from.
func uiCertInfo() UICert {
	dir := plugin.GetOptions().UITLSDir
	if dir == "" {
		return UICert{}
	}
	out := UICert{TLS: true}
	b, err := os.ReadFile(filepath.Join(dir, uitls.CertFile))
	if err != nil {
		out.Error = err.Error()
		return out
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		out.Error = "no certificate in " + uitls.CertFile
		return out
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	sum := sha256.Sum256(c.Raw)
	out.Fingerprint = hex.EncodeToString(sum[:])
	out.SelfSigned = bytes.Equal(c.RawIssuer, c.RawSubject)
	for _, o := range c.Subject.Organization {
		if o == bootstrapOrg {
			out.Bootstrap = out.SelfSigned
		}
	}
	out.Subject = commonOrOrg(c.Subject, c.Subject.CommonName, c.Subject.Organization)
	out.Issuer = commonOrOrg(c.Issuer, c.Issuer.CommonName, c.Issuer.Organization)
	out.Names = append(out.Names, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		out.Names = append(out.Names, ip.String())
	}
	out.NotBefore, out.NotAfter = c.NotBefore, c.NotAfter
	return out
}
