package plugin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"time"
)

// Endpointer is implemented by targets that talk to a device over TLS, so the
// server can show what certificate the device presents when it is not trusted.
type Endpointer interface {
	APIEndpoint(cfg map[string]string) string // host:port of the API
}

// CertInfo describes a certificate a device presented.
type CertInfo struct {
	Endpoint    string    `json:"endpoint"`
	Fingerprint string    `json:"fingerprint"` // lowercase hex SHA-256 of the leaf
	Subject     string    `json:"subject"`
	Issuer      string    `json:"issuer"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	SelfSigned  bool      `json:"self_signed"`
	Expired     bool      `json:"expired"`
	Names       []string  `json:"names"`
}

// IsTLSTrustError reports whether err is a certificate verification failure
// (unknown authority, wrong name, expired...) rather than a network or login problem.
func IsTLSTrustError(err error) bool {
	var ua x509.UnknownAuthorityError
	var he x509.HostnameError
	var ci x509.CertificateInvalidError
	var cv *tls.CertificateVerificationError
	return errors.As(err, &ua) || errors.As(err, &he) || errors.As(err, &ci) || errors.As(err, &cv)
}

// FetchCert connects without verifying anything, to show what is being presented.
// The result is for the user to review: nothing is trusted until they confirm.
func FetchCert(ctx context.Context, endpoint string) (*CertInfo, error) {
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, err
	}
	sni := host
	if net.ParseIP(host) != nil {
		sni = ""
	}
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 10 * time.Second},
		Config: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10, ServerName: sni}}
	conn, err := d.DialContext(ctx, "tcp", endpoint)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	certs := conn.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, errors.New("the device presented no certificate")
	}
	leaf := certs[0]
	sum := sha256.Sum256(leaf.Raw)
	names := append([]string{}, leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		names = append(names, ip.String())
	}
	return &CertInfo{
		Endpoint:    endpoint,
		Fingerprint: hex.EncodeToString(sum[:]),
		Subject:     dnString(leaf.Subject.CommonName, leaf.Subject.Organization),
		Issuer:      dnString(leaf.Issuer.CommonName, leaf.Issuer.Organization),
		NotBefore:   leaf.NotBefore, NotAfter: leaf.NotAfter,
		SelfSigned: bytes.Equal(leaf.RawIssuer, leaf.RawSubject),
		Expired:    time.Now().After(leaf.NotAfter),
		Names:      names,
	}, nil
}

func dnString(cn string, org []string) string {
	switch {
	case cn != "" && len(org) > 0:
		return cn + " (" + org[0] + ")"
	case cn != "":
		return cn
	case len(org) > 0:
		return org[0]
	}
	return "(unnamed)"
}
