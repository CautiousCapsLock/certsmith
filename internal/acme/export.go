package acme

import (
	"archive/zip"
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"github.com/CautiousCapsLock/certsmith/internal/plugin"
)

// ExportPKCS12 packs the certificate, its private key and its CA chain into a PKCS#12 file protected by
// password, for products whose console takes that format. older selects 3DES and SHA-1, which the
// consoles of older products still require; the default is AES-256.
func ExportPKCS12(b *plugin.Bundle, password string, older bool) ([]byte, error) {
	if password == "" {
		return nil, errors.New("a password is required")
	}
	key, err := parsePrivateKey(b.KeyPEM)
	if err != nil {
		return nil, err
	}
	enc := pkcs12.Modern
	if older {
		enc = pkcs12.LegacyDES
	}
	return enc.Encode(key, b.Leaf, caCerts(b.ChainPEM), password)
}

// ExportPEMZip packs the four PEM files CertSmith keeps for a certificate into a zip archive.
func ExportPEMZip(b *plugin.Bundle) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range []struct {
		name string
		data []byte
	}{
		{"cert.pem", b.CertPEM}, {"chain.pem", b.ChainPEM}, {"fullchain.pem", b.FullChain}, {"key.pem", b.KeyPEM},
	} {
		if len(f.data) == 0 {
			continue // no chain for a certificate that has none
		}
		h := &zip.FileHeader{Name: f.name, Method: zip.Deflate}
		h.SetMode(0o600)
		w, err := zw.CreateHeader(h)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(f.data); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func parsePrivateKey(keyPEM []byte) (any, error) {
	blk, _ := pem.Decode(keyPEM)
	if blk == nil {
		return nil, errors.New("the certificate has no private key on file")
	}
	if k, err := x509.ParsePKCS8PrivateKey(blk.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(blk.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParseECPrivateKey(blk.Bytes); err == nil {
		return k, nil
	}
	return nil, fmt.Errorf("unsupported private key format (%s)", blk.Type)
}

func caCerts(chainPEM []byte) []*x509.Certificate {
	var out []*x509.Certificate
	rest := chainPEM
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			return out
		}
		if c, err := x509.ParseCertificate(blk.Bytes); err == nil {
			out = append(out, c)
		}
	}
}
