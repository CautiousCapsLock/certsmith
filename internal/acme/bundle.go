// Package acme issues certificates (Let's Encrypt via lego, or a built-in test CA)
// and stores the resulting bundles on disk.
package acme

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CautiousCapsLock/certsmith/internal/plugin"
)

// BundleFromPEM builds a Bundle from a leaf-first PEM chain and a private key.
func BundleFromPEM(name string, domains []string, fullChain, keyPEM []byte) (*plugin.Bundle, error) {
	var leaf *x509.Certificate
	var leafPEM, chainPEM []byte
	rest := fullChain
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		enc := pem.EncodeToMemory(blk)
		if leaf == nil {
			leaf, leafPEM = c, enc
		} else {
			chainPEM = append(chainPEM, enc...)
		}
	}
	if leaf == nil {
		return nil, errors.New("no certificate in PEM data")
	}
	return &plugin.Bundle{
		Name:      name,
		Domains:   domains,
		Leaf:      leaf,
		CertPEM:   leafPEM,
		ChainPEM:  chainPEM,
		FullChain: append(append([]byte{}, leafPEM...), chainPEM...),
		KeyPEM:    keyPEM,
		Serial:    SerialHex(leaf),
		NotBefore: leaf.NotBefore,
		NotAfter:  leaf.NotAfter,
	}, nil
}

func SerialHex(c *x509.Certificate) string {
	return strings.ToLower(fmt.Sprintf("%x", c.SerialNumber))
}

// Save writes the bundle under <dataDir>/certs/<id>/ with restrictive permissions.
func Save(dataDir, id string, b *plugin.Bundle) error {
	dir := filepath.Join(dataDir, "certs", id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	files := map[string][]byte{
		"cert.pem":      b.CertPEM,
		"chain.pem":     b.ChainPEM,
		"fullchain.pem": b.FullChain,
		"key.pem":       b.KeyPEM,
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name+".tmp"), data, 0o600); err != nil {
			return err
		}
	}
	// fullchain last: a reader that sees the new fullchain also sees the new key.
	for _, name := range []string{"cert.pem", "chain.pem", "key.pem", "fullchain.pem"} {
		if err := os.Rename(filepath.Join(dir, name+".tmp"), filepath.Join(dir, name)); err != nil {
			return err
		}
	}
	return nil
}

func Load(dataDir, id, name string, domains []string) (*plugin.Bundle, error) {
	dir := filepath.Join(dataDir, "certs", id)
	fc, err := os.ReadFile(filepath.Join(dir, "fullchain.pem"))
	if err != nil {
		return nil, err
	}
	key, err := os.ReadFile(filepath.Join(dir, "key.pem"))
	if err != nil {
		return nil, err
	}
	return BundleFromPEM(name, domains, fc, key)
}
