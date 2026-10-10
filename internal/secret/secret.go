// Package secret encrypts credentials at rest with AES-256-GCM.
//
// The key comes from CERTSMITH_MASTER_KEY (64 hex chars) or, failing that, a
// key file generated on first start in the data directory.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const prefix = "enc:v1:"

// Mask is what the API shows in place of a stored secret.
const Mask = "********"

type Box struct{ aead cipher.AEAD }

func Open(dataDir string) (*Box, error) {
	keyHex := strings.TrimSpace(os.Getenv("CERTSMITH_MASTER_KEY"))
	if keyHex == "" {
		path := filepath.Join(dataDir, "master.key")
		b, err := os.ReadFile(path)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			raw := make([]byte, 32)
			if _, err := rand.Read(raw); err != nil {
				return nil, err
			}
			keyHex = hex.EncodeToString(raw)
			if err := os.WriteFile(path, []byte(keyHex+"\n"), 0o600); err != nil {
				return nil, err
			}
		case err != nil:
			return nil, err
		default:
			keyHex = strings.TrimSpace(string(b))
		}
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil || len(key) != 32 {
		return nil, errors.New("master key must be 64 hex characters")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead}, nil
}

func (b *Box) Seal(s string) string {
	if s == "" || strings.HasPrefix(s, prefix) {
		return s
	}
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic(err) // crypto/rand failing is unrecoverable
	}
	return prefix + base64.StdEncoding.EncodeToString(b.aead.Seal(nonce, nonce, []byte(s), nil))
}

func (b *Box) Unseal(s string) (string, error) {
	if !strings.HasPrefix(s, prefix) {
		return s, nil
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, prefix))
	if err != nil {
		return "", err
	}
	if len(raw) < b.aead.NonceSize() {
		return "", errors.New("ciphertext too short")
	}
	pt, err := b.aead.Open(nil, raw[:b.aead.NonceSize()], raw[b.aead.NonceSize():], nil)
	if err != nil {
		return "", fmt.Errorf("decrypt (wrong master key?): %w", err)
	}
	return string(pt), nil
}
