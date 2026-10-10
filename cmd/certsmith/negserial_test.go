package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

// negativeSerialCert builds a self-signed certificate like the factory ones on FortiManager and
// FortiAnalyzer: the serial number's top bit is set and not padded, so it reads as negative.
func negativeSerialCert(t *testing.T) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial := new(big.Int).SetBytes([]byte{0x7f, 1, 2, 3, 4, 5, 6, 7}) // 8 bytes, top bit clear
	tpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "FMG-VM64"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(1, 0, 0),
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	// 02 08 7f ... -> 02 08 ff ...: the same length, but now a negative INTEGER
	want := []byte{0x02, 0x08, 0x7f, 1, 2, 3, 4, 5, 6, 7}
	i := bytes.Index(der, want)
	if i < 0 {
		t.Fatal("serial not found in the certificate")
	}
	der[i+2] = 0xff
	return der, key
}

func TestAFactoryCertificateWithANegativeSerialCanBeParsed(t *testing.T) {
	der, _ := negativeSerialCert(t)
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("a certificate with a negative serial must be accepted: %v", err)
	}
	if c.SerialNumber.Sign() >= 0 {
		t.Fatalf("test certificate is not negative: %v", c.SerialNumber)
	}
}

// The failure happened inside the TLS handshake, whatever the verification settings.
func TestATLSClientCanConnectToADeviceWithANegativeSerialCertificate(t *testing.T) {
	der, key := negativeSerialCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _ = c.(*tls.Conn).Handshake() }()
		}
	}()
	pinned := false
	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		InsecureSkipVerify: true, // trust is decided by the pin below, as CertSmith does for a device it was told to trust
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			pinned = bytes.Equal(raw[0], der)
			return nil
		},
	})
	if err != nil {
		t.Fatalf("handshake failed: %v", err)
	}
	conn.Close()
	if !pinned {
		t.Fatal("did not see the device's certificate")
	}
}
