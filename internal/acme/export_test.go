package acme

import (
	"context"
	"testing"

	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"github.com/CautiousCapsLock/certsmith/internal/model"
)

func TestExportedPKCS12OpensWithBothEncoders(t *testing.T) {
	iss := &Issuer{DataDir: t.TempDir()}
	b, err := iss.Issue(context.Background(), Request{Name: "t", Domains: []string{"a.example.com"}, KeyType: "ec256", Settings: model.Settings{ACMEDirectory: model.DirSelfSigned}})
	if err != nil {
		t.Fatal(err)
	}
	for _, older := range []bool{false, true} {
		p12, err := ExportPKCS12(b, "pass-phrase-1", older)
		if err != nil {
			t.Fatalf("older=%v: %v", older, err)
		}
		_, leaf, cas, err := pkcs12.DecodeChain(p12, "pass-phrase-1")
		if err != nil || SerialHex(leaf) != b.Serial || len(cas) != 1 {
			t.Errorf("older=%v: serial %v, %d CAs, %v", older, leaf != nil, len(cas), err)
		}
	}
	if _, err := ExportPKCS12(b, "", false); err == nil {
		t.Error("an empty password must be refused")
	}
}
