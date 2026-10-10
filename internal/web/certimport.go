package web

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CautiousCapsLock/certsmith/internal/acme"
	"github.com/CautiousCapsLock/certsmith/internal/certimport"
	"github.com/CautiousCapsLock/certsmith/internal/model"
	"github.com/CautiousCapsLock/certsmith/internal/notify"
	"github.com/CautiousCapsLock/certsmith/internal/store"
)

// importIn is an uploaded certificate. The files are read in the browser: a PKCS#12 file travels as
// base64, PEM files as text. Nothing about it is written to a log.
type importIn struct {
	Name     string `json:"name"`
	P12      string `json:"p12"`
	Password string `json:"password"`
	CertPEM  string `json:"cert_pem"`
	KeyPEM   string `json:"key_pem"`
	ChainPEM string `json:"chain_pem"`
}

func (in importIn) input() (certimport.Input, error) {
	out := certimport.Input{Password: in.Password, CertPEM: []byte(in.CertPEM), KeyPEM: []byte(in.KeyPEM), ChainPEM: []byte(in.ChainPEM)}
	if p := strings.TrimSpace(in.P12); p != "" {
		raw, err := base64.StdEncoding.DecodeString(p)
		if err != nil {
			return out, errors.New("the PKCS#12 file did not arrive intact; choose it again")
		}
		out.P12 = raw
	}
	return out, nil
}

func (s *Server) parseImport(w http.ResponseWriter, r *http.Request) (*certimport.Result, importIn, bool) {
	var in importIn
	if !decode(w, r, &in) {
		return nil, in, false
	}
	input, err := in.input()
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return nil, in, false
	}
	res, err := certimport.Parse(input, time.Now())
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return nil, in, false
	}
	return res, in, true
}

// importCheck reads an uploaded certificate and says what it is and what is doubtful about it. It stores
// nothing, so the person can look before committing.
func (s *Server) importCheck(w http.ResponseWriter, r *http.Request) {
	res, _, ok := s.parseImport(w, r)
	if !ok {
		return
	}
	writeJSON(w, map[string]any{"summary": res.Summary})
}

// importCert adds an uploaded certificate. It is then a certificate like any other for targets, live
// checks and alerts, except that it is never issued or renewed: a new one is uploaded instead.
func (s *Server) importCert(w http.ResponseWriter, r *http.Request) {
	res, in, ok := s.parseImport(w, r)
	if !ok {
		return
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		fail(w, http.StatusBadRequest, "name is required")
		return
	}
	id := store.NewID()
	if err := acme.Save(s.DataDir, id, res.Bundle); err != nil {
		fail(w, http.StatusInternalServerError, "could not store the certificate: "+err.Error())
		return
	}
	now := time.Now()
	err := s.St.Update(func(db *model.DB) error {
		db.Certificates = append(db.Certificates, model.Certificate{
			ID: id, Name: name, Domains: res.Domains, IssuedDomains: res.Domains, KeyType: res.KeyType,
			Enabled: true, Source: model.SourceImport, ImportedAt: now,
			Serial: res.Bundle.Serial, Issuer: res.Issuer, NotBefore: res.Bundle.NotBefore, NotAfter: res.Bundle.NotAfter,
		})
		return nil
	})
	if err != nil {
		_ = os.RemoveAll(filepath.Join(s.DataDir, "certs", id))
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.afterImport(name, "imported", res, now)
	writeJSON(w, map[string]any{"ok": true, "id": id, "summary": res.Summary})
}

// replaceCert swaps the certificate of an imported entry for a newly uploaded one. Targets that were
// deployed to follow it the same way they follow a renewal.
func (s *Server) replaceCert(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var existing *model.Certificate
	s.St.View(func(db *model.DB) {
		for i := range db.Certificates {
			if db.Certificates[i].ID == id {
				c := db.Certificates[i]
				existing = &c
			}
		}
	})
	switch {
	case existing == nil:
		fail(w, http.StatusNotFound, "certificate not found")
		return
	case existing.Source != model.SourceImport:
		fail(w, http.StatusConflict, "this certificate is issued by CertSmith, so it is renewed there; only an imported certificate is replaced by uploading")
		return
	}
	res, _, ok := s.parseImport(w, r)
	if !ok {
		return
	}
	if err := acme.Save(s.DataDir, id, res.Bundle); err != nil {
		fail(w, http.StatusInternalServerError, "could not store the certificate: "+err.Error())
		return
	}
	now := time.Now()
	_ = s.St.Update(func(db *model.DB) error {
		for i := range db.Certificates {
			if c := &db.Certificates[i]; c.ID == id {
				c.Domains, c.IssuedDomains, c.KeyType = res.Domains, res.Domains, res.KeyType
				c.Serial, c.Issuer, c.NotBefore, c.NotAfter = res.Bundle.Serial, res.Issuer, res.Bundle.NotBefore, res.Bundle.NotAfter
				c.ImportedAt, c.LastError = now, ""
			}
		}
		return nil
	})
	s.afterImport(existing.Name, "replaced", res, now)
	writeJSON(w, map[string]any{"ok": true, "id": id, "summary": res.Summary})
}

func (s *Server) afterImport(name, verb string, res *certimport.Result, now time.Time) {
	short := res.Bundle.Serial
	if len(short) > 8 {
		short = short[:8]
	}
	s.St.AddEvent("info", name, fmt.Sprintf("%s certificate %s (expires %s)", verb, short, res.Bundle.NotAfter.Format("2006-01-02")))
	s.notifyAdmin(notify.CertIssued, "Certificate "+verb+": "+name,
		fmt.Sprintf("%s was %s. It covers %s, is issued by %s and is valid until %s.", name, verb,
			strings.Join(res.Domains, ", "), res.Issuer, res.Bundle.NotAfter.Format("2 Jan 2006")))
	_ = now
	s.Eng.Kick() // targets that were deployed to catch up promptly
}
