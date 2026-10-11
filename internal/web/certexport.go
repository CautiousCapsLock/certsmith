package web

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/CautiousCapsLock/certsmith/internal/acme"
	"github.com/CautiousCapsLock/certsmith/internal/model"
)

// exportIn asks for a certificate and its private key as a file, for a device CertSmith cannot deploy
// to. It is a POST with the person's own password, so a signed-in browser alone cannot take keys.
type exportIn struct {
	Format   string `json:"format"`   // p12 | pem
	Password string `json:"password"` // protects the PKCS#12 file
	Older    bool   `json:"older"`    // 3DES/SHA-1 instead of AES-256, for older consoles
	Confirm  string `json:"confirm"`  // the signed-in user's own password
}

var unsafeFileChars = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func exportName(name string) string {
	n := strings.Trim(unsafeFileChars.ReplaceAllString(name, "-"), "-.")
	if n == "" {
		n = "certificate"
	}
	return n
}

// exportCert returns the certificate with its private key as a PKCS#12 file or a zip of PEM files.
// Every download is recorded in the audit log (what, by whom, from where) and never the password.
func (s *Server) exportCert(w http.ResponseWriter, r *http.Request) {
	var in exportIn
	if !decode(w, r, &in) {
		return
	}
	me, ok := s.confirmSelf(w, r, in.Confirm)
	if !ok {
		return
	}
	var c *model.Certificate
	s.St.View(func(db *model.DB) {
		for i := range db.Certificates {
			if db.Certificates[i].ID == r.PathValue("id") {
				cp := db.Certificates[i]
				c = &cp
			}
		}
	})
	switch {
	case c == nil:
		fail(w, http.StatusNotFound, "certificate not found")
		return
	case c.Serial == "":
		fail(w, http.StatusConflict, "no certificate has been issued for this entry yet")
		return
	}
	if in.Format != "p12" && in.Format != "pem" {
		fail(w, http.StatusBadRequest, "choose PKCS#12 or PEM files")
		return
	}
	if in.Format == "p12" && utf8.RuneCountInString(in.Password) < 8 {
		fail(w, http.StatusBadRequest, "choose a password of at least 8 characters to protect the file")
		return
	}
	b, err := acme.Load(s.DataDir, c.ID, c.Name, c.Domains)
	if err != nil {
		fail(w, http.StatusInternalServerError, "could not read the stored certificate: "+err.Error())
		return
	}
	var data []byte
	var file, ctype, what string
	if in.Format == "p12" {
		data, err = acme.ExportPKCS12(b, in.Password, in.Older)
		file, ctype, what = exportName(c.Name)+".p12", "application/x-pkcs12", "PKCS#12 file"
		if in.Older {
			what += " (3DES, for older systems)"
		}
	} else {
		data, err = acme.ExportPEMZip(b)
		file, ctype, what = exportName(c.Name)+"-pem.zip", "application/zip", "PEM files (zip)"
	}
	if err != nil {
		fail(w, http.StatusInternalServerError, "could not build the file: "+err.Error())
		return
	}
	s.audit(r, "cert.export", c.Name, what+", serial "+short8(c.Serial))
	s.St.AddEvent("warn", c.Name, fmt.Sprintf("certificate and private key downloaded by %s as a %s", me.Name, what))
	h := w.Header()
	h.Set("Content-Type", ctype)
	h.Set("Content-Disposition", `attachment; filename="`+file+`"`)
	h.Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
}

func short8(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}
