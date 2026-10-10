package acme

import (
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
)

// CAPreset is a certificate authority that needs External Account Binding, offered in the provider
// form so that its directory URL does not have to be looked up. The URL is filled in and stays
// editable: some CAs (Sectigo, DigiCert, SSL.com) publish a different directory per product or per
// account, so the one on the CA's own account page is the one to use.
type CAPreset struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	Directory string `json:"directory"`
	Help      string `json:"help"`
	// PreValidated is true for a CA that can validate your domains in your account ahead of time (and
	// so issues for those names without a challenge). A provider at such a CA may have no DNS
	// credentials. Where it is false the CA checks every name with a challenge, so DNS credentials are
	// required. When unsure about a CA, leave it false: credentials that turn out to be unused cost
	// nothing, but missing ones fail the issuance.
	PreValidated bool `json:"prevalidated"`
}

// CustomCA is the preset id for any other CA: the directory URL is typed in.
const CustomCA = "custom"

var CAPresets = []CAPreset{
	{ID: "zerossl", Label: "ZeroSSL", Directory: "https://acme.zerossl.com/v2/DV90",
		Help: "Create an EAB key under Developer in your ZeroSSL dashboard. It gives a Key ID and an HMAC key."},
	{ID: "sectigo", Label: "Sectigo", Directory: "https://acme.sectigo.com/v2/DV", PreValidated: true,
		Help: "The URL depends on the product (DV, OV, EV, InCommon ...). Copy the directory URL, Key ID and HMAC key from the ACME account page in Sectigo Certificate Manager, where domains can also be validated ahead of time."},
	{ID: "google", Label: "Google Trust Services", Directory: "https://dv.acme-v02.api.pki.goog/directory",
		Help: "Create the EAB key with gcloud (publicca external-account-keys create). It gives a Key ID and a base64url HMAC key."},
	{ID: CustomCA, Label: "Another CA (enter the directory URL)", Directory: "", PreValidated: true,
		Help: "Any ACME CA that issues External Account Binding credentials, for example DigiCert or SSL.com. Use the directory URL from its account page."},
}

// NormalizeHMAC accepts an EAB MAC key as a CA shows it: surrounding spaces, padding and the
// standard base64 alphabet are tolerated, and the result is base64url without padding, which is what
// the ACME client wants. It fails for anything that is not base64 at all.
func NormalizeHMAC(s string) (string, error) {
	s = strings.Join(strings.Fields(s), "")
	s = strings.TrimRight(s, "=")
	s = strings.NewReplacer("+", "-", "/", "_").Replace(s)
	if s == "" {
		return "", errors.New("the HMAC key is empty")
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return "", errors.New("the HMAC key is not valid base64: paste it exactly as the CA shows it")
	}
	if len(raw) < 32 { // HS256, which the binding is signed with, needs a key at least as long as its hash
		return "", errors.New("the HMAC key is too short to be a CA's MAC key: copy the whole key")
	}
	return s, nil
}

// ValidDirectory checks a CA directory URL: https, with a host.
func ValidDirectory(s string) error {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return errors.New("the CA directory must be an https:// URL")
	}
	return nil
}

// PreValidates reports whether the CA with this preset id can validate domains in the account ahead of
// time, so that a provider there may do without DNS credentials.
func PreValidates(caID string) bool {
	for _, c := range CAPresets {
		if c.ID == caID {
			return c.PreValidated
		}
	}
	return true // not a known preset: a CA the user typed in, whose behaviour only they know
}

// CALabel is the display name of a CA preset, or the id when it is not one.
func CALabel(caID string) string {
	for _, c := range CAPresets {
		if c.ID == caID {
			return c.Label
		}
	}
	return caID
}
