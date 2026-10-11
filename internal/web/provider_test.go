package web

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/CautiousCapsLock/certsmith/internal/model"
)

const goodHMAC = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5YWJjZGVm" // 48 bytes, base64url

func eabBody(over map[string]any) map[string]any {
	b := map[string]any{
		"name": "ZeroSSL", "kind": "cloudflare", "config": map[string]string{"api_token": "cf-secret-token"},
		"authority": "eab", "ca": "zerossl", "eab_kid": "kid-123", "eab_hmac": goodHMAC, "email": "me@example.com",
	}
	for k, v := range over {
		b[k] = v
	}
	return b
}

func providers(t *testing.T, srv *Server) []model.DNSProvider {
	t.Helper()
	return srv.St.Snapshot().DNSProviders
}

func TestAnEABProviderIsSavedWithItsCAAndTheKeySealed(t *testing.T) {
	ts, srv := newTestServer(t)
	c := setupAndLogin(t, ts)
	code, body, _ := call(t, c, "POST", ts.URL+"/api/dns", eabBody(nil), false, nil)
	if code != 200 {
		t.Fatalf("%d %s", code, body)
	}
	ps := providers(t, srv)
	if len(ps) != 1 {
		t.Fatalf("providers = %+v", ps)
	}
	p := ps[0]
	if !p.IsEAB() || p.Directory != "https://acme.zerossl.com/v2/DV90" || p.EABKid != "kid-123" || p.Email != "me@example.com" {
		t.Fatalf("stored provider = %+v (the preset's directory must be filled in)", p)
	}
	if !strings.HasPrefix(p.EABHMAC, "enc:v1:") || strings.Contains(p.EABHMAC, goodHMAC) {
		t.Fatalf("the HMAC key must be stored sealed, got %q", p.EABHMAC)
	}
	if plain, err := srv.Box.Unseal(p.EABHMAC); err != nil || plain != goodHMAC {
		t.Fatalf("unsealed = %q %v", plain, err)
	}

	// the key never leaves the server: the page gets the mask
	_, state, _ := call(t, c, "GET", ts.URL+"/api/state", nil, false, nil)
	if strings.Contains(state, goodHMAC) || strings.Contains(state, "enc:v1:") && strings.Contains(state, p.EABHMAC) {
		t.Fatalf("the HMAC key leaked into /api/state: %s", state)
	}
	var st struct {
		DB struct {
			DNS []model.DNSProvider `json:"dns_providers"`
		} `json:"db"`
	}
	_ = json.Unmarshal([]byte(state), &st)
	if len(st.DB.DNS) != 1 || st.DB.DNS[0].EABHMAC != "********" || st.DB.DNS[0].EABKid != "kid-123" || st.DB.DNS[0].Config["api_token"] != "********" {
		t.Fatalf("state = %+v", st.DB.DNS)
	}
}

func TestEditingAnEABProviderKeepsTheStoredKeyUnlessANewOneIsGiven(t *testing.T) {
	ts, srv := newTestServer(t)
	c := setupAndLogin(t, ts)
	call(t, c, "POST", ts.URL+"/api/dns", eabBody(nil), false, nil)
	id := providers(t, srv)[0].ID
	sealed := providers(t, srv)[0].EABHMAC

	// the page sends the mask back for an unchanged key
	code, body, _ := call(t, c, "PUT", ts.URL+"/api/dns/"+id, eabBody(map[string]any{"name": "ZeroSSL renamed", "eab_hmac": "********", "config": map[string]string{"api_token": "********"}}), false, nil)
	if code != 200 {
		t.Fatalf("%d %s", code, body)
	}
	if p := providers(t, srv)[0]; p.Name != "ZeroSSL renamed" || p.EABHMAC != sealed {
		t.Fatalf("an unchanged key must be kept: %+v", p)
	}
	// a new key replaces it
	newKey := "ZmVkY2JhOTg3NjU0MzIxMGZlZGNiYTk4NzY1NDMyMTBmZWRjYmE5ODc2NTQzMjEw"
	call(t, c, "PUT", ts.URL+"/api/dns/"+id, eabBody(map[string]any{"eab_hmac": newKey, "config": map[string]string{"api_token": "********"}}), false, nil)
	if plain, _ := srv.Box.Unseal(providers(t, srv)[0].EABHMAC); plain != newKey {
		t.Fatalf("the new key was not stored: %q", plain)
	}
}

func TestAnEABProviderIsValidated(t *testing.T) {
	ts, srv := newTestServer(t)
	c := setupAndLogin(t, ts)
	for name, tc := range map[string]struct {
		over map[string]any
		want string
	}{
		"no key id":            {map[string]any{"eab_kid": ""}, "key ID"},
		"no hmac":              {map[string]any{"eab_hmac": ""}, "HMAC"},
		"hmac not base64":      {map[string]any{"eab_hmac": "!!! not base64 !!!"}, "base64"},
		"hmac too short":       {map[string]any{"eab_hmac": "abcd"}, "too short"},
		"custom needs a URL":   {map[string]any{"ca": "custom", "directory": ""}, "directory"},
		"plain http directory": {map[string]any{"ca": "custom", "directory": "http://ca.example/dir"}, "https"},
		"bad email":            {map[string]any{"email": "nobody"}, "email"},
		"unknown authority":    {map[string]any{"authority": "mystery"}, "unknown certificate authority"},
	} {
		code, body, _ := call(t, c, "POST", ts.URL+"/api/dns", eabBody(tc.over), false, nil)
		if code != 400 || !strings.Contains(body, tc.want) {
			t.Errorf("%s: want 400 mentioning %q, got %d %s", name, tc.want, code, body)
		}
	}
	if n := len(providers(t, srv)); n != 0 {
		t.Fatalf("%d invalid providers were stored", n)
	}
	// a custom CA with its own https directory is fine
	if code, body, _ := call(t, c, "POST", ts.URL+"/api/dns", eabBody(map[string]any{"name": "Other", "ca": "custom", "directory": "https://ca.example/acme/directory"}), false, nil); code != 200 {
		t.Fatalf("%d %s", code, body)
	}
	if p := providers(t, srv)[0]; p.Directory != "https://ca.example/acme/directory" {
		t.Fatalf("directory = %q", p.Directory)
	}
}

func TestALetsEncryptProviderCarriesNoCADetails(t *testing.T) {
	ts, srv := newTestServer(t)
	c := setupAndLogin(t, ts)
	// stray CA fields on a Let's Encrypt provider (a form that was switched back) must not be stored
	code, body, _ := call(t, c, "POST", ts.URL+"/api/dns", eabBody(map[string]any{"name": "CF", "authority": "letsencrypt"}), false, nil)
	if code != 200 {
		t.Fatalf("%d %s", code, body)
	}
	p := providers(t, srv)[0]
	if p.IsEAB() || p.Authority != "" || p.Directory != "" || p.EABKid != "" || p.EABHMAC != "" || p.Email != "" || p.CA != "" {
		t.Fatalf("a Let's Encrypt provider stored CA details: %+v", p)
	}
	// and an old-style body with no authority at all is still a Let's Encrypt provider
	code, _, _ = call(t, c, "POST", ts.URL+"/api/dns", map[string]any{"name": "Old", "kind": "cloudflare", "config": map[string]string{"api_token": "x"}}, false, nil)
	if code != 200 || providers(t, srv)[1].IsEAB() {
		t.Fatalf("legacy provider: %d %+v", code, providers(t, srv))
	}
}

func TestTheSchemaOffersTheEABCAs(t *testing.T) {
	ts, _ := newTestServer(t)
	c := setupAndLogin(t, ts)
	_, schema, _ := call(t, c, "GET", ts.URL+"/api/schema", nil, false, nil)
	var s struct {
		CAs []struct{ ID, Label, Directory string } `json:"eab_cas"`
	}
	if err := json.Unmarshal([]byte(schema), &s); err != nil {
		t.Fatal(err)
	}
	ids := map[string]string{}
	for _, c := range s.CAs {
		ids[c.ID] = c.Directory
	}
	if ids["zerossl"] == "" || ids["sectigo"] == "" {
		t.Fatalf("ZeroSSL and Sectigo must be offered: %v", ids)
	}
	if d, ok := ids["custom"]; !ok || d != "" {
		t.Fatalf("a custom entry with no directory must be offered: %v", ids)
	}
}

func TestACertificateCanUseAnEABProviderAndAProviderInUseCannotBeDeleted(t *testing.T) {
	ts, srv := newTestServer(t)
	c := setupAndLogin(t, ts)
	call(t, c, "POST", ts.URL+"/api/dns", eabBody(nil), false, nil)
	id := providers(t, srv)[0].ID
	code, body, _ := call(t, c, "POST", ts.URL+"/api/certs", map[string]any{
		"name": "zs", "domains": []string{"example.com"}, "dns_id": id, "key_type": "ec256", "enabled": false}, false, nil)
	if code != 200 {
		t.Fatalf("%d %s", code, body)
	}
	if code, body, _ := call(t, c, "DELETE", ts.URL+"/api/dns/"+id, nil, false, nil); code != 400 || !strings.Contains(body, "in use") {
		t.Fatalf("deleting a provider that a certificate uses: %d %s", code, body)
	}
}

func TestCheckingAnAccountNeedsValidDetailsAndReportsTheCAsAnswer(t *testing.T) {
	ts, _ := newTestServer(t)
	c := setupAndLogin(t, ts)
	if code, body, _ := call(t, c, "POST", ts.URL+"/api/dns/check-account", eabBody(map[string]any{"eab_kid": ""}), false, nil); code != 400 || !strings.Contains(body, "key ID") {
		t.Fatalf("missing key id: %d %s", code, body)
	}
	// valid details but a CA that is not there: the failure is reported, not hidden
	code, body, _ := call(t, c, "POST", ts.URL+"/api/dns/check-account", eabBody(map[string]any{"ca": "custom", "directory": "https://127.0.0.1:1/directory"}), false, nil)
	if code != 400 || body == "" {
		t.Fatalf("an unreachable CA must fail the check: %d %s", code, body)
	}
}

func noDNS(over map[string]any) map[string]any {
	b := eabBody(map[string]any{"kind": "", "config": nil})
	for k, v := range over {
		b[k] = v
	}
	return b
}

func TestProvidersAtCAsThatPreValidateMayHaveNoDNSCredentialsOthersMayNot(t *testing.T) {
	ts, srv := newTestServer(t)
	c := setupAndLogin(t, ts)
	for name, tc := range map[string]struct {
		body map[string]any
		code int
		want string
	}{
		"sectigo validates in the account": {noDNS(map[string]any{"name": "S", "ca": "sectigo"}), 200, ""},
		"another CA is the user's own":     {noDNS(map[string]any{"name": "C", "ca": "custom", "directory": "https://ca.example/dir"}), 200, ""},
		"zerossl always challenges":        {noDNS(map[string]any{"name": "Z", "ca": "zerossl"}), 400, "ZeroSSL checks every name"},
		"google always challenges":         {noDNS(map[string]any{"name": "G", "ca": "google"}), 400, "Google Trust Services checks every name"},
		"let's encrypt always challenges":  {noDNS(map[string]any{"name": "L", "authority": "letsencrypt"}), 400, "choose a DNS provider"},
	} {
		code, body, _ := call(t, c, "POST", ts.URL+"/api/dns", tc.body, false, nil)
		if code != tc.code || !strings.Contains(body, tc.want) {
			t.Errorf("%s: want %d mentioning %q, got %d %s", name, tc.code, tc.want, code, body)
		}
	}
	ps := providers(t, srv)
	if len(ps) != 2 {
		t.Fatalf("stored %d providers, want the 2 that are allowed: %+v", len(ps), ps)
	}
	for _, p := range ps {
		if p.Kind != "" || len(p.Config) != 0 || !p.IsEAB() {
			t.Fatalf("a provider without DNS credentials must store none: %+v", p)
		}
	}

	// there is nothing to test, and the page is told so
	id := ps[0].ID
	if code, body, _ := call(t, c, "POST", ts.URL+"/api/dns/test", map[string]any{"id": id, "domain": "example.com"}, false, nil); code != 400 || !strings.Contains(body, "no DNS credentials") {
		t.Fatalf("testing DNS on a provider without any: %d %s", code, body)
	}
	// but the CA account can still be checked, and a certificate can use the provider
	if code, body, _ := call(t, c, "POST", ts.URL+"/api/certs", map[string]any{"name": "x", "domains": []string{"example.com"}, "dns_id": id, "key_type": "ec256", "enabled": false}, false, nil); code != 200 {
		t.Fatalf("a certificate on a provider without DNS: %d %s", code, body)
	}
	// and credentials can be added later, on edit
	code, body, _ := call(t, c, "PUT", ts.URL+"/api/dns/"+id, eabBody(map[string]any{"name": "S", "ca": "sectigo", "eab_hmac": "********"}), false, nil)
	if code != 200 || providers(t, srv)[0].Kind != "cloudflare" {
		t.Fatalf("adding DNS credentials to it later: %d %s", code, body)
	}
}

// Checking a CA account never touches DNS, so it must not ask for DNS credentials. The edit dialog
// of a saved provider sends the CA details only (the stored DNS secrets are masked there).
func TestCheckingAnAccountDoesNotAskForDNSCredentials(t *testing.T) {
	ts, _ := newTestServer(t)
	c := setupAndLogin(t, ts)
	// ZeroSSL always challenges, so saving it without DNS credentials is refused...
	if code, body, _ := call(t, c, "POST", ts.URL+"/api/dns", noDNS(map[string]any{"name": "Z", "ca": "zerossl"}), false, nil); code != 400 || !strings.Contains(body, "needs DNS credentials") {
		t.Fatalf("saving without DNS credentials: %d %s", code, body)
	}
	// ...but checking its account with the same body is not: it gets as far as the CA, which is not there
	code, body, _ := call(t, c, "POST", ts.URL+"/api/dns/check-account",
		noDNS(map[string]any{"ca": "custom", "directory": "https://127.0.0.1:1/directory"}), false, nil)
	if code != 400 || strings.Contains(body, "DNS credentials") || body == "" {
		t.Fatalf("an account check must reach the CA and fail there, not on DNS credentials: %d %s", code, body)
	}
	code, body, _ = call(t, c, "POST", ts.URL+"/api/dns/check-account",
		noDNS(map[string]any{"ca": "zerossl", "directory": "https://127.0.0.1:1/directory"}), false, nil)
	if code != 400 || strings.Contains(body, "DNS credentials") {
		t.Fatalf("ZeroSSL account check without DNS credentials: %d %s", code, body)
	}
}
