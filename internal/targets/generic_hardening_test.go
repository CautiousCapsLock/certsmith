package targets

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CautiousCapsLock/certsmith/internal/plugin"
)

// A webhook that answers with a redirect must not be followed: the payload, a private key when it is
// included, would be posted again to a place the configured URL does not name.
func TestWebhookDoesNotFollowRedirects(t *testing.T) {
	hits := 0
	elsewhere := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer elsewhere.Close()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	cfg := map[string]string{"url": srv.URL, "insecure": "true", "include_key": "true"}
	_, err := webhookTarget{}.Deploy(context.Background(), cfg, testBundle(t))
	if err == nil || !strings.Contains(err.Error(), "HTTP 307") {
		t.Fatalf("a redirect answer must be reported as a failure, got %v", err)
	}
	if hits != 0 {
		t.Fatalf("the redirect was followed: %d request(s) reached the other server", hits)
	}
}

func TestWebhookWillNotSendAPrivateKeyOverPlainHTTP(t *testing.T) {
	got := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got++ }))
	defer srv.Close()
	b := testBundle(t)
	_, err := webhookTarget{}.Deploy(context.Background(), map[string]string{"url": srv.URL, "include_key": "true"}, b)
	if err == nil || !strings.Contains(err.Error(), "plain HTTP") || got != 0 {
		t.Fatalf("with the key included, an http:// URL must be refused before anything is sent: err=%v requests=%d", err, got)
	}
	// without the key it is the administrator's choice (an internal endpoint)
	if _, err := (webhookTarget{}).Deploy(context.Background(), map[string]string{"url": srv.URL}, b); err != nil || got != 1 {
		t.Fatalf("http:// without the key must work: err=%v requests=%d", err, got)
	}
}

// A file name planted in a shared directory (a link to somewhere else) is not written through.
func TestFilesTargetDoesNotWriteThroughAPlantedLink(t *testing.T) {
	dir, elsewhere := t.TempDir(), filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(elsewhere, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(dir, ".key.pem.tmp")); err != nil {
		t.Skip("symbolic links are not available here")
	}
	if _, err := (filesTarget{}).Deploy(context.Background(), map[string]string{"dir": dir}, testBundle(t)); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(elsewhere); string(b) != "keep me" {
		t.Fatalf("the planted link was written through: %q", b)
	}
	st, err := os.Stat(filepath.Join(dir, "key.pem"))
	if err != nil || st.Mode().Perm() != 0o640 {
		t.Fatalf("key.pem: %v, mode %v", err, st)
	}
}

// A post-deploy command gets the certificate's location, not CertSmith's master key.
func TestCommandsDoNotReceiveTheMasterKeyOrSeedPassword(t *testing.T) {
	t.Setenv("CERTSMITH_MASTER_KEY", strings.Repeat("ab", 32))
	t.Setenv("CERTSMITH_ADMIN_PASSWORD", "seed-password-for-test")
	env := strings.Join(commandEnv("/srv/certs", "01ab"), "\n")
	for _, secret := range []string{"CERTSMITH_MASTER_KEY", "CERTSMITH_ADMIN_PASSWORD", "seed-password-for-test"} {
		if strings.Contains(env, secret) {
			t.Errorf("the command environment contains %s", secret)
		}
	}
	for _, want := range []string{"CERTSMITH_CERT_DIR=/srv/certs", "CERTSMITH_SERIAL=01ab"} {
		if !strings.Contains(env, want) {
			t.Errorf("the command environment lacks %s", want)
		}
	}
	_ = plugin.GetOptions // the gate itself (CERTSMITH_ALLOW_COMMANDS) is unchanged and tested elsewhere
}
