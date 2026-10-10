package uitls

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBootstrapAndReload(t *testing.T) {
	dir := t.TempDir()
	l, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	fp1 := l.Fingerprint()
	if fp1 == "" {
		t.Fatal("no fingerprint")
	}
	if st, _ := os.Stat(filepath.Join(dir, KeyFile)); st.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %v", st.Mode().Perm())
	}

	// replacing the files (what a "files" target does) is picked up without a restart
	other := t.TempDir()
	if err := generate(other); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{KeyFile, CertFile} {
		b, _ := os.ReadFile(filepath.Join(other, f))
		_ = os.WriteFile(filepath.Join(dir, f), b, 0o600)
	}
	future := time.Now().Add(time.Minute)
	_ = os.Chtimes(filepath.Join(dir, CertFile), future, future)
	if fp2 := l.Fingerprint(); fp2 == fp1 || fp2 == "" {
		t.Fatal("new certificate not reloaded")
	}

	// a corrupt replacement keeps serving the last good certificate
	good := l.Fingerprint()
	_ = os.WriteFile(filepath.Join(dir, CertFile), []byte("garbage"), 0o600)
	later := future.Add(time.Minute)
	_ = os.Chtimes(filepath.Join(dir, CertFile), later, later)
	if l.Fingerprint() != good {
		t.Fatal("corrupt file must not replace the working certificate")
	}
}
