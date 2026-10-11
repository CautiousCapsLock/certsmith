package web

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

// The release notes ship inside the program and are what the page shows as "this version": every file must
// be named for a version and be written the way people are meant to read it (headings and bullet points).
func TestShippedReleaseNotesAreReadable(t *testing.T) {
	files, err := fs.Glob(staticFS, "static/releases/*.md")
	if err != nil || len(files) == 0 {
		t.Fatalf("no release notes are shipped: %v", err)
	}
	name := regexp.MustCompile(`^static/releases/v\d+\.\d+\.\d+\.md$`)
	for _, f := range files {
		if !name.MatchString(f) {
			t.Errorf("%s: release notes are named vX.Y.Z.md", f)
		}
		b, _ := fs.ReadFile(staticFS, f)
		s := string(b)
		bullets := 0
		for _, l := range strings.Split(s, "\n") {
			if strings.HasPrefix(l, "- ") {
				bullets++
			}
		}
		switch {
		case !strings.Contains(s, "\n## "):
			t.Errorf("%s: needs at least one ## heading", f)
		case bullets < 3:
			t.Errorf("%s: write the changes as bullet points (found %d)", f, bullets)
		}
	}
}

func TestReleaseNotesEndpointNeedsSignInAndIsEmptyWithoutAnUpdate(t *testing.T) {
	srv, _ := newTestServer(t)
	c := setupAndLogin(t, srv)
	if code, _, _ := call(t, newClient(), "GET", srv.URL+"/api/release-notes", nil, false, nil); code != 401 {
		t.Errorf("signed out: %d, want 401", code)
	}
	code, body, _ := call(t, c, "GET", srv.URL+"/api/release-notes", nil, false, nil)
	if code != 200 || !strings.Contains(body, `"upcoming":[]`) {
		t.Errorf("no update known: %d %s", code, body)
	}
}
