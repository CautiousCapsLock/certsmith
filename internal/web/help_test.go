package web

import (
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"
)

// The Readme is a page of its own with pictures. A moved or misspelt image would only show as a broken
// picture in a pop-up nobody tests, so check every link here.
func TestTheReadmePageAndAllItsImagesAreServed(t *testing.T) {
	ts, _ := newTestServer(t)
	get := func(path string) (int, string, http.Header) {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b), resp.Header
	}
	code, page, _ := get("/help.html")
	if code != 200 || !strings.Contains(page, "<title>CertSmith Readme</title>") {
		t.Fatalf("/help.html: %d", code)
	}
	imgs := regexp.MustCompile(`src="(help/[^"]+)"`).FindAllStringSubmatch(page, -1)
	if len(imgs) < 8 {
		t.Fatalf("the Readme should carry screenshots, found %d", len(imgs))
	}
	for _, m := range imgs {
		code, body, h := get("/" + m[1])
		if code != 200 || len(body) < 2000 || !strings.HasPrefix(h.Get("Content-Type"), "image/") {
			t.Errorf("%s: status %d, %d bytes, type %q", m[1], code, len(body), h.Get("Content-Type"))
		}
	}
	// the anchors in the contents list point at sections that exist
	for _, a := range regexp.MustCompile(`href="#([a-z]+)"`).FindAllStringSubmatch(page, -1) {
		if !strings.Contains(page, `id="`+a[1]+`"`) {
			t.Errorf("contents entry #%s has no section", a[1])
		}
	}
	// none of it needs a session, and nothing in it is a secret
	if m := regexp.MustCompile(`\b(10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)\b`).FindString(page); m != "" {
		t.Errorf("the Readme must not contain a private-range address, found %q", m)
	}
}

func TestTheHeaderHasTheReadmeButtonAndAnExplainedCheckEndpointsButton(t *testing.T) {
	ts, _ := newTestServer(t)
	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	page := string(b)
	if !strings.Contains(page, `id="readme-btn"`) {
		t.Error("no Readme button in the header")
	}
	m := regexp.MustCompile(`id="probe-btn"[^>]*title="([^"]+)"`).FindStringSubmatch(page)
	// short enough to read at a glance, and it says what is checked and that nothing changes
	if m == nil || len(m[1]) < 40 || len(m[1]) > 160 || !strings.Contains(m[1], "Changes nothing") || !strings.Contains(m[1], "certificate") {
		t.Errorf("the Check endpoints tooltip must explain what it does, briefly: %v", m)
	}
}
