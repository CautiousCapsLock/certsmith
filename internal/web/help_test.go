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

func TestTheHeaderHasTheReadmeButtonAndTheCertificatesPageAnExplainedCheckEndpointsButton(t *testing.T) {
	ts, _ := newTestServer(t)
	get := func(path string) string {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}
	page := get("/")
	if !strings.Contains(page, `id="readme-btn"`) {
		t.Error("no Readme button in the header")
	}
	if strings.Contains(page, `id="probe-btn"`) {
		t.Error("Check endpoints belongs on the Certificates page, not in the header")
	}
	m := regexp.MustCompile(`id: 'probe-btn',[^}]*?title: '([^']+)'`).FindStringSubmatch(get("/app.js"))
	// short enough to read at a glance, and it says what is checked and that nothing changes
	if m == nil || len(m[1]) < 40 || len(m[1]) > 160 || !strings.Contains(m[1], "Changes nothing") || !strings.Contains(m[1], "certificate") {
		t.Errorf("the Check endpoints tooltip must explain what it does, briefly: %v", m)
	}
	// Tab goes username, password, repeat, OK: the Show button must not be a tab stop
	if !regexp.MustCompile(`class: 'reveal'[^}]*tabindex: '-1'`).MatchString(get("/app.js")) {
		t.Error("the Show button on password fields must be skipped by the Tab key")
	}
	// Import is offered next to Let's Encrypt and EAB in the Add provider dialog, and opens the import dialog
	if !regexp.MustCompile(`value: 'import' \}, 'Import an existing certificate`).MatchString(get("/app.js")) {
		t.Error("the Add provider dialog must offer Import an existing certificate beside Let's Encrypt and EAB")
	}
	// importing lives on the providers page only: no import button on the Certificates page
	if regexp.MustCompile(`onclick: \(\) => importForm\(null\)`).MatchString(get("/app.js")) || strings.Contains(get("/app.js"), "'Import certificate' }, 'Import certificate'") {
		t.Error("the Certificates page must not have its own Import certificate button")
	}
	// the row buttons of the providers tables sit against the right-hand edge
	if !regexp.MustCompile(`table\.list td\.act \{[^}]*text-align: right`).MatchString(get("/style.css")) ||
		!regexp.MustCompile(`h\('td', \{ class: 'act' \}, h\('button', \{ class: 'btn small ghost', onclick: \(\) => providerForm\(p\)`).MatchString(get("/app.js")) {
		t.Error("the Edit buttons of the providers tables must be right-aligned in an 'act' cell")
	}
	// the theme: chosen on the Settings page, applied before the page draws, and the CSS honours it
	if !strings.Contains(get("/"), `src="theme.js"`) || !strings.Contains(get("/theme.js"), "certsmith.theme") ||
		!strings.Contains(get("/style.css"), `:root[data-theme="light"]`) || !strings.Contains(get("/style.css"), `:root[data-theme="dark"]`) {
		t.Error("the colour theme must be applied from theme.js and honoured by the stylesheet")
	}
	for _, choice := range []string{"radio('light', 'Light')", "radio('dark', 'Dark')", "radio('system', 'Follow system')"} {
		if !strings.Contains(get("/app.js"), choice) {
			t.Errorf("Settings must offer the theme choice %s", choice)
		}
	}
	// the private key can be downloaded for a manual import, behind the user's own password
	for _, want := range []string{"function exportForm(", "'/export'", "Your password, to confirm", "Certificate and key downloaded"} {
		if !strings.Contains(get("/app.js"), want) {
			t.Errorf("the certificate download dialog is incomplete: missing %q", want)
		}
	}
	// a FortiGate's ZTNA servers are discovered, chosen, and SSL VPN is switched off where it is gone
	for _, want := range []string{"function ztnaPanel(", "Look for ZTNA servers", "'/api/discover-target'", "SSL VPN was removed in FortiOS 7.6", "pf.afterTest()", "class: 'testblock'"} {
		if !strings.Contains(get("/app.js"), want) {
			t.Errorf("the ZTNA panel is incomplete: missing %q", want)
		}
	}
	// the test button sits inline with the token, and the sections of a target are separated by rules
	for _, want := range []string{"class: 'tokenrow'", "'sectionrule'"} {
		if !strings.Contains(get("/app.js"), want) {
			t.Errorf("the target dialog layout is incomplete: missing %q", want)
		}
	}
	// the test block is closed by a rule, between the credentials and the choices
	if !regexp.MustCompile(`\.testblock \{[^}]*border-bottom`).MatchString(get("/style.css")) {
		t.Error("the Test connection block must end with a rule")
	}
	// the ZTNA panel leaves room below it, so its button does not touch the next field
	if css := get("/style.css"); !regexp.MustCompile(`\.ztnapanel \{[^}]*margin:`).MatchString(css) ||
		regexp.MustCompile(`\.ztnapanel \{[^}]*border-bottom`).MatchString(css) {
		t.Error("the ZTNA panel needs space beneath it and no rule of its own: Verify addresses draws the one rule")
	}
	// the ZTNA panel sits under the function tick boxes, above Verify addresses
	if !strings.Contains(get("/app.js"), "(form.by.ipsec_phase1 || form.by.uses || form.by.fos_version || form.by.ztna).wrap") {
		t.Error("the ZTNA panel must be placed between the tick boxes and Verify addresses")
	}
	// a certificate that only needs putting on a device is "Action needed", not an error
	for _, want := range []string{"function targetState(", "'Action needed'", "needs a deployment or a manual import"} {
		if !strings.Contains(get("/app.js"), want) {
			t.Errorf("a target that needs a deployment must be reported as action needed: missing %q", want)
		}
	}
	// the columns of a target row line up whatever number of buttons a row has: the last track is fixed
	if !regexp.MustCompile(`\.trow \{[^}]*minmax\(0, 2fr\) \d+px;`).MatchString(get("/style.css")) {
		t.Error("the buttons column of a target row must have a fixed width so rows align")
	}
	// a device installed by hand that serves an older certificate is not "serving a different cert" in red
	if !strings.Contains(get("/app.js"), "'not the current certificate'") {
		t.Error("a manually installed device with an older certificate must say so in words, not as a fault")
	}
	// a device that is installed by hand says so, and has no Deploy button
	for _, want := range []string{"const isManual =", "import needed", "isManual(t.kind)"} {
		if !strings.Contains(get("/app.js"), want) {
			t.Errorf("the page must handle manually installed targets: missing %q", want)
		}
	}
	// an unreachable endpoint is explained in words, with the exact error kept underneath
	for _, want := range []string{"function describeProbeError(", "No answer: the connection timed out", "the device refused the connection", "function deploymentNotes("} {
		if !strings.Contains(strings.ToLower(get("/app.js")), strings.ToLower(want)) {
			t.Errorf("the page must explain a failed endpoint check in words: missing %q", want)
		}
	}
	if !regexp.MustCompile(`section\('Imported certificates'`).MatchString(get("/app.js")) {
		t.Error("the providers page must list imported certificates in their own section")
	}
}
