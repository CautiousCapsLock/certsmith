package targets

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/CautiousCapsLock/certsmith/internal/model"
	"github.com/CautiousCapsLock/certsmith/internal/plugin"
)

// docMatches reports whether a recorded call is covered by the plugin's documentation:
// same method, and the path equal once <placeholders> match any one segment.
func docMatches(docs []plugin.CallDoc, op string, c model.APICall) bool {
	path := c.Path
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	for _, d := range docs {
		if d.Op != op || !strings.EqualFold(d.Method, c.Method) {
			continue
		}
		dp := d.Path
		if i := strings.IndexByte(dp, '?'); i >= 0 {
			dp = dp[:i]
		}
		re := regexp.MustCompile("^" + regexp.MustCompile(`<[^>]*>`).ReplaceAllString(regexp.QuoteMeta(dp), "[^/]+") + "$")
		if re.MatchString(path) {
			return true
		}
	}
	return false
}

// The documentation is only worth having if it is true: everything the FortiGate plugin really
// sends, in a deployment that exercises every step, must be described.
func TestEveryFortiGateCallIsDocumented(t *testing.T) {
	f := newFakeFGT(t)
	b, _ := realisticBundle(t)
	f.certs["certsmith-20200101-aaaa"] = 0 // pruned
	cfg := capCfg(f, "admin-gui,ssl-vpn")
	cfg["cert_prefix"] = "certsmith"
	docs := fortiGate{}.Descriptor().Calls

	tr := plugin.NewTrace("test")
	if _, err := (fortiGate{}).Test(plugin.WithTrace(context.Background(), tr), cfg); err != nil {
		t.Fatal(err)
	}
	dt := plugin.NewTrace("deploy")
	if _, err := (fortiGate{}).Deploy(plugin.WithTrace(context.Background(), dt), cfg, b); err != nil {
		t.Fatal(err)
	}
	for op, calls := range map[string][]model.APICall{"test": tr.Calls(), "deploy": dt.Calls()} {
		if len(calls) < 3 {
			t.Fatalf("%s recorded only %d calls", op, len(calls))
		}
		for _, c := range calls {
			if !docMatches(docs, op, c) {
				t.Errorf("%s call %s %s is not documented", op, c.Method, c.Path)
			}
		}
	}
}

func TestTheDocumentedCallsAreActuallyMade(t *testing.T) {
	f := newFakeFGT(t)
	b, _ := realisticBundle(t)
	f.certs["certsmith-20200101-aaaa"] = 0
	cfg := capCfg(f, "admin-gui,ssl-vpn")
	cfg["cert_prefix"] = "certsmith"
	tr := plugin.NewTrace("deploy")
	if _, err := (fortiGate{}).Deploy(plugin.WithTrace(context.Background(), tr), cfg, b); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"POST /api/v2/monitor/vpn-certificate/local/import",
		"POST /api/v2/monitor/vpn-certificate/ca/import",
		"PUT /api/v2/cmdb/system/global",
		"PUT /api/v2/cmdb/vpn.ssl/settings",
		"DELETE /api/v2/cmdb/vpn.certificate/local/certsmith-20200101-aaaa",
	} {
		found := false
		for _, c := range tr.Calls() {
			if c.Method+" "+strings.SplitN(c.Path, "?", 2)[0] == want {
				found = true
			}
		}
		if !found {
			t.Errorf("expected %s in the trace", want)
		}
	}
}

func TestATraceShowsTheStatusOfFailedCallsAndNeverASecret(t *testing.T) {
	f := newFakeFGT(t)
	cfg := capCfg(f, "admin-gui")
	cfg["token"] = "wrong"
	tr := plugin.NewTrace("test")
	if _, err := (fortiGate{}).Test(plugin.WithTrace(context.Background(), tr), cfg); err == nil {
		t.Fatal("expected failure")
	}
	calls := tr.Calls()
	if len(calls) == 0 || calls[0].Status != http.StatusUnauthorized || calls[0].Op != "test" {
		t.Fatalf("calls = %+v", calls)
	}
	for _, c := range calls {
		all := c.Host + c.Path + c.Detail + c.Error
		if strings.Contains(all, "wrong") {
			t.Fatalf("token leaked into the trace: %+v", c)
		}
	}
}

func TestTransportErrorsAreRecordedWithoutTheURL(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	addr := strings.TrimPrefix(srv.URL, "https://")
	srv.Close() // nothing listening any more
	tr := plugin.NewTrace("test")
	cfg := map[string]string{"host": addr, "token": "tok-secret", "insecure": "true", "uses": "admin-gui"}
	if _, err := (fortiGate{}).Test(plugin.WithTrace(context.Background(), tr), cfg); err == nil {
		t.Fatal("expected failure")
	}
	calls := tr.Calls()
	if len(calls) == 0 || calls[0].Error == "" || calls[0].Status != 0 {
		t.Fatalf("calls = %+v", calls)
	}
	if strings.Contains(calls[0].Error, "https://") || strings.Contains(calls[0].Error, "tok-secret") {
		t.Fatalf("error carries the URL: %q", calls[0].Error)
	}
}

func TestWebhookURLsAreNotRecordedBecauseTheyMayBeSecrets(t *testing.T) {
	var got string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = r.URL.String() }))
	defer srv.Close()
	b, _ := realisticBundle(t)
	tr := plugin.NewTrace("deploy")
	cfg := map[string]string{"url": srv.URL + "/hooks/T0K3N/abc?key=hunter2", "insecure": "true"}
	if _, err := (webhookTarget{}).Deploy(plugin.WithTrace(context.Background(), tr), cfg, b); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "T0K3N") {
		t.Fatalf("the webhook was not called with its full URL: %q", got)
	}
	calls := tr.Calls()
	if len(calls) != 1 || calls[0].Method != "POST" || calls[0].Status != 200 {
		t.Fatalf("calls = %+v", calls)
	}
	if strings.Contains(calls[0].Path, "T0K3N") || strings.Contains(calls[0].Path, "hunter2") {
		t.Fatalf("secret URL recorded: %q", calls[0].Path)
	}
}

func TestSecretQueryValuesAreDroppedButTheNamesStay(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	hc, err := httpClient(strings.TrimPrefix(srv.URL, "https://"), map[string]string{"insecure": "true"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	tr := plugin.NewTrace("test")
	ctx := plugin.WithTrace(context.Background(), tr)
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+"/x?vdom=root&access_token=abc123&API-Key=zzz", nil)
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	p := tr.Calls()[0].Path
	if strings.Contains(p, "abc123") || strings.Contains(p, "zzz") || !strings.Contains(p, "vdom=root") || !strings.Contains(p, "access_token=") {
		t.Fatalf("path = %q", p)
	}
}

// FortiManager sends everything to /jsonrpc, so the trace records what each request asked for.
func TestFortiManagerCallsAreRecordedByWhatTheyAsk(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"result":[{"status":{"code":0,"message":"OK"},"data":{"Hostname":"fmg","Version":"v7.6","Platform Type":"FMG-VM"}}]}`))
	}))
	defer srv.Close()
	cfg := map[string]string{"host": strings.TrimPrefix(srv.URL, "https://"), "token": "tok", "insecure": "true"}
	tr := plugin.NewTrace("test")
	if _, err := (fortiMgr{kind: "fortimanager"}).Test(plugin.WithTrace(context.Background(), tr), cfg); err != nil {
		t.Fatal(err)
	}
	b, _ := realisticBundle(t)
	dt := plugin.NewTrace("deploy")
	if _, err := (fortiMgr{kind: "fortimanager"}).Deploy(plugin.WithTrace(context.Background(), dt), cfg, b); err != nil {
		t.Fatal(err)
	}
	docs := (fortiMgr{kind: "fortimanager"}).Descriptor().Calls
	for op, calls := range map[string][]model.APICall{"test": tr.Calls(), "deploy": dt.Calls()} {
		if len(calls) == 0 {
			t.Fatalf("%s: nothing recorded", op)
		}
		for _, c := range calls {
			if c.Path != "/jsonrpc" || c.Detail == "" {
				t.Fatalf("call = %+v", c)
			}
			method, path, _ := strings.Cut(c.Detail, " ")
			covered := false
			for _, d := range docs {
				if d.Op == op && d.Method == method {
					covered = true
				}
			}
			if !covered {
				t.Errorf("%s: %s %s is not documented", op, method, path)
			}
		}
	}
	if got := tr.Calls()[0].Detail; got != "get /sys/status" {
		t.Fatalf("detail = %q", got)
	}
}

// fakeFAZ follows the JSON-RPC rules that matter: "set" and "update" need an existing object,
// "add" creates one in a table, and asking for a missing object answers code -3 with HTTP 200.
type fakeFAZ struct {
	certs   map[string]map[string]any
	global  map[string]any // the admin settings object
	bindURL string         // an extra URL answered like the admin settings (for tests of custom paths)
	methods []string
	cas     []map[string]any // the CA store
	failCA  bool
}

func (f *fakeFAZ) serve(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Method string `json:"method"`
		Params []struct {
			URL  string         `json:"url"`
			Data map[string]any `json:"data"`
		} `json:"params"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	p := req.Params[0]
	f.methods = append(f.methods, req.Method+" "+p.URL)
	reply := func(code int, msg string, data any) {
		_ = json.NewEncoder(w).Encode(map[string]any{"result": []any{map[string]any{"status": map[string]any{"code": code, "message": msg}, "url": p.URL, "data": data}}})
	}
	const table = "/cli/global/system/certificate/local"
	switch {
	case p.URL == "/sys/status":
		reply(0, "OK", map[string]any{"Hostname": "faz", "Version": "v7.6.0", "Platform Type": "FAZVM64"})
	case p.URL == table && req.Method == "get":
		var rows []any
		for _, c := range f.certs {
			rows = append(rows, c)
		}
		reply(0, "OK", rows)
	case p.URL == table && req.Method == "add":
		name, _ := p.Data["name"].(string)
		if _, ok := f.certs[name]; ok {
			reply(-2, "Object already exists", nil)
			return
		}
		f.certs[name] = p.Data
		reply(0, "OK", map[string]any{"name": name})
	case p.URL == "/cli/global/system/certificate/ca":
		switch {
		case f.failCA && req.Method == "add":
			reply(-9, "Invalid value", nil)
		case req.Method == "get":
			reply(0, "OK", f.cas)
		case req.Method == "add":
			// stored the way the real device does: a list holding the PEM inside quote marks
			row := map[string]any{}
			for k, v := range p.Data {
				row[k] = v
			}
			if text, ok := p.Data["ca"].(string); ok {
				row["ca"] = []any{`"` + text + `"`}
			}
			f.cas = append(f.cas, row)
			reply(0, "OK", map[string]any{"name": p.Data["name"]})
		}
	case p.URL == table: // set/update on the table itself: not an object, FortiAnalyzer refuses
		reply(-3, "Object does not exist", nil)
	case strings.HasPrefix(p.URL, table+"/"):
		name := strings.TrimPrefix(p.URL, table+"/")
		if _, ok := f.certs[name]; !ok {
			reply(-3, "Object does not exist", nil)
			return
		}
		switch req.Method {
		case "get":
			reply(0, "OK", f.certs[name])
		case "update", "set":
			f.certs[name] = p.Data
			reply(0, "OK", nil)
		case "delete":
			delete(f.certs, name)
			reply(0, "OK", nil)
		}
	case p.URL == "/cli/global/system/admin/setting" || p.URL == f.bindURL:
		if req.Method == "set" || req.Method == "update" {
			for k, v := range p.Data {
				f.global[k] = v
			}
		}
		reply(0, "OK", f.global)
	default:
		reply(-6, "Invalid url", nil)
	}
}

func fazDeploy(t *testing.T, f *fakeFAZ) (string, error) {
	srv := httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	b, _ := realisticBundle(t)
	cfg := map[string]string{"host": strings.TrimPrefix(srv.URL, "https://"), "token": "tok", "insecure": "true", "keep_old": "1"}
	return (fortiMgr{kind: "fortianalyzer"}).Deploy(context.Background(), cfg, b)
}

// FortiAnalyzer answered "set" on a certificate that did not exist yet with code -3
// ("Object does not exist"): a new certificate has to be created with "add".
func TestFortiAnalyzerCreatesTheCertificateWithAddNotSet(t *testing.T) {
	f := &fakeFAZ{certs: map[string]map[string]any{}, global: map[string]any{"admin_server_cert": "server.crt"}}
	if _, err := fazDeploy(t, f); err != nil {
		t.Fatalf("%v (calls: %v)", err, f.methods)
	}
	if len(f.certs) != 1 {
		t.Fatalf("certificate not created: %v", f.methods)
	}
	for name := range f.certs {
		if f.global["admin_server_cert"] != name {
			t.Fatalf("not bound: %v", f.global)
		}
	}
	if f.certs[func() string {
		for n := range f.certs {
			return n
		}
		return ""
	}()]["private-key"] == nil {
		t.Fatal("the private key was not sent")
	}
}

func TestFortiAnalyzerOverwritesACertificateLeftByAnInterruptedDeployment(t *testing.T) {
	b, _ := realisticBundle(t)
	f := &fakeFAZ{certs: map[string]map[string]any{certName("certsmith", b, 35): {"name": "stale"}}, global: map[string]any{}}
	srv := httptest.NewTLSServer(http.HandlerFunc(f.serve))
	defer srv.Close()
	cfg := map[string]string{"host": strings.TrimPrefix(srv.URL, "https://"), "token": "tok", "insecure": "true"}
	if _, err := (fortiMgr{kind: "fortianalyzer"}).Deploy(context.Background(), cfg, b); err != nil {
		t.Fatalf("%v (calls: %v)", err, f.methods)
	}
	sawUpdate := false
	for _, m := range f.methods {
		if strings.HasPrefix(m, "update ") {
			sawUpdate = true
		}
		if m == "add /cli/global/system/certificate/local" {
			t.Fatalf("tried to create a certificate that already exists: %v", f.methods)
		}
	}
	if !sawUpdate || f.certs[certName("certsmith", b, 35)]["name"] == "stale" {
		t.Fatalf("not overwritten: %v", f.methods)
	}
}

func TestFortiAnalyzerKeepsOnlyTheConfiguredNumberOfOldCertificates(t *testing.T) {
	f := &fakeFAZ{certs: map[string]map[string]any{
		"certsmith-20200101-aaaa": {"name": "certsmith-20200101-aaaa"},
		"certsmith-20200202-bbbb": {"name": "certsmith-20200202-bbbb"},
		"certsmith-20200303-cccc": {"name": "certsmith-20200303-cccc"},
		"unrelated":               {"name": "unrelated"},
	}, global: map[string]any{}}
	if _, err := fazDeploy(t, f); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.certs["unrelated"]; !ok {
		t.Fatal("a certificate that is not CertSmith's was deleted")
	}
	if len(f.certs) != 1+1+1 { // new one + one kept old + unrelated
		t.Fatalf("certs left: %v", f.certs)
	}
}

func TestAFazTargetSavedWithTheOldCertificatePathStillWorks(t *testing.T) {
	f := &fakeFAZ{certs: map[string]map[string]any{}, global: map[string]any{}}
	srv := httptest.NewTLSServer(http.HandlerFunc(f.serve))
	defer srv.Close()
	b, _ := realisticBundle(t)
	cfg := map[string]string{"host": strings.TrimPrefix(srv.URL, "https://"), "token": "tok", "insecure": "true",
		"cert_path": "/cli/global/certificate/local"} // what 0.8.0 and 0.8.1 stored by default: never valid
	if _, err := (fortiMgr{kind: "fortianalyzer"}).Deploy(context.Background(), cfg, b); err != nil {
		t.Fatalf("%v (calls: %v)", err, f.methods)
	}
	if len(f.certs) != 1 {
		t.Fatalf("not uploaded: %v", f.methods)
	}
	if got := (fortiMgr{kind: "fortianalyzer"}).Descriptor().Fields; true {
		for _, fl := range got {
			if fl.Key == "cert_path" && fl.Default != "/cli/global/system/certificate/local" {
				t.Fatalf("default = %q", fl.Default)
			}
		}
	}
}

// The device's real answer is what explains a failure, so the trace keeps it: FortiAnalyzer
// says "code -3 ..." inside an HTTP 200.
func TestTheTraceKeepsTheAnswerInsideAnHTTP200AndMarksItFailed(t *testing.T) {
	f := &fakeFAZ{certs: map[string]map[string]any{}, global: map[string]any{}}
	srv := httptest.NewTLSServer(http.HandlerFunc(f.serve))
	defer srv.Close()
	b, _ := realisticBundle(t)
	cfg := map[string]string{"host": strings.TrimPrefix(srv.URL, "https://"), "token": "tok", "insecure": "true",
		"cert_path": "/cli/global/nonsense/local"} // the fake answers -6 for this
	tr := plugin.NewTrace("deploy")
	if _, err := (fortiMgr{kind: "fortianalyzer"}).Deploy(plugin.WithTrace(context.Background(), tr), cfg, b); err == nil {
		t.Fatal("expected failure")
	}
	calls := tr.Calls()
	last := calls[len(calls)-1]
	if last.Status != 200 || !last.Failed || !strings.Contains(last.Answer, "code -6") {
		t.Fatalf("last call = %+v", last)
	}

	// the normal "not there yet" answer of the first look is not shown as a failure
	f2 := &fakeFAZ{certs: map[string]map[string]any{}, global: map[string]any{}}
	srv2 := httptest.NewTLSServer(http.HandlerFunc(f2.serve))
	defer srv2.Close()
	tr2 := plugin.NewTrace("deploy")
	cfg2 := map[string]string{"host": strings.TrimPrefix(srv2.URL, "https://"), "token": "tok", "insecure": "true"}
	if _, err := (fortiMgr{kind: "fortianalyzer"}).Deploy(plugin.WithTrace(context.Background(), tr2), cfg2, b); err != nil {
		t.Fatal(err)
	}
	var first model.APICall
	for _, c := range tr2.Calls() {
		if strings.Contains(c.Detail, "certificate/local/") && c.Detail[:3] == "get" {
			first = c
			break
		}
	}
	if first.Detail == "" || first.Failed || !strings.Contains(first.Answer, "not there yet") {
		t.Fatalf("existence check = %+v", first)
	}
}

func fazWith(t *testing.T, f *fakeFAZ, extra map[string]string) (fortiMgr, map[string]string) {
	srv := httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	cfg := map[string]string{"host": strings.TrimPrefix(srv.URL, "https://"), "token": "tok", "insecure": "true"}
	for k, v := range extra {
		cfg[k] = v
	}
	return fortiMgr{kind: "fortianalyzer"}, cfg
}

// 7.6.7: the web admin certificate is admin_server_cert on system/admin/setting. Earlier versions
// of CertSmith used a hyphenated name on system/global, which does not exist.
func TestTheWebAdminCertificateIsChosenOnSystemAdminSetting(t *testing.T) {
	f := &fakeFAZ{certs: map[string]map[string]any{}, global: map[string]any{"admin_server_cert": "server.crt", "https_port": 443}}
	p, cfg := fazWith(t, f, map[string]string{"bind_path": "/cli/global/system/global", "bind_field": "admin-server-cert"}) // old stored defaults
	b, _ := realisticBundle(t)
	if _, err := p.Deploy(context.Background(), cfg, b); err != nil {
		t.Fatalf("%v (%v)", err, f.methods)
	}
	if f.global["admin_server_cert"] != certName("certsmith", b, 35) || f.global["https_port"] != 443 {
		t.Fatalf("settings = %v", f.global)
	}
	for _, m := range f.methods {
		if strings.Contains(m, "/system/global") {
			t.Fatalf("still touched system/global: %v", f.methods)
		}
	}
}

func TestTheOtherSpellingOfTheSettingIsUsedWhenThatIsWhatTheDeviceHas(t *testing.T) {
	f := &fakeFAZ{certs: map[string]map[string]any{}, global: map[string]any{"admin-server-cert": "server.crt"}}
	p, cfg := fazWith(t, f, nil)
	b, _ := realisticBundle(t)
	if _, err := p.Deploy(context.Background(), cfg, b); err != nil {
		t.Fatalf("%v (%v)", err, f.methods)
	}
	if f.global["admin-server-cert"] != certName("certsmith", b, 35) {
		t.Fatalf("settings = %v", f.global)
	}
	if _, wrong := f.global["admin_server_cert"]; wrong {
		t.Fatalf("wrote the spelling the device does not have: %v", f.global)
	}
}

// A wrong settings path must stop the deployment before anything is uploaded.
func TestNothingIsUploadedWhenTheAdminSettingsCannotBeRead(t *testing.T) {
	f := &fakeFAZ{certs: map[string]map[string]any{}, global: map[string]any{}}
	p, cfg := fazWith(t, f, map[string]string{"bind_path": "/cli/global/nonsense"})
	b, _ := realisticBundle(t)
	if _, err := p.Deploy(context.Background(), cfg, b); err == nil {
		t.Fatal("expected failure")
	}
	if len(f.certs) != 0 {
		t.Fatalf("a certificate was uploaded anyway: %v", f.methods)
	}
}

func TestTestShowsWhichCertificateTheDeviceUsesNow(t *testing.T) {
	f := &fakeFAZ{certs: map[string]map[string]any{}, global: map[string]any{"admin_server_cert": "server.crt"}}
	p, cfg := fazWith(t, f, nil)
	msg, err := p.Test(context.Background(), cfg)
	if err != nil || !strings.Contains(msg, "server.crt") || !strings.Contains(msg, "admin_server_cert") {
		t.Fatalf("msg=%q err=%v", msg, err)
	}
	p, cfg = fazWith(t, f, map[string]string{"bind_path": "/cli/global/nonsense"})
	if _, err := p.Test(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "admin settings") {
		t.Fatalf("a wrong settings path must fail the test: %v", err)
	}
}

func TestFortiAnalyzerGetsTheIssuingCAInstalledSoTheFullChainIsSent(t *testing.T) {
	f := &fakeFAZ{certs: map[string]map[string]any{}, global: map[string]any{"admin_server_cert": "server.crt"}}
	p, cfg := fazWith(t, f, nil)
	b, interPEM := realisticBundle(t)
	msg, err := p.Deploy(context.Background(), cfg, b)
	if err != nil {
		t.Fatalf("%v (%v)", err, f.methods)
	}
	if !strings.Contains(msg, "installed 1 issuing CA") {
		t.Fatalf("msg = %q", msg)
	}
	if len(f.cas) != 1 {
		t.Fatalf("CA store = %v (roots must not be installed)", f.cas)
	}
	got := chainCerts([]byte(strings.ReplaceAll(f.cas[0]["ca"].([]any)[0].(string), `"`, "")))
	want := chainCerts(interPEM)
	if len(got) != 1 || !got[0].Equal(want[0]) {
		t.Fatalf("installed the wrong certificate: %v", f.cas[0])
	}
	if n := f.cas[0]["name"].(string); !strings.HasPrefix(n, "certsmith-ca-") || strings.ContainsAny(n, " ,;") {
		t.Fatalf("name = %q", n)
	}
	// it is in place before the web service is switched (the switch restarts it)
	caAt, setAt := -1, -1
	for i, m := range f.methods {
		if m == "add /cli/global/system/certificate/ca" {
			caAt = i
		}
		if m == "set /cli/global/system/admin/setting" {
			setAt = i
		}
	}
	if caAt < 0 || setAt < 0 || caAt > setAt {
		t.Fatalf("order wrong (ca %d, switch %d): %v", caAt, setAt, f.methods)
	}

	// a second deployment of the same certificate does not install it again
	if msg2, err := p.Deploy(context.Background(), cfg, b); err != nil || !strings.Contains(msg2, "already installed") || len(f.cas) != 1 {
		t.Fatalf("second deploy: %q %v cas=%d", msg2, err, len(f.cas))
	}
}

func TestAFailedCAInstallDoesNotFailTheFortiAnalyzerDeployment(t *testing.T) {
	f := &fakeFAZ{certs: map[string]map[string]any{}, global: map[string]any{}, failCA: true}
	p, cfg := fazWith(t, f, nil)
	b, _ := realisticBundle(t)
	msg, err := p.Deploy(context.Background(), cfg, b)
	if err != nil || !strings.Contains(msg, "could not install the issuing CA") {
		t.Fatalf("msg=%q err=%v", msg, err)
	}
	if f.global["admin_server_cert"] != certName("certsmith", b, 35) {
		t.Fatal("the certificate must still be switched on")
	}
}

func TestInstallingTheCAOnFortiAnalyzerCanBeSwitchedOff(t *testing.T) {
	f := &fakeFAZ{certs: map[string]map[string]any{}, global: map[string]any{}}
	p, cfg := fazWith(t, f, map[string]string{"install_chain": "false"})
	b, _ := realisticBundle(t)
	if _, err := p.Deploy(context.Background(), cfg, b); err != nil {
		t.Fatal(err)
	}
	for _, m := range f.methods {
		if strings.Contains(m, "/certificate/ca") {
			t.Fatalf("touched the CA store: %v", f.methods)
		}
	}
}

// The documented sequence must be the real one: every call a run makes has to be found in the
// plugin's documentation, in the documented order (conditional calls may simply not occur).
func inDocumentedOrder(t *testing.T, docs []plugin.CallDoc, op string, calls []model.APICall) {
	t.Helper()
	norm := func(c model.APICall) (method, path string) {
		method, path = c.Method, c.Path
		if c.Detail != "" { // JSON-RPC: the method and URL are in the body
			method, path, _ = strings.Cut(c.Detail, " ")
		}
		if i := strings.IndexByte(path, '?'); i >= 0 {
			path = path[:i]
		}
		return
	}
	i := 0
	for _, c := range calls {
		method, path := norm(c)
		found := false
		for ; i < len(docs); i++ {
			d := docs[i]
			if d.Op != op || !strings.EqualFold(d.Method, method) {
				continue
			}
			dp := d.Path
			if j := strings.IndexByte(dp, '?'); j >= 0 {
				dp = dp[:j]
			}
			re := regexp.MustCompile("^" + regexp.MustCompile(`<[^>]*>`).ReplaceAllString(regexp.QuoteMeta(dp), "[^/]+") + "$")
			if re.MatchString(path) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("%s: %s %s is not documented at or after the position of the previous call", op, method, path)
		}
	}
}

func TestTheDocumentedOrderOfFortiManagerCallsIsTheRealOrder(t *testing.T) {
	b, _ := realisticBundle(t)
	old := map[string]map[string]any{}
	for _, n := range []string{"certsmith-20200101-aaaa", "certsmith-20200202-bbbb", "certsmith-20200303-cccc"} {
		old[n] = map[string]any{"name": n}
	}
	f := &fakeFAZ{certs: old, global: map[string]any{"admin_server_cert": "server.crt"}}
	p, cfg := fazWith(t, f, map[string]string{"keep_old": "1"})
	docs := p.Descriptor().Calls
	tt := plugin.NewTrace("test")
	if _, err := p.Test(plugin.WithTrace(context.Background(), tt), cfg); err != nil {
		t.Fatal(err)
	}
	inDocumentedOrder(t, docs, "test", tt.Calls())
	dt := plugin.NewTrace("deploy")
	if _, err := p.Deploy(plugin.WithTrace(context.Background(), dt), cfg, b); err != nil {
		t.Fatal(err)
	}
	var sawDelete, sawCA bool
	for _, c := range dt.Calls() {
		sawDelete = sawDelete || strings.HasPrefix(c.Detail, "delete ")
		sawCA = sawCA || c.Detail == "add /cli/global/system/certificate/ca"
	}
	if !sawDelete || !sawCA {
		t.Fatalf("the run did not exercise pruning and the CA install: %v", f.methods)
	}
	inDocumentedOrder(t, docs, "deploy", dt.Calls())
}

func TestTheDocumentedOrderOfFortiGateCallsIsTheRealOrder(t *testing.T) {
	f := newFakeFGT(t)
	b, _ := realisticBundle(t)
	f.certs["certsmith-20200101-aaaa"] = 0
	cfg := capCfg(f, "admin-gui,ssl-vpn")
	cfg["cert_prefix"] = "certsmith"
	docs := fortiGate{}.Descriptor().Calls
	tt := plugin.NewTrace("test")
	if _, err := (fortiGate{}).Test(plugin.WithTrace(context.Background(), tt), cfg); err != nil {
		t.Fatal(err)
	}
	inDocumentedOrder(t, docs, "test", tt.Calls())
	dt := plugin.NewTrace("deploy")
	if _, err := (fortiGate{}).Deploy(plugin.WithTrace(context.Background(), dt), cfg, b); err != nil {
		t.Fatal(err)
	}
	inDocumentedOrder(t, docs, "deploy", dt.Calls())
}

// A redeploy must recognise the CAs it installed before, even though the device stores them as a
// quoted list, and must not add the same CA again under a new name.
func TestARedeployDoesNotAddTheSameCAAgainOnFortiManager(t *testing.T) {
	f := &fakeFAZ{certs: map[string]map[string]any{}, global: map[string]any{}}
	p, cfg := fazWith(t, f, nil)
	b, _ := realisticBundle(t)
	for i := 0; i < 3; i++ {
		if _, err := p.Deploy(context.Background(), cfg, b); err != nil {
			t.Fatalf("deploy %d: %v (%v)", i+1, err, f.methods)
		}
	}
	if len(f.cas) != 1 {
		names := []any{}
		for _, c := range f.cas {
			names = append(names, c["name"])
		}
		t.Fatalf("after three deployments the CA store has %d entries: %v", len(f.cas), names)
	}
}
