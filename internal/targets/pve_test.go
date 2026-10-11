package targets

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProxmoxFieldsExplainTheNodeNameAndThePermission(t *testing.T) {
	d := pveTarget{}.Descriptor()
	by := map[string]int{}
	for i, f := range d.Fields {
		by[f.Key] = i
	}
	node := d.Fields[by["node"]]
	if !strings.Contains(node.Help, "Datacenter") || !strings.Contains(node.Help, "hostname") {
		t.Errorf("node name help must say where to find the name: %q", node.Help)
	}
	tok := d.Fields[by["token"]]
	if !strings.Contains(tok.Help, "Sys.Modify") {
		t.Errorf("token help must name the privilege: %q", tok.Help)
	}
	steps := strings.Join(tok.Steps, "\n")
	for _, want := range []string{
		"API Tokens", "API Token Permission", "/nodes/", "Privilege Separation",
		"Administrator", "PVEAdmin", // the role to use, and the look-alike that does not work
		"Sys.Modify", "CertSmith", // the optional hardening role
	} {
		if !strings.Contains(steps, want) {
			t.Errorf("the token steps must mention %q", want)
		}
	}
	if tok.StepsTitle == "" {
		t.Error("the how-to needs a title to open it by")
	}
}

func TestProxmoxTestAndDeployUseTheNodeAndTheToken(t *testing.T) {
	var posted string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "PVEAPIToken=root@pam!cs=secret" {
			t.Errorf("Authorization = %q", got)
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/version":
			_, _ = w.Write([]byte(`{"data":{"version":"8.4.1"}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api2/json/nodes/pve1/certificates/custom":
			_ = r.ParseForm()
			posted = r.PostForm.Get("force") + r.PostForm.Get("restart")
			if r.PostForm.Get("certificates") == "" || r.PostForm.Get("key") == "" {
				t.Errorf("the chain and key must both be sent: %v", r.PostForm)
			}
			_, _ = w.Write([]byte(`{"data":null}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	cfg := map[string]string{
		"host": strings.TrimPrefix(srv.URL, "https://"), "node": "pve1",
		"token": "root@pam!cs=secret", "insecure": "true",
	}
	msg, err := pveTarget{}.Test(context.Background(), cfg)
	if err != nil || msg != "Proxmox VE 8.4.1" {
		t.Fatalf("Test = %q, %v", msg, err)
	}
	msg, err = pveTarget{}.Deploy(context.Background(), cfg, testBundle(t))
	if err != nil || !strings.Contains(msg, "node pve1") || posted != "11" {
		t.Fatalf("Deploy = %q, %v (force+restart = %q)", msg, err, posted)
	}
}
