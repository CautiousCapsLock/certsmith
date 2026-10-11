package targets

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/CautiousCapsLock/certsmith/internal/plugin"
)

// ztnaFGT is a FortiGate that also has ZTNA objects: it answers the firewall objects itself and
// everything else (status, certificates, system settings) through the ordinary fake.
type ztnaFGT struct {
	*fakeFGT
	mu      sync.Mutex
	vips    map[string][]string // name -> certificate entries
	vhosts  map[string][]string
	servers bool // 7.6: firewall/access-proxy exists
	puts    []string
	srv     *httptest.Server
}

func newZTNAFGT(t *testing.T, version string) *ztnaFGT {
	z := &ztnaFGT{
		fakeFGT: newFakeFGT(t),
		vips:    map[string][]string{"ztna-vip": {"Fortinet_Factory"}},
		vhosts:  map[string][]string{"portal.example.com": {"Fortinet_Factory"}, "app2.example.com": {"old-cert", "certsmith-wild-20200101-aaaa"}},
		servers: strings.HasPrefix(version, "v7.6"),
	}
	z.fakeFGT.version = version
	z.srv = httptest.NewTLSServer(http.HandlerFunc(z.handle))
	t.Cleanup(z.srv.Close)
	return z
}

func entries(names []string) []map[string]string {
	out := make([]map[string]string, len(names))
	for i, n := range names {
		out[i] = map[string]string{"name": n}
	}
	return out
}

func (z *ztnaFGT) handle(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	reply := func(v any) { _ = json.NewEncoder(w).Encode(map[string]any{"results": v}) }
	const base = "/api/v2/cmdb/firewall/"
	z.mu.Lock()
	defer z.mu.Unlock()
	switch {
	case p == base+"vip" && r.Method == http.MethodGet:
		var res []map[string]any
		for n, c := range z.vips {
			res = append(res, map[string]any{"name": n, "type": "access-proxy", "extip": "203.0.113.10", "extport": "8443", "ssl-certificate": entries(c)})
		}
		reply(res)
	case p == base+"access-proxy-virtual-host" && r.Method == http.MethodGet:
		var res []map[string]any
		for n, c := range z.vhosts {
			res = append(res, map[string]any{"name": n, "host": n, "ssl-certificate": entries(c)})
		}
		reply(res)
	case p == base+"access-proxy" && r.Method == http.MethodGet:
		if !z.servers {
			http.NotFound(w, r)
			return
		}
		reply([]map[string]any{{"name": "ztna-server", "vip": "ztna-vip", "auth-virtual-host": "portal.example.com",
			"api-gateway": []map[string]any{{"id": 1, "virtual-host": "app2.example.com"}}}})
	case strings.HasPrefix(p, base+"vip/") || strings.HasPrefix(p, base+"access-proxy-virtual-host/"):
		table, name := z.vips, strings.TrimPrefix(p, base+"vip/")
		if strings.HasPrefix(p, base+"access-proxy-virtual-host/") {
			table, name = z.vhosts, strings.TrimPrefix(p, base+"access-proxy-virtual-host/")
		}
		cur, ok := table[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodPut {
			var body struct {
				SSL []struct {
					Name string `json:"name"`
				} `json:"ssl-certificate"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			var next []string
			for _, e := range body.SSL {
				next = append(next, e.Name)
			}
			table[name] = next
			z.puts = append(z.puts, name)
			reply(map[string]any{})
			return
		}
		reply([]map[string]any{{"name": name, "ssl-certificate": entries(cur)}})
	default:
		z.fakeFGT.handle(w, r)
	}
}

func (z *ztnaFGT) cfg(extra map[string]string) map[string]string {
	c := map[string]string{
		"host": strings.TrimPrefix(z.srv.URL, "https://"), "token": "tok", "insecure": "true",
		"cert_prefix": "certsmith", "uses": "", "keep_old": "0",
	}
	for k, v := range extra {
		c[k] = v
	}
	return c
}

func TestDiscoveringTheZTNAServersOnFortiOS76(t *testing.T) {
	z := newZTNAFGT(t, "v7.6.7")
	res, err := fortiGate{}.Discover(context.Background(), z.cfg(nil))
	if err != nil {
		t.Fatal(err)
	}
	d := res.(fgDiscovery)
	if d.Version != "v7.6.7" || d.SSLVPN {
		t.Errorf("version %q, SSL VPN present = %v: 7.6 has none", d.Version, d.SSLVPN)
	}
	byName := map[string]fgZTNARow{}
	for _, r := range d.ZTNA {
		byName[r.Kind+":"+r.Name] = r
	}
	vip := byName["vip:ztna-vip"]
	if vip.Where != "203.0.113.10:8443" || vip.Server != "ztna-server" || strings.Join(vip.Certs, ",") != "Fortinet_Factory" {
		t.Errorf("vip row = %+v", vip)
	}
	if h := byName["vhost:app2.example.com"]; h.Server != "ztna-server" || len(h.Certs) != 2 || h.Where != "app2.example.com" {
		t.Errorf("virtual host row = %+v (it belongs to the server through an api-gateway)", h)
	}
	if byName["vhost:portal.example.com"].Server != "ztna-server" {
		t.Errorf("the auth virtual host should be labelled with its server: %+v", byName["vhost:portal.example.com"])
	}
}

func TestDiscoveringOnFortiOS80HasNoZTNAServerObjectAndSaysSo(t *testing.T) {
	z := newZTNAFGT(t, "v8.0.1")
	res, err := fortiGate{}.Discover(context.Background(), z.cfg(nil))
	if err != nil {
		t.Fatal(err)
	}
	d := res.(fgDiscovery)
	if d.SSLVPN || len(d.ZTNA) != 3 {
		t.Fatalf("8.0 discovery = %+v, want SSL VPN absent and the VIP plus two virtual hosts", d)
	}
	for _, r := range d.ZTNA {
		if r.Server != "" {
			t.Errorf("8.0 has no ZTNA server object to name: %+v", r)
		}
	}
}

func TestDeployingReplacesOnlyTheChosenEntryAndKeepsTheRestOfTheList(t *testing.T) {
	z := newZTNAFGT(t, "v7.6.7")
	b, _ := realisticBundle(t)
	cfg := z.cfg(map[string]string{
		"ztna": "vip;ztna-vip;Fortinet_Factory\nvhost;app2.example.com;old-cert",
		"uses": "admin-gui",
	})
	msg, err := fortiGate{}.Deploy(context.Background(), cfg, b)
	if err != nil {
		t.Fatalf("%v (%s)", err, msg)
	}
	name := fgCertName("certsmith", b.Name, b, 35)
	z.mu.Lock()
	defer z.mu.Unlock()
	if got := z.vips["ztna-vip"]; len(got) != 1 || got[0] != name {
		t.Errorf("vip entries = %v, want [%s]", got, name)
	}
	// the host had two entries: "old-cert" (chosen) and an earlier CertSmith one; the earlier CertSmith
	// entry is what a renewal replaces, and the chosen one is left alone
	if got := z.vhosts["app2.example.com"]; len(got) != 2 || got[0] != "old-cert" || got[1] != name {
		t.Errorf("virtual host entries = %v, want [old-cert %s]", got, name)
	}
	if got := z.vhosts["portal.example.com"]; len(got) != 1 || got[0] != "Fortinet_Factory" {
		t.Errorf("a ZTNA server that was not chosen must not change: %v", got)
	}
}

func TestAChosenEntryThatNoLongerExistsStopsTheDeploymentAndRollsBack(t *testing.T) {
	z := newZTNAFGT(t, "v7.6.7")
	b, _ := realisticBundle(t)
	cfg := z.cfg(map[string]string{
		"ztna": "vip;ztna-vip;Fortinet_Factory\nvhost;portal.example.com;a-cert-someone-removed",
		"uses": "admin-gui",
	})
	if _, err := (fortiGate{}).Deploy(context.Background(), cfg, b); err == nil || !strings.Contains(err.Error(), "no longer holds") {
		t.Fatalf("err = %v, want it to say the list no longer holds the chosen certificate", err)
	}
	z.mu.Lock()
	defer z.mu.Unlock()
	if got := z.vips["ztna-vip"]; len(got) != 1 || got[0] != "Fortinet_Factory" {
		t.Errorf("the first change was not rolled back: %v", got)
	}
	if z.fakeFGT.values["system/global:admin-server-cert"] != "Fortinet_Factory" {
		t.Errorf("the admin certificate changed although the deployment failed: %q", z.fakeFGT.values["system/global:admin-server-cert"])
	}
}

func TestTheSSLVPNSettingIsSkippedOnReleasesThatHaveNone(t *testing.T) {
	z := newZTNAFGT(t, "v7.6.7")
	b, _ := realisticBundle(t)
	cfg := z.cfg(map[string]string{"uses": "admin-gui,ssl-vpn"})
	msg, err := fortiGate{}.Deploy(context.Background(), cfg, b)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if !strings.Contains(msg, "ssl-vpn skipped") {
		t.Errorf("message = %q, want the skipped SSL VPN reported", msg)
	}
	name := fgCertName("certsmith", b.Name, b, 35)
	if z.fakeFGT.values["vpn.ssl/settings:servercert"] == name {
		t.Error("the SSL VPN setting was written on a release that has none")
	}
	if z.fakeFGT.values["system/global:admin-server-cert"] != name {
		t.Error("the admin certificate must still be switched")
	}
	// and the test reports it as not applicable, not as a failure
	got, err := fortiGate{}.Test(context.Background(), cfg)
	if err != nil || !strings.Contains(got, "ssl-vpn n/a") {
		t.Errorf("Test = %q, %v", got, err)
	}
}

func TestVersionsAndTheirSSLVPN(t *testing.T) {
	for v, gone := range map[string]bool{"v7.4.5": false, "v7.2.9": false, "v7.6.0": true, "v7.6.7": true, "v8.0.1": true, "": false} {
		if got := sslVPNRemoved(v); got != gone {
			t.Errorf("sslVPNRemoved(%q) = %v, want %v", v, got, gone)
		}
	}
}

func TestCertificateNamesCarryAReadableLabelAndStillSortByDate(t *testing.T) {
	b, _ := realisticBundle(t)
	b.Name = "Local Wildcard FAC"
	got := fgCertName("certsmith", b.Name, b, 35)
	if len(got) > 35 || !strings.HasPrefix(got, "certsmith-local-wild") || !strings.HasSuffix(got, fgNameOrderSuffix(b)) {
		t.Errorf("name = %q", got)
	}
	// a long prefix leaves no room: the plain form, as before
	if got := fgCertName("a-very-long-prefix-for-certificates", "x", b, 35); got != certName("a-very-long-prefix-for-certificates", b, 35) {
		t.Errorf("long prefix = %q", got)
	}
	// names with different labels are ordered by the date and serial they end with
	a, c := "certsmith-zzz-20260101-aaaa", "certsmith-aaa-20260202-bbbb"
	if !(fgNameOrder(c) > fgNameOrder(a)) {
		t.Error("the later certificate must sort as newer whatever its label")
	}
	if fgNameOrder("certsmith-20260101-aaaa") != "20260101-aaaa" {
		t.Error("names without a label keep working")
	}
}

func fgNameOrderSuffix(b *plugin.Bundle) string {
	return "-" + b.NotBefore.UTC().Format("20060102") + "-" + b.Serial[len(b.Serial)-4:]
}

var _ = time.Second
