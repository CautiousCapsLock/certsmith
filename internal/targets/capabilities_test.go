package targets

import (
	"context"
	"net"
	"strings"
	"testing"
)

func capCfg(f *fakeFGT, uses string) map[string]string {
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(f.srv.URL, "https://"))
	return map[string]string{"host": host, "port": port, "token": "tok", "insecure": "true", "uses": uses, "keep_old": "0"}
}

func TestHostPortCombinations(t *testing.T) {
	cases := []struct {
		name     string
		cfg      map[string]string
		def      string
		expected string
	}{
		{"separate fields", map[string]string{"host": "fw.lab", "port": "8443"}, "443", "fw.lab:8443"},
		{"port left empty uses the default", map[string]string{"host": "fw.lab"}, "443", "fw.lab:443"},
		{"legacy host:port still works", map[string]string{"host": "fw.lab:10443"}, "443", "fw.lab:10443"},
		{"explicit port wins over legacy", map[string]string{"host": "fw.lab:10443", "port": "8443"}, "443", "fw.lab:8443"},
		{"ipv6 literal", map[string]string{"host": "fd00::1"}, "443", "[fd00::1]:443"},
		{"proxmox default", map[string]string{"host": "pve"}, "8006", "pve:8006"},
	}
	for _, c := range cases {
		if got := hostPort(c.cfg, c.def); got != c.expected {
			t.Errorf("%s: got %q want %q", c.name, got, c.expected)
		}
	}
}

func TestTickBoxesBecomeIndependentCapabilities(t *testing.T) {
	f := newFakeFGT(t)
	msg, err := fortiGate{}.Deploy(context.Background(), capCfg(f, "admin-gui,ssl-vpn"), testBundle(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"admin-gui updated", "ssl-vpn updated"} {
		if !strings.Contains(msg, want) {
			t.Errorf("report %q missing %q", msg, want)
		}
	}
}

func TestOnlyTickedCapabilitiesAreTouched(t *testing.T) {
	f := newFakeFGT(t)
	if _, err := (fortiGate{}).Deploy(context.Background(), capCfg(f, "ssl-vpn"), testBundle(t)); err != nil {
		t.Fatal(err)
	}
	if f.values["system/global:admin-server-cert"] != "Fortinet_Factory" {
		t.Fatalf("admin GUI was changed although it was not ticked: %v", f.values)
	}
	if f.values["vpn.ssl/settings:servercert"] == "Fortinet_Factory" {
		t.Fatal("ticked SSL VPN was not switched")
	}
}

func TestNothingTickedIsAnError(t *testing.T) {
	f := newFakeFGT(t)
	if _, err := (fortiGate{}).Test(context.Background(), capCfg(f, "")); err == nil || !strings.Contains(err.Error(), "tick at least one") {
		t.Fatalf("got %v", err)
	}
}

func TestIPsecNeedsPhase1Names(t *testing.T) {
	f := newFakeFGT(t)
	if _, err := (fortiGate{}).Test(context.Background(), capCfg(f, "ipsec")); err == nil || !strings.Contains(err.Error(), "phase 1") {
		t.Fatalf("got %v", err)
	}
	c, err := plan(map[string]string{"uses": "ipsec", "ipsec_phase1": "to-hq, to-dc"})
	if err != nil || len(c) != 1 || len(c[0].bindings) != 2 || !c[0].bindings[0].list {
		t.Fatalf("plan = %+v, %v", c, err)
	}
}

func TestTestReportsEachCapabilitySeparately(t *testing.T) {
	f := newFakeFGT(t)
	f.failGet = "vpn.ssl/settings"
	_, err := fortiGate{}.Test(context.Background(), capCfg(f, "admin-gui,ssl-vpn"))
	if err == nil {
		t.Fatal("expected a failure for the broken capability")
	}
	for _, want := range []string{"admin-gui ok", "ssl-vpn FAILED", "SSL VPN portal"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%q missing from %q", want, err)
		}
	}
}

func TestAdminGUIIsAppliedLast(t *testing.T) {
	c, err := plan(map[string]string{"uses": "admin-gui,ssl-vpn,auth-portal"})
	if err != nil {
		t.Fatal(err)
	}
	if c[len(c)-1].id != "admin-gui" {
		var ids []string
		for _, x := range c {
			ids = append(ids, x.id)
		}
		t.Fatalf("order %v: admin-gui restarts HTTPS and must go last", ids)
	}
}

func TestDefaultProbeFollowsAdminGUI(t *testing.T) {
	g := fortiGate{}
	if got := g.DefaultProbes(map[string]string{"host": "fw", "uses": "admin-gui"}); len(got) != 1 || got[0] != "fw:443" {
		t.Fatalf("admin gui: %v", got)
	}
	if got := g.DefaultProbes(map[string]string{"host": "fw", "port": "8443", "uses": "admin-gui,ssl-vpn"}); got[0] != "fw:8443" {
		t.Fatalf("custom port: %v", got)
	}
	// an SSL VPN-only certificate is not shown on the management address: do not probe it there
	if got := g.DefaultProbes(map[string]string{"host": "fw", "uses": "ssl-vpn"}); len(got) != 0 {
		t.Fatalf("ssl-vpn only must not auto-probe the admin port: %v", got)
	}
}

func TestLegacyBindingsStillWork(t *testing.T) {
	f := newFakeFGT(t)
	cfg := capCfg(f, "")
	cfg["bindings"] = "admin-gui\nssl-vpn"
	if _, err := (fortiGate{}).Deploy(context.Background(), cfg, testBundle(t)); err != nil {
		t.Fatalf("configs saved by earlier versions must keep deploying: %v", err)
	}
}

func TestDescriptorShape(t *testing.T) {
	d := fortiGate{}.Descriptor()
	if d.Vendor != "Fortinet" {
		t.Errorf("vendor = %q", d.Vendor)
	}
	var host, port, uses bool
	for _, f := range d.Fields {
		switch f.Key {
		case "host":
			host = f.Row == "conn"
		case "port":
			port = f.Row == "conn" && f.Default == "443"
		case "uses":
			uses = f.Type == "checks" && len(f.Choices) >= 4
		}
	}
	if !host || !port || !uses {
		t.Fatalf("host/port on one row=%v/%v, tick boxes=%v", host, port, uses)
	}
}
