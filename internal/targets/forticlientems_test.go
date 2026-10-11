package targets

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFortiClientEMSIsAManualTargetUnderFortinetThatChecksBothPorts(t *testing.T) {
	d := forticlientEMS{}.Descriptor()
	if d.Kind != "forticlientems" || d.Vendor != "Fortinet" || !d.Manual {
		t.Fatalf("descriptor = %+v", d)
	}
	got := forticlientEMS{}.DefaultProbes(map[string]string{"host": "ems.example.com"})
	if strings.Join(got, ",") != "ems.example.com:443,ems.example.com:8013" {
		t.Errorf("default probes = %v, want the console (443) and the FortiClient port (8013)", got)
	}
	got = forticlientEMS{}.DefaultProbes(map[string]string{"host": "ems.example.com", "port": "8443", "client_port": "9000"})
	if strings.Join(got, ",") != "ems.example.com:8443,ems.example.com:9000" {
		t.Errorf("custom ports = %v", got)
	}
	got = forticlientEMS{}.DefaultProbes(map[string]string{"host": "ems.example.com", "client_port": "0"})
	if len(got) != 1 || got[0] != "ems.example.com:443" {
		t.Errorf("client_port 0 must check only the console: %v", got)
	}
}

func TestFortiClientEMSNeverClaimsToHaveDeployed(t *testing.T) {
	msg, err := forticlientEMS{}.Deploy(context.Background(), map[string]string{"host": "ems.example.com"}, nil)
	if err == nil || msg != "" || !strings.Contains(err.Error(), "import the certificate in the EMS console") {
		t.Fatalf("Deploy = %q, %v: it must refuse and say what to do instead", msg, err)
	}
}

func TestFortiClientEMSTestReadsTheCertificateOnEveryPort(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	cfg := map[string]string{"host": "127.0.0.1", "port": port, "client_port": port}
	msg, err := forticlientEMS{}.Test(context.Background(), cfg)
	if err != nil || strings.Count(msg, "serves") != 2 {
		t.Fatalf("Test = %q, %v: want both ports reported", msg, err)
	}
	// a port with nothing listening is reported as a failure that names the address
	cfg["client_port"] = "1"
	if _, err := (forticlientEMS{}).Test(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "127.0.0.1:1") {
		t.Errorf("a closed client port must fail the test and name it: %v", err)
	}
}
