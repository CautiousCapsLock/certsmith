package targets

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/CautiousCapsLock/certsmith/internal/plugin"
)

func init() { plugin.RegisterTarget(pveTarget{}) }

// pveTarget installs a custom certificate for pveproxy on a Proxmox VE node via
// POST /nodes/{node}/certificates/custom (same call as the GUI's upload button).
type pveTarget struct{}

func (pveTarget) Descriptor() plugin.Descriptor {
	fields := connFields("8006", "e.g. pve1.lab.example")
	fields = append(fields, []plugin.Field{
		{Key: "node", Label: "Node name", Type: "text", Required: true},
		{Key: "token", Label: "API token", Type: "password", Required: true, Secret: true,
			Help: "Format USER@REALM!TOKENID=SECRET. Needs Sys.Modify on /nodes/<node>."},
		verifyField,
	}...)
	return plugin.Descriptor{
		Kind:   "pve",
		Vendor: "Proxmox",
		Label:  "Proxmox VE (node web certificate)",
		Help:   "Uploads the certificate and private key to the node and restarts the pveproxy service.",
		Fields: append(fields, tlsFields...),
		Calls: []plugin.CallDoc{
			{Op: "test", Method: "GET", Path: "/api2/json/version", Purpose: "Proves the address and API token work, and reads the Proxmox VE version."},
			{Op: "deploy", Method: "POST", Path: "/api2/json/nodes/<node>/certificates/custom", Changes: true,
				Purpose: "Uploads the certificate chain and key for the node (replacing any custom one) and restarts pveproxy so it is used straight away."},
		},
		AutoVerify: true, AutoVerifyPort: "8006",
	}
}

func (pveTarget) APIEndpoint(cfg map[string]string) string { return hostPort(cfg, "8006") }

func (pveTarget) DefaultProbes(cfg map[string]string) []string {
	return []string{hostPort(cfg, "8006")}
}

func (pveTarget) do(ctx context.Context, cfg map[string]string, method, path string, form url.Values) ([]byte, error) {
	host := hostPort(cfg, "8006")
	hc, err := httpClient(host, cfg, 60*time.Second)
	if err != nil {
		return nil, err
	}
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	var out []byte
	err = retryNet(ctx, 4, 3*time.Second, func() error {
		if form != nil {
			body = strings.NewReader(form.Encode())
		}
		req, err := http.NewRequestWithContext(ctx, method, "https://"+host+"/api2/json"+path, body)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "PVEAPIToken="+cfg["token"])
		if form != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		resp, err := hc.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		if resp.StatusCode/100 != 2 {
			plugin.Annotate(ctx, strings.TrimSpace(string(raw)), true)
			return &apiError{Status: resp.StatusCode, Msg: strings.TrimSpace(string(raw))}
		}
		out = raw
		return nil
	})
	return out, err
}

func (p pveTarget) Test(ctx context.Context, cfg map[string]string) (string, error) {
	raw, err := p.do(ctx, cfg, http.MethodGet, "/version", nil)
	if err != nil {
		return "", err
	}
	var v struct {
		Data struct {
			Version string `json:"version"`
		} `json:"data"`
	}
	_ = json.Unmarshal(raw, &v)
	return "Proxmox VE " + v.Data.Version, nil
}

func (p pveTarget) Deploy(ctx context.Context, cfg map[string]string, b *plugin.Bundle) (string, error) {
	cfg = withDeployedPin(cfg, b)
	form := url.Values{
		"certificates": {string(b.FullChain)},
		"key":          {string(b.KeyPEM)},
		"force":        {"1"},
		"restart":      {"1"},
	}
	if _, err := p.do(ctx, cfg, http.MethodPost, "/nodes/"+url.PathEscape(cfg["node"])+"/certificates/custom", form); err != nil {
		return "", err
	}
	return fmt.Sprintf("installed on node %s; pveproxy restarted", cfg["node"]), nil
}
