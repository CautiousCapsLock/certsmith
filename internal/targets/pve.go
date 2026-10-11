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
	fields := connFields("8006", "e.g. pve1.lab.example, as you browse to it")
	fields = append(fields, []plugin.Field{
		{Key: "node", Label: "Node name", Type: "text", Required: true,
			Help: "The node's name in Proxmox, not its address: the entry under Datacenter in the left-hand tree " +
				"(the command hostname prints it on the host). Case matters and there is no domain part."},
		{Key: "token", Label: "API token", Type: "password", Required: true, Secret: true,
			Help:       "Format USER@REALM!TOKENID=SECRET. Needs the Sys.Modify privilege on /nodes/<node name>.",
			StepsTitle: "How to create the token and give it permission",
			Steps: []string{
				"Datacenter → Permissions → API Tokens → Add. Pick a user (root@pam is fine), give the token an ID such as certsmith and leave Privilege Separation ticked. Copy the secret straight away, it is shown once, and paste it above as USER@REALM!TOKENID=SECRET.",
				"Datacenter → Permissions → Add → API Token Permission. Path: /nodes/ and your node name (the list offers it). API Token: the one you just made. Role: Administrator. Leave Propagate ticked.",
				"Administrator is the only built-in role that includes Sys.Modify, the privilege the certificate upload needs. PVEAdmin looks right but does not include it, so a token with that role passes the test and then fails to deploy.",
				"If the token belongs to a user other than root@pam, give that user the same role on the same path too: a separated token can only hold what its user holds.",
				"Optional hardening: make a role that holds only that privilege. Datacenter → Permissions → Roles → Create, name it CertSmith, tick only Sys.Modify, then choose CertSmith in step 2 instead of Administrator. The token can then replace the node's web certificate but cannot power the node off or open its console.",
				"Test connection only proves the address and the token. The permission is first used when the certificate is deployed, and a missing one is reported then, before anything on the node is changed.",
			}},
		verifyField,
	}...)
	return plugin.Descriptor{
		Kind:   "pve",
		Vendor: "Proxmox",
		Label:  "Proxmox VE (node web certificate)",
		Help:   "Uploads the certificate and private key to the node and restarts the pveproxy service. In a cluster, add each node as its own target.",
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
