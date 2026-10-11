package targets

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/CautiousCapsLock/certsmith/internal/plugin"
)

// ---- FortiOS version ------------------------------------------------------------------

// fgVersion reads "v7.6.7" (the monitor/system/status form) into major and minor.
func fgVersion(v string) (major, minor int) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return 0, 0
	}
	major, _ = strconv.Atoi(parts[0])
	minor, _ = strconv.Atoi(parts[1])
	return major, minor
}

// sslVPNRemoved reports whether the release has no SSL VPN: it was replaced by ZTNA and agentless VPN
// in FortiOS 7.6.
func sslVPNRemoved(version string) bool {
	major, minor := fgVersion(version)
	return major > 7 || (major == 7 && minor >= 6)
}

// ---- ZTNA servers ---------------------------------------------------------------------
//
// A ZTNA server's certificate is named in two kinds of object, on 7.6 and on 8.0 alike:
//   firewall/vip (type access-proxy)            ssl-certificate: a list of {name}
//   firewall/access-proxy-virtual-host          ssl-certificate: a list of {name}
// On 7.6 the ZTNA server itself (firewall/access-proxy) only points at those; 8.0 has no such object.
// The administrator chooses which entries CertSmith replaces, and the choice is kept in the target's
// "ztna" setting as lines of  vip;<name>;<certificate now there>  or  vhost;<name>;<certificate now there>.

type ztnaChoice struct{ kind, name, entry string }

func parseZTNA(text string) ([]ztnaChoice, error) {
	var out []ztnaChoice
	for _, line := range plugin.Lines(text) {
		parts := strings.SplitN(line, ";", 3)
		if len(parts) != 3 || (parts[0] != "vip" && parts[0] != "vhost") || parts[1] == "" || parts[2] == "" {
			return nil, fmt.Errorf("ZTNA choice %q: want vip;<name>;<certificate> or vhost;<name>;<certificate>", line)
		}
		out = append(out, ztnaChoice{parts[0], parts[1], parts[2]})
	}
	return out, nil
}

func (z ztnaChoice) binding() fgBinding {
	path := "firewall/vip"
	if z.kind == "vhost" {
		path = "firewall/access-proxy-virtual-host"
	}
	return fgBinding{path: path, mkey: z.name, field: "ssl-certificate", list: true, entry: z.entry}
}

// wantFor is the value to write for a binding, given the value read. An ordinary binding takes the new
// certificate outright. A chosen list entry replaces only that entry, and leaves the rest of the list
// alone: the entry that CertSmith put there earlier (its prefix), or else the one the administrator
// chose. If neither is there any more, nothing is written and the person is asked to choose again.
func (b fgBinding) wantFor(old json.RawMessage, name, prefix string) (json.RawMessage, error) {
	if b.entry == "" {
		return b.valueFor(name), nil
	}
	var cur []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(old, &cur); err != nil {
		return nil, fmt.Errorf("read the certificate list of %s: %w", b.mkey, err)
	}
	idx := -1
	for i, e := range cur {
		if e.Name == name {
			return old, nil // already the new certificate
		}
		if idx < 0 && prefix != "" && strings.HasPrefix(e.Name, prefix+"-") {
			idx = i
		}
	}
	if idx < 0 {
		for i, e := range cur {
			if e.Name == b.entry {
				idx = i
				break
			}
		}
	}
	if idx < 0 {
		return nil, fmt.Errorf("%s no longer holds the certificate %q you chose: open the target and choose again", b.mkey, b.entry)
	}
	out := make([]map[string]string, len(cur))
	for i, e := range cur {
		out[i] = map[string]string{"name": e.Name}
	}
	out[idx]["name"] = name
	return json.Marshal(out)
}

// ---- discovery ------------------------------------------------------------------------

type fgZTNARow struct {
	Kind   string   `json:"kind"`             // vip | vhost
	Name   string   `json:"name"`             // the object
	Certs  []string `json:"certs"`            // the certificate entries it holds now
	Where  string   `json:"where"`            // address:port of a VIP, or the host name of a virtual host
	Server string   `json:"server,omitempty"` // the ZTNA server (7.6) that uses it
}

type fgDiscovery struct {
	Version string      `json:"version"`
	SSLVPN  bool        `json:"ssl_vpn"` // false: this release has no SSL VPN
	ZTNA    []fgZTNARow `json:"ztna"`
	Notes   []string    `json:"notes,omitempty"`
}

// listObjects GETs a cmdb table and returns its rows.
func (c *fgClient) listObjects(ctx context.Context, path string, q url.Values) ([]map[string]json.RawMessage, error) {
	var resp struct {
		Results []map[string]json.RawMessage `json:"results"`
	}
	if err := c.callRetry(ctx, http.MethodGet, "/api/v2/cmdb/"+path, q, nil, &resp); err != nil {
		return nil, err
	}
	return resp.Results, nil
}

func jstr(m map[string]json.RawMessage, k string) string {
	var s string
	_ = json.Unmarshal(m[k], &s)
	return s
}

func jnames(m map[string]json.RawMessage, k string) []string {
	var l []struct {
		Name string `json:"name"`
	}
	_ = json.Unmarshal(m[k], &l)
	out := make([]string, 0, len(l))
	for _, e := range l {
		out = append(out, e.Name)
	}
	return out
}

// Discover lists the ZTNA servers' certificates (read-only).
func (fortiGate) Discover(ctx context.Context, cfg map[string]string) (any, error) {
	c, err := newFGClient(cfg)
	if err != nil {
		return nil, err
	}
	var st struct {
		Version string `json:"version"`
	}
	if err := c.call(ctx, http.MethodGet, "/api/v2/monitor/system/status", nil, nil, &st); err != nil {
		return nil, err
	}
	out := fgDiscovery{Version: st.Version, SSLVPN: !sslVPNRemoved(st.Version), ZTNA: []fgZTNARow{}}

	vips, err := c.listObjects(ctx, "firewall/vip", url.Values{"filter": {"type==access-proxy"}})
	if err != nil {
		return nil, fmt.Errorf("list the ZTNA virtual IPs: %w", err)
	}
	vhosts, err := c.listObjects(ctx, "firewall/access-proxy-virtual-host", nil)
	if err != nil {
		return nil, fmt.Errorf("list the ZTNA virtual hosts: %w", err)
	}
	// 7.6 only: which ZTNA server each belongs to. 8.0 has no such object, so a failure is not one.
	serverOfVIP, serverOfHost := map[string]string{}, map[string]string{}
	if aps, err := c.listObjects(ctx, "firewall/access-proxy", nil); err == nil {
		for _, ap := range aps {
			name := jstr(ap, "name")
			if v := jstr(ap, "vip"); v != "" {
				serverOfVIP[v] = name
			}
			if v := jstr(ap, "auth-virtual-host"); v != "" {
				serverOfHost[v] = name
			}
			var gws []map[string]json.RawMessage
			_ = json.Unmarshal(ap["api-gateway"], &gws)
			for _, gw := range gws {
				if v := jstr(gw, "virtual-host"); v != "" {
					serverOfHost[v] = name
				}
			}
		}
	}
	for _, v := range vips {
		where := jstr(v, "extip")
		var port string
		_ = json.Unmarshal(v["extport"], &port)
		if port != "" && port != "0" {
			where += ":" + port
		}
		out.ZTNA = append(out.ZTNA, fgZTNARow{Kind: "vip", Name: jstr(v, "name"), Certs: jnames(v, "ssl-certificate"), Where: where, Server: serverOfVIP[jstr(v, "name")]})
	}
	for _, h := range vhosts {
		out.ZTNA = append(out.ZTNA, fgZTNARow{Kind: "vhost", Name: jstr(h, "name"), Certs: jnames(h, "ssl-certificate"), Where: jstr(h, "host"), Server: serverOfHost[jstr(h, "name")]})
	}
	sort.SliceStable(out.ZTNA, func(i, j int) bool {
		if out.ZTNA[i].Kind != out.ZTNA[j].Kind {
			return out.ZTNA[i].Kind < out.ZTNA[j].Kind
		}
		return out.ZTNA[i].Name < out.ZTNA[j].Name
	})
	if !out.SSLVPN {
		out.Notes = append(out.Notes, "This FortiOS release has no SSL VPN. Its place is taken by ZTNA and agentless VPN, listed here.")
	}
	return out, nil
}

// ---- readable certificate names -------------------------------------------------------

var (
	nameLabelChars = regexp.MustCompile(`[^a-z0-9]+`)
	nameDateSerial = regexp.MustCompile(`-(\d{8})-([0-9a-f]{4})$`)
)

// fgCertName is <prefix>-<label>-<yyyymmdd>-<serial4>. The label is CertSmith's name for the
// certificate, lower-cased and cut to what fits in FortiOS's 35 characters, so the entries in a
// certificate picker on the device say which certificate they are. With no room for a label (a long
// prefix) it is the plain <prefix>-<yyyymmdd>-<serial4>.
func fgCertName(prefix, label string, b *plugin.Bundle, max int) string {
	plain := certName(prefix, b, max)
	suffix := "-" + b.NotBefore.UTC().Format("20060102") + "-" + b.Serial[max0(len(b.Serial)-4):]
	label = strings.Trim(nameLabelChars.ReplaceAllString(strings.ToLower(label), "-"), "-")
	room := max - len(prefix) - 1 - len(suffix)
	if label == "" || room < 3 || len(plain) != len(prefix)+len(suffix) {
		return plain
	}
	if len(label) > room {
		label = strings.Trim(label[:room], "-")
	}
	if label == "" {
		return plain
	}
	return prefix + "-" + label + suffix
}

// fgNameOrder is what older-first / newer-first is decided on for CertSmith's certificate names:
// the date and serial at the end, so names with different labels still sort by when they were issued.
func fgNameOrder(n string) string {
	if m := nameDateSerial.FindStringSubmatch(n); m != nil {
		return m[1] + "-" + m[2]
	}
	return n
}
