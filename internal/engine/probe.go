package engine

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"strings"
	"time"

	"github.com/CautiousCapsLock/certsmith/internal/acme"
	"github.com/CautiousCapsLock/certsmith/internal/model"
	"github.com/CautiousCapsLock/certsmith/internal/plugin"
)

// ProbeAddr connects over TLS and reports the leaf certificate being served.
// Verification is skipped on purpose: the goal is to see what is served, even
// when it is expired, self-signed or for the wrong name.
func ProbeAddr(ctx context.Context, addr, expectSerial string) model.ProbeResult {
	r := model.ProbeResult{Addr: addr, CheckedAt: time.Now()}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host, port = addr, "443"
	}
	d := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 10 * time.Second},
		Config: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10,
			ServerName: sniName(host)},
	}
	pctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, err := d.DialContext(pctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		r.Error = err.Error()
		return r
	}
	defer conn.Close()
	certs := conn.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		r.Error = "no certificate presented"
		return r
	}
	leaf := certs[0]
	r.ChainLen, r.SelfSigned = len(certs), bytes.Equal(leaf.RawIssuer, leaf.RawSubject)
	r.Serial = acme.SerialHex(leaf)
	r.Subject, r.Issuer = leaf.Subject.CommonName, leaf.Issuer.CommonName
	r.NotAfter = leaf.NotAfter
	r.Match = expectSerial == "" || r.Serial == expectSerial
	return r
}

func sniName(host string) string {
	if net.ParseIP(host) != nil {
		return ""
	}
	return host
}

func (e *Engine) ProbeAll(ctx context.Context) {
	var ids []string
	e.St.View(func(db *model.DB) {
		for _, t := range db.Targets {
			if t.Enabled {
				ids = append(ids, t.ID)
			}
		}
	})
	for _, id := range ids {
		if ctx.Err() != nil {
			return
		}
		e.probeTarget(ctx, id)
	}
}

// probePending checks targets that have verify addresses but have never been
// probed (just created or reconfigured), so they show data straight away.
func (e *Engine) probePending(ctx context.Context) {
	var ids []string
	var pending []model.Target
	e.St.View(func(db *model.DB) {
		for _, t := range db.Targets {
			if t.Enabled && len(t.Probes) == 0 {
				pending = append(pending, t)
			}
		}
	})
	for _, t := range pending {
		if len(e.probeAddrs(t)) > 0 {
			ids = append(ids, t.ID)
		}
	}
	for _, id := range ids {
		e.probeTarget(ctx, id)
	}
}

// probeAddrs is every endpoint to check for a target: the ones typed under
// "Verify", plus the ones the plugin knows show its certificate (for a device's
// admin GUI that is simply its own host and port).
func (e *Engine) probeAddrs(t model.Target) []string {
	var out []string
	seen := map[string]bool{}
	add := func(a string) {
		if a = strings.TrimSpace(a); a != "" && !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	for _, a := range plugin.Lines(t.Config["verify"]) {
		add(a)
	}
	if p, ok := plugin.TargetFor(t.Kind); ok {
		if pr, ok := p.(plugin.Prober); ok {
			if cfg, err := e.OpenConfig(p.Descriptor(), t.Config); err == nil {
				for _, a := range pr.DefaultProbes(cfg) {
					add(a)
				}
			}
		}
	}
	return dropShadowedIPs(out, lookupHost)
}

// lookupHost resolves a name for dropShadowedIPs; a variable so that tests need no DNS.
var lookupHost = func(host string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return net.DefaultResolver.LookupHost(ctx, host)
}

// dropShadowedIPs removes an address written as an IP when another address in the list is a name that
// resolves to exactly that IP on the same port: they are one endpoint (a device addressed by IP whose
// DNS name was typed under "Verify"), and listing it twice is only noise. Two names are never merged,
// because the same IP can serve different certificates by name; a name that has several addresses, or
// cannot be resolved, merges nothing.
func dropShadowedIPs(addrs []string, lookup func(string) ([]string, error)) []string {
	split := func(a string) (host, port string) {
		h, p, err := net.SplitHostPort(a)
		if err != nil {
			return strings.Trim(a, "[]"), "443"
		}
		return h, p
	}
	hasIP, hasName := false, false
	for _, a := range addrs {
		if h, _ := split(a); net.ParseIP(h) != nil {
			hasIP = true
		} else {
			hasName = true
		}
	}
	if !hasIP || !hasName {
		return addrs
	}
	only := map[string]bool{} // "ip|port" for each name that resolves to that one address
	for _, a := range addrs {
		h, port := split(a)
		if net.ParseIP(h) != nil {
			continue
		}
		ips, err := lookup(h)
		if err != nil || len(ips) != 1 {
			continue
		}
		if ip := net.ParseIP(ips[0]); ip != nil {
			only[ip.String()+"|"+port] = true
		}
	}
	var out []string
	for _, a := range addrs {
		h, port := split(a)
		if ip := net.ParseIP(h); ip != nil && only[ip.String()+"|"+port] {
			continue
		}
		out = append(out, a)
	}
	return out
}

func (e *Engine) probeTarget(ctx context.Context, id string) {
	snap := e.St.Snapshot()
	var t *model.Target
	for i := range snap.Targets {
		if snap.Targets[i].ID == id {
			t = &snap.Targets[i]
		}
	}
	if t == nil {
		return
	}
	addrs := e.probeAddrs(*t)
	if len(addrs) == 0 {
		e.updateTarget(id, func(t *model.Target) { t.Probes = nil })
		return
	}
	expect := ""
	for _, c := range snap.Certificates {
		if c.ID == t.CertID {
			expect = c.Serial
		}
	}
	manual := false
	if p, ok := plugin.TargetFor(t.Kind); ok {
		manual = p.Descriptor().Manual
	}
	prev := map[string]model.ProbeResult{}
	for _, p := range t.Probes {
		prev[p.Addr] = p
	}
	var results []model.ProbeResult
	for _, a := range addrs {
		r := ProbeAddr(ctx, strings.TrimSpace(a), expect)
		// A mismatch only counts as bad once we believe the target is up to date. A target that is
		// installed by hand is never "deployed", so there the current certificate is the expectation.
		bad := r.Error != "" || (!r.Match && expect != "" && (manual || t.DeployedSerial == expect))
		if bad {
			r.Bad = prev[r.Addr].Bad + 1
		}
		results = append(results, r)
	}
	e.updateTarget(id, func(t *model.Target) { t.Probes = results })
}
