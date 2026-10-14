package engine

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/CautiousCapsLock/certsmith/internal/model"
	"github.com/CautiousCapsLock/certsmith/internal/notify"
	"github.com/CautiousCapsLock/certsmith/internal/plugin"
)

type alert struct {
	level string // warn | crit
	line  string
}

// desiredAlerts derives the set of currently-true problem conditions.
func desiredAlerts(db *model.DB) map[string]alert {
	out := map[string]alert{}
	warn := db.Settings.WarnDays
	for _, c := range db.Certificates {
		if !c.Enabled {
			continue
		}
		if c.LastError != "" {
			lvl := "warn"
			if c.Serial == "" || daysLeft(c.NotAfter) <= 7 {
				lvl = "crit"
			}
			out["cert:"+c.ID+":error"] = alert{lvl, fmt.Sprintf("Certificate %q: issuance failing: %s", c.Name, c.LastError)}
		}
		if c.Serial != "" {
			if d := daysLeft(c.NotAfter); d <= warn {
				lvl := "warn"
				if d <= 7 {
					lvl = "crit"
				}
				out["cert:"+c.ID+":expiry"] = alert{lvl, fmt.Sprintf("Certificate %q expires in %d day(s) (%s)", c.Name, d, c.NotAfter.Format("2006-01-02"))}
			}
		}
	}
	for _, t := range db.Targets {
		if !t.Enabled {
			continue
		}
		if t.LastError != "" {
			out["target:"+t.ID+":error"] = alert{"crit", fmt.Sprintf("Target %q: deployment failing: %s", t.Name, t.LastError)}
		}
		for _, p := range t.Probes {
			key := "probe:" + t.ID + ":" + p.Addr
			switch {
			case p.Error != "" && p.Bad >= 2:
				out[key+":down"] = alert{"crit", fmt.Sprintf("%s (%s): cannot read served certificate: %s", t.Name, p.Addr, p.Error)}
			case p.Error == "":
				if d := daysLeft(p.NotAfter); d <= warn {
					lvl := "warn"
					if d <= 7 {
						lvl = "crit"
					}
					out[key+":expiry"] = alert{lvl, fmt.Sprintf("%s (%s) is serving a certificate that expires in %d day(s)", t.Name, p.Addr, d)}
				}
				if p.Match && p.ChainLen == 1 && !p.SelfSigned {
					out[key+":chain"] = alert{"warn", fmt.Sprintf("%s (%s) sends the certificate without its intermediate CA, so browsers may show it as untrusted", t.Name, p.Addr)}
				}
				if !p.Match && p.Bad >= 2 {
					if pl, ok := plugin.TargetFor(t.Kind); ok && pl.Descriptor().Manual {
						// not a fault: the certificate has to be put on the device by hand
						out[key+":mismatch"] = alert{"warn", fmt.Sprintf("%s (%s) is serving a different certificate (serial %s) than the current one: import the new certificate on the device", t.Name, p.Addr, short(p.Serial))}
					} else {
						out[key+":mismatch"] = alert{"crit", fmt.Sprintf("%s (%s) is serving a different certificate (serial %s) than the one deployed", t.Name, p.Addr, short(p.Serial))}
					}
				}
			}
		}
	}
	persistAlerts(db, out)
	return out
}

func short(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

// alertType maps an alert condition's key to its alert type, so it can be routed per channel.
func alertType(key string) string {
	switch {
	case strings.HasPrefix(key, "cert:") && strings.HasSuffix(key, ":error"):
		return notify.CertFailed
	case strings.HasPrefix(key, "cert:") && strings.HasSuffix(key, ":expiry"):
		return notify.CertExpiring
	case strings.HasPrefix(key, "cert:") && strings.HasSuffix(key, ":persist"):
		return notify.PersistRecord
	case strings.HasPrefix(key, "provider:") && strings.HasSuffix(key, ":persistuntil"):
		return notify.PersistExpiring
	case strings.HasPrefix(key, "target:"):
		return notify.DeployFailed
	case strings.HasSuffix(key, ":down"):
		return notify.EndpointDown
	case strings.HasSuffix(key, ":mismatch"):
		return notify.EndpointMismatch
	case strings.HasSuffix(key, ":chain"):
		return notify.EndpointChain
	case strings.HasSuffix(key, ":expiry"):
		return notify.EndpointExpiring
	}
	return ""
}

// CheckAlerts sends new alerts (and repeats unresolved ones daily), plus a note when a condition
// clears. Each alert goes only to the channels its type is routed to in Settings.
func (e *Engine) CheckAlerts(ctx context.Context) {
	snap := e.St.Snapshot()
	want := desiredAlerts(&snap)
	now := time.Now()

	type firing struct{ key, line string }
	var fire []firing
	var resolved []string
	for k, a := range want {
		last, seen := snap.Alerts[k]
		if !seen || now.Sub(last) >= alertRepeat {
			fire = append(fire, firing{k, strings.ToUpper(a.level) + ": " + a.line})
		}
	}
	for k := range snap.Alerts {
		if _, still := want[k]; !still {
			resolved = append(resolved, k)
		}
	}
	if len(fire) == 0 && len(resolved) == 0 {
		return
	}
	sort.Slice(fire, func(i, j int) bool { return fire[i].line < fire[j].line })

	sent := true
	if len(fire) > 0 {
		var emailLines, hookLines []string
		for _, f := range fire {
			e.St.AddEvent("warn", "alert", f.line)
			em, wh := notify.Routes(snap.Settings, alertType(f.key))
			if em {
				emailLines = append(emailLines, f.line)
			}
			if wh {
				hookLines = append(hookLines, f.line)
			}
		}
		deliver := func(lines []string, email, webhook bool) {
			if len(lines) == 0 {
				return
			}
			cs := notify.Only(snap.Settings, email, webhook)
			if !notify.Configured(cs) { // that channel is not set up: nothing to send, nothing failed
				return
			}
			ok := e.send(ctx, cs, notify.Message{
				Subject: fmt.Sprintf("[CertSmith] %d certificate alert(s)", len(lines)),
				Body:    strings.Join(lines, "\n") + "\n",
			})
			sent = sent && ok
		}
		deliver(emailLines, true, false)
		deliver(hookLines, false, true)
	}
	_ = e.St.Update(func(db *model.DB) error {
		if sent {
			for _, f := range fire {
				db.Alerts[f.key] = now
			}
		}
		for _, k := range resolved {
			delete(db.Alerts, k)
		}
		return nil
	})
	if len(resolved) > 0 {
		e.St.AddEvent("info", "alert", fmt.Sprintf("%d alert condition(s) cleared", len(resolved)))
		e.Notify(ctx, notify.AlertCleared, "[CertSmith] alerts cleared", fmt.Sprintf("%d alert condition(s) are no longer active.", len(resolved)))
	}
}

func (e *Engine) send(ctx context.Context, s model.Settings, m notify.Message) bool {
	pw, err := e.Box.Unseal(s.SMTP.Password)
	if err != nil {
		e.Log.Error("smtp password", "err", err)
		return false
	}
	if err := notify.Send(ctx, s, pw, m); err != nil {
		e.Log.Error("alert delivery failed", "err", err)
		e.St.AddEvent("error", "notify", "delivery failed: "+err.Error())
		return false
	}
	return true
}

// Notify sends one message of the given alert type to the channels it is routed to in Settings
// (and that are set up). It does nothing when the type is switched off everywhere.
func (e *Engine) Notify(ctx context.Context, typ, subject, body string) {
	s := e.St.Snapshot().Settings
	em, wh := notify.Routes(s, typ)
	em, wh = em && s.SMTP.Enabled, wh && s.WebhookURL != ""
	if !em && !wh {
		return
	}
	e.send(ctx, notify.Only(s, em, wh), notify.Message{Subject: subject, Body: body})
}

// SendTest delivers a test message and returns the delivery error, if any.
func (e *Engine) SendTest(ctx context.Context, s model.Settings) error {
	pw, err := e.Box.Unseal(s.SMTP.Password)
	if err != nil {
		return err
	}
	if !notify.Configured(s) {
		return fmt.Errorf("enable email or set a webhook URL first")
	}
	return notify.Send(ctx, s, pw, notify.Message{
		Subject: "[CertSmith] test alert",
		Body:    "If you can read this, CertSmith alert delivery works.\n",
	})
}
