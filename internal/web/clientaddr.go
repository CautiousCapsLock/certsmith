package web

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/CautiousCapsLock/certsmith/internal/model"
)

// parseProxies reads the trusted proxy list: each entry is an address or a network (CIDR). It returns
// the entries in a normal form, so what is saved is what was understood.
func parseProxies(entries []string) (norm []string, prefixes []netip.Prefix, err error) {
	seen := map[string]bool{}
	for _, raw := range entries {
		e := strings.TrimSpace(raw)
		if e == "" {
			continue
		}
		var p netip.Prefix
		if strings.Contains(e, "/") {
			p, err = netip.ParsePrefix(e)
			if err != nil {
				return nil, nil, fmt.Errorf("%q is not an address or a network such as 192.0.2.0/24", e)
			}
			p = p.Masked()
		} else {
			a, aerr := netip.ParseAddr(e)
			if aerr != nil {
				return nil, nil, fmt.Errorf("%q is not an address or a network such as 192.0.2.0/24", e)
			}
			a = a.Unmap()
			p = netip.PrefixFrom(a, a.BitLen())
		}
		s := p.String()
		if !seen[s] {
			seen[s] = true
			norm = append(norm, s)
			prefixes = append(prefixes, p)
		}
	}
	return norm, prefixes, nil
}

func inPrefixes(a netip.Addr, ps []netip.Prefix) bool {
	a = a.Unmap()
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// resolveClient works out which address a request really came from. conn is the connection's own
// address. Only when the connection comes from a trusted proxy is X-Forwarded-For believed, and then
// from the right: each proxy appends the address it received the request from, so the entries to the
// right of the first one that is not a trusted proxy were added by our own infrastructure and the one
// at that position is the client. A header sent by anyone else is ignored. viaProxy reports whether
// the answer came from the header.
func resolveClient(conn string, xff []string, trusted []netip.Prefix) (client string, viaProxy bool) {
	c, err := netip.ParseAddr(conn)
	if err != nil || len(trusted) == 0 || !inPrefixes(c, trusted) {
		return conn, false
	}
	var chain []string
	for _, h := range xff {
		for _, part := range strings.Split(h, ",") {
			if p := strings.TrimSpace(part); p != "" {
				chain = append(chain, p)
			}
		}
	}
	for i := len(chain) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(chain[i])
		if err != nil {
			return conn, false // something that is not an address: believe none of it
		}
		if !inPrefixes(a, trusted) {
			return a.Unmap().String(), true
		}
	}
	return conn, false
}

func connHost(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

func (s *Server) trustedProxies() []netip.Prefix {
	var entries []string
	s.St.View(func(db *model.DB) { entries = db.Settings.TrustedProxies })
	_, ps, _ := parseProxies(entries)
	return ps
}

// clientIP is the address that decisions (the sign-in throttle) are made on: the connection's own, or
// the client's when the connection comes from a proxy listed under Settings.
func (s *Server) clientIP(r *http.Request) (string, bool) {
	return resolveClient(connHost(r), r.Header.Values("X-Forwarded-For"), s.trustedProxies())
}

// clientAddr is where a request came from, for the audit log and the user list. From a trusted proxy
// it is the client, with the proxy it came through. From anywhere else the connection address is shown,
// and a forwarded address, which anyone can write, only as a hint in the form the log has always used.
func (s *Server) clientAddr(r *http.Request) string {
	host := connHost(r)
	if ip, via := s.clientIP(r); via {
		return ip + " (via " + host + ")"
	}
	if xff := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-For"), ",")[0]); xff != "" && len(xff) <= 45 &&
		strings.Trim(xff, "0123456789abcdefABCDEF:.") == "" {
		return xff + " (via " + host + ")"
	}
	return host
}
