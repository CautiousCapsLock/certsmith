package main

import (
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// redirectHandler answers plain-HTTP requests on the optional redirect port by sending
// the browser to the same path on the HTTPS page. It serves no content of its own.
//
// The target host is the host the client asked for (the Host header), so
// http://192.0.2.5/ goes to https://192.0.2.5/ and http://certs.example.com/x to
// https://certs.example.com/x. Only a syntactically valid host name or address is
// accepted, the path is rebuilt rather than copied, and the scheme is fixed, so a request
// cannot steer the browser to a different site. httpsPort is the port of the HTTPS
// listener; 443 is left out of the URL.
//
// The redirect is temporary (307) and not cacheable: the port the page listens on can be
// changed, and a browser must not remember an old answer for it.
func redirectHandler(httpsPort string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "use HTTPS", http.StatusMethodNotAllowed)
			return
		}
		host, ok := redirectHost(r.Host)
		if !ok {
			http.Error(w, "bad host", http.StatusBadRequest)
			return
		}
		target := host
		if httpsPort != "" && httpsPort != "443" {
			target = net.JoinHostPort(strings.Trim(host, "[]"), httpsPort)
		}
		path := r.URL.Path
		if path == "" {
			path = "/"
		}
		u := url.URL{Scheme: "https", Host: target, Path: path, RawPath: r.URL.RawPath, RawQuery: r.URL.RawQuery}
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, u.String(), http.StatusTemporaryRedirect)
	})
}

// redirectHost returns the host part of a Host header (port removed, IPv6 in brackets)
// if it is a plausible host name or IP address.
func redirectHost(h string) (string, bool) {
	if h == "" || len(h) > 262 {
		return "", false
	}
	if strings.HasPrefix(h, "[") { // [v6] or [v6]:port
		end := strings.Index(h, "]")
		if end < 0 {
			return "", false
		}
		ip := net.ParseIP(h[1:end])
		if ip == nil || !validPort(strings.TrimPrefix(h[end+1:], ":"), h[end+1:] == "") {
			return "", false
		}
		return "[" + ip.String() + "]", true
	}
	host := h
	if strings.Contains(h, ":") {
		if strings.Count(h, ":") != 1 { // an unbracketed IPv6 address is not a valid Host
			return "", false
		}
		i := strings.Index(h, ":")
		host = h[:i]
		if !validPort(h[i+1:], false) {
			return "", false
		}
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), true
	}
	if !validHostname(host) {
		return "", false
	}
	return strings.ToLower(host), true
}

func validPort(p string, emptyOK bool) bool {
	if p == "" {
		return emptyOK
	}
	if len(p) > 5 {
		return false
	}
	for _, c := range p {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func validHostname(h string) bool {
	h = strings.TrimSuffix(h, ".")
	if h == "" || len(h) > 253 {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
			default:
				return false
			}
		}
	}
	return true
}

// newRedirectServer builds the plain-HTTP listener. Its limits are tight because it only
// ever sends a redirect.
func newRedirectServer(addr, httpsPort string) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           redirectHandler(httpsPort),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
}
