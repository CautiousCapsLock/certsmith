package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func redirectTo(t *testing.T, httpsPort, method, host, target string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	req.Host = host
	rec := httptest.NewRecorder()
	redirectHandler(httpsPort).ServeHTTP(rec, req)
	return rec
}

func TestRedirectTargets(t *testing.T) {
	cases := []struct {
		name, port, host, target, want string
	}{
		{"name, 443 omitted", "443", "certs.example.com", "/", "https://certs.example.com/"},
		{"port 80 on the host is dropped", "443", "certs.example.com:80", "/", "https://certs.example.com/"},
		{"ipv4", "443", "192.0.2.10", "/", "https://192.0.2.10/"},
		{"path and query kept", "443", "192.0.2.10", "/api/state?a=1&b=x%20y", "https://192.0.2.10/api/state?a=1&b=x%20y"},
		{"non-default https port", "8443", "192.0.2.10:80", "/x", "https://192.0.2.10:8443/x"},
		{"ipv6", "443", "[2001:db8::1]", "/", "https://[2001:db8::1]/"},
		{"ipv6 with port and https port", "8443", "[2001:db8::1]:80", "/", "https://[2001:db8::1]:8443/"},
		{"host is lower-cased", "443", "Certs.Example.COM", "/", "https://certs.example.com/"},
		{"double slash path stays on our host", "443", "certs.example.com", "//evil.example/steal", "https://certs.example.com//evil.example/steal"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := redirectTo(t, c.port, http.MethodGet, c.host, c.target)
			if rec.Code != http.StatusTemporaryRedirect {
				t.Fatalf("status %d, want 307", rec.Code)
			}
			if got := rec.Header().Get("Location"); got != c.want {
				t.Fatalf("Location %q, want %q", got, c.want)
			}
			if rec.Header().Get("Cache-Control") != "no-store" {
				t.Errorf("redirect must not be cacheable, Cache-Control=%q", rec.Header().Get("Cache-Control"))
			}
		})
	}
}

func TestRedirectRejectsOddHosts(t *testing.T) {
	for _, h := range []string{
		"", "evil.com/@good.com", "a b.example", "x.example\r\nSet-Cookie: a=b", "a@b.example",
		"2001:db8::1", "[2001:db8::1", "[notanip]", "host:abc", "host:123456", "-bad.example",
		"a..example", "http://evil.example", "ex ample.com", strings.Repeat("a", 300) + ".example",
	} {
		rec := redirectTo(t, "443", http.MethodGet, h, "/")
		if rec.Code != http.StatusBadRequest {
			t.Errorf("host %q: status %d (Location %q), want 400", h, rec.Code, rec.Header().Get("Location"))
		}
	}
}

func TestRedirectOnlyForGetAndHead(t *testing.T) {
	for _, m := range []string{http.MethodGet, http.MethodHead} {
		if rec := redirectTo(t, "443", m, "certs.example.com", "/"); rec.Code != http.StatusTemporaryRedirect {
			t.Errorf("%s: status %d, want 307", m, rec.Code)
		}
	}
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		rec := redirectTo(t, "443", m, "certs.example.com", "/api/login")
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: status %d, want 405 (never pretend a plain-HTTP POST is fine)", m, rec.Code)
		}
		if rec.Header().Get("Location") != "" {
			t.Errorf("%s: must not redirect, got Location %q", m, rec.Header().Get("Location"))
		}
	}
}

// The listener itself, over a real socket, with redirects not followed.
func TestRedirectServerEndToEnd(t *testing.T) {
	ts := httptest.NewServer(redirectHandler("8443"))
	defer ts.Close()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(ts.URL + "/some/path?q=1")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("status %d, want 307", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "https://127.0.0.1:8443/some/path?q=1") {
		t.Fatalf("Location %q", loc)
	}
}
