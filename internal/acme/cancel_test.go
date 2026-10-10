package acme

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTransportRefusesRequestsAfterStop(t *testing.T) {
	hit := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit++ }))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	c := &http.Client{Transport: ctxTransport{ctx: ctx, next: http.DefaultTransport}}

	if _, err := c.Get(srv.URL); err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, err := c.Get(srv.URL); !errors.Is(err, context.Canceled) {
		t.Fatalf("after stop the request should fail with context.Canceled, got %v", err)
	}
	if hit != 1 {
		t.Fatalf("server saw %d requests, want 1: nothing may be sent to the CA after a stop", hit)
	}
}
