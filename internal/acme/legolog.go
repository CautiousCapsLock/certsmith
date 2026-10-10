package acme

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
)

// lineHandler writes lego's log records as the plain lines the issuance log has always shown:
//
//	2006/01/02 15:04:05 [INFO] Obtaining bundled SAN certificate. domains=a.example.com
//
// lego v5 logs through log/slog; its default text format (time=... level=... msg=...) would make the
// issuance log of a certificate look different from the CertSmith lines written beside it.
type lineHandler struct {
	mu    *sync.Mutex
	w     io.Writer
	attrs []slog.Attr
}

func newLineHandler(w io.Writer) *lineHandler { return &lineHandler{mu: &sync.Mutex{}, w: w} }

func (h *lineHandler) Enabled(_ context.Context, l slog.Level) bool { return l >= slog.LevelInfo }

func (h *lineHandler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	fmt.Fprintf(&b, "%s [%s] %s", r.Time.Format("2006/01/02 15:04:05"), levelName(r.Level), r.Message)
	write := func(a slog.Attr) bool {
		if a.Equal(slog.Attr{}) {
			return true
		}
		fmt.Fprintf(&b, " %s=%v", a.Key, a.Value.Resolve())
		return true
	}
	for _, a := range h.attrs {
		write(a)
	}
	r.Attrs(write)
	b.WriteByte('\n')
	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := io.WriteString(h.w, b.String())
	return err
}

func (h *lineHandler) WithAttrs(a []slog.Attr) slog.Handler {
	return &lineHandler{mu: h.mu, w: h.w, attrs: append(append([]slog.Attr{}, h.attrs...), a...)}
}

func (h *lineHandler) WithGroup(string) slog.Handler { return h }

func levelName(l slog.Level) string {
	switch {
	case l >= slog.LevelError:
		return "ERROR"
	case l >= slog.LevelWarn:
		return "WARN"
	}
	return "INFO"
}
