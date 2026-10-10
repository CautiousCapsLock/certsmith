package plugin

import (
	"context"
	"errors"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/CautiousCapsLock/certsmith/internal/model"
)

// A Trace collects the API calls a plugin makes while it runs. The engine puts one in the
// context it hands to Test and Deploy; the HTTP client every target uses records into it, so
// plugins get this without extra code.
type Trace struct {
	mu    sync.Mutex
	op    string
	calls []model.APICall
}

// maxTraceCalls bounds one run: a deployment makes a few dozen calls, never thousands.
const maxTraceCalls = 400

func NewTrace(op string) *Trace { return &Trace{op: op} }

func (t *Trace) add(c model.APICall) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.calls) < maxTraceCalls {
		c.Op = t.op
		t.calls = append(t.calls, c)
	}
}

// annotate records what the device said about the most recent call.
func (t *Trace) annotate(answer string, failed bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if n := len(t.calls); n > 0 {
		t.calls[n-1].Answer, t.calls[n-1].Failed = answer, failed
	}
}

// Annotate adds the device's own account of its answer to the request just made with ctx. Plugins
// call it once they have read the response body; plugins make their requests one at a time.
func Annotate(ctx context.Context, answer string, failed bool) {
	if t := TraceFrom(ctx); t != nil {
		if len(answer) > 300 {
			answer = answer[:300] + "…"
		}
		t.annotate(strings.Join(strings.Fields(answer), " "), failed)
	}
}

// Calls returns what was recorded, oldest first.
func (t *Trace) Calls() []model.APICall {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]model.APICall(nil), t.calls...)
}

type traceKey struct{}
type detailKey struct{}
type hidePathKey struct{}

func WithTrace(ctx context.Context, t *Trace) context.Context {
	return context.WithValue(ctx, traceKey{}, t)
}

func TraceFrom(ctx context.Context) *Trace {
	t, _ := ctx.Value(traceKey{}).(*Trace)
	return t
}

// WithDetail labels the requests made with the returned context ("get /sys/status"), for APIs
// such as JSON-RPC where every request has the same URL.
func WithDetail(ctx context.Context, detail string) context.Context {
	return context.WithValue(ctx, detailKey{}, detail)
}

// HidePath makes the trace record only the host for requests made with the returned context, for
// endpoints whose path or query is itself a secret (webhook URLs).
func HidePath(ctx context.Context) context.Context {
	return context.WithValue(ctx, hidePathKey{}, true)
}

var secretParam = regexp.MustCompile(`(?i)token|key|secret|pass|auth|sig|session|cookie|credential`)

// Record notes one finished request. u is the request URL; status is 0 when no response arrived.
func Record(ctx context.Context, method string, u *url.URL, status int, took time.Duration, err error) {
	t := TraceFrom(ctx)
	if t == nil {
		return
	}
	c := model.APICall{Time: time.Now().Add(-took), Method: method, Host: u.Host, Status: status, Millis: took.Milliseconds()}
	if hide, _ := ctx.Value(hidePathKey{}).(bool); hide {
		c.Path = "/…"
	} else {
		c.Path = u.EscapedPath()
		if q := u.Query(); len(q) > 0 {
			c.Path += "?" + redactQuery(q)
		}
	}
	c.Detail, _ = ctx.Value(detailKey{}).(string)
	if err != nil {
		c.Error = cleanErr(err)
	}
	t.add(c)
}

// redactQuery keeps the parameter names (they say what was asked) but drops the values of any
// that could be a credential.
func redactQuery(q url.Values) string {
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		v := strings.Join(q[k], ",")
		if secretParam.MatchString(k) {
			v = "…"
		}
		parts = append(parts, url.QueryEscape(k)+"="+v)
	}
	return strings.Join(parts, "&")
}

// cleanErr drops the request URL that net/http wraps around its errors: the trace already says
// which request failed, and the URL may hold a secret.
func cleanErr(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	return strings.TrimSpace(err.Error())
}
