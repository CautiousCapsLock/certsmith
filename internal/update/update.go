// Package update asks the release host whether a newer version of CertSmith has been published.
//
// It only reads. Nothing here downloads or installs anything: the web interface shows the result
// and the install command, and the installer does the rest. The request carries no identifier of the
// installation, only the User-Agent "certsmith/<version>" that every HTTP client sends.
package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultRepo is the repository releases are published in. CERTSMITH_REPO overrides it.
const DefaultRepo = "CautiousCapsLock/certsmith"

// DefaultAPI is the release API host.
const DefaultAPI = "https://api.github.com"

// Info is what the web interface shows about versions.
type Info struct {
	Current   string    `json:"current"`
	Latest    string    `json:"latest"`    // tag of the newest published release, "" until a check has succeeded
	Available bool      `json:"available"` // Latest is newer than Current
	URL       string    `json:"url"`       // release page, https only
	Published time.Time `json:"published"`
	CheckedAt time.Time `json:"checked_at"`
	Error     string    `json:"error"`
	Repo      string    `json:"repo"`
}

// Checker remembers the last answer.
type Checker struct {
	Repo    string
	APIBase string
	Version string
	Client  *http.Client

	mu   sync.Mutex
	last Info
}

var repoRe = regexp.MustCompile(`^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$`)

// New returns a Checker. An invalid repo falls back to the default.
func New(repo, version string) *Checker {
	if !repoRe.MatchString(repo) {
		repo = DefaultRepo
	}
	c := &Checker{Repo: repo, APIBase: DefaultAPI, Version: version,
		Client: &http.Client{Timeout: 15 * time.Second}}
	c.last = Info{Current: version, Repo: repo}
	return c
}

// Last returns the most recent result (never nil-safe to modify; it is a copy).
func (c *Checker) Last() Info {
	c.mu.Lock()
	defer c.mu.Unlock()
	i := c.last
	i.Current, i.Repo = c.Version, c.Repo
	return i
}

type release struct {
	Tag        string    `json:"tag_name"`
	HTMLURL    string    `json:"html_url"`
	Published  time.Time `json:"published_at"`
	Draft      bool      `json:"draft"`
	Prerelease bool      `json:"prerelease"`
}

var tagRe = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+([-+.][0-9A-Za-z.+-]*)?$`)

// Check asks for the latest published release and records the answer.
func (c *Checker) Check(ctx context.Context) Info {
	info := Info{Current: c.Version, Repo: c.Repo, CheckedAt: time.Now()}
	rel, err := c.fetch(ctx)
	if err != nil {
		info.Error = err.Error()
		// keep what was known: a failed check must not erase the last good answer
		c.mu.Lock()
		prev := c.last
		c.mu.Unlock()
		info.Latest, info.URL, info.Published, info.Available = prev.Latest, prev.URL, prev.Published, prev.Available
	} else {
		info.Latest, info.URL, info.Published = rel.Tag, rel.HTMLURL, rel.Published
		if cmp, ok := Compare(rel.Tag, c.Version); ok && cmp > 0 {
			info.Available = true
		}
	}
	c.mu.Lock()
	c.last = info
	c.mu.Unlock()
	return info
}

func (c *Checker) fetch(ctx context.Context) (*release, error) {
	url := strings.TrimRight(c.APIBase, "/") + "/repos/" + c.Repo + "/releases/latest"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "certsmith/"+c.Version)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not reach the release host: %w", err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, errors.New("no published release was found (the repository may be private or have no release yet)")
	case resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests:
		return nil, errors.New("the release host is limiting requests; it will be tried again later")
	case resp.StatusCode/100 != 2:
		return nil, fmt.Errorf("the release host answered HTTP %d", resp.StatusCode)
	}
	var rel release
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&rel); err != nil {
		return nil, errors.New("the release host sent an answer that could not be read")
	}
	if rel.Draft || rel.Prerelease {
		return nil, errors.New("the latest release is not a stable release")
	}
	if !tagRe.MatchString(rel.Tag) {
		return nil, fmt.Errorf("the latest release has an unexpected version %q", truncate(rel.Tag, 40))
	}
	// The release page is shown as a link: only a plain https address is accepted.
	if !strings.HasPrefix(rel.HTMLURL, "https://") || strings.ContainsAny(rel.HTMLURL, " \t\r\n\"'<>") {
		rel.HTMLURL = ""
	}
	return &rel, nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// version is a parsed semantic version.
type version struct {
	major, minor, patch int
	pre                 []string // pre-release identifiers; empty for a release
}

func parse(s string) (version, bool) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	if i := strings.IndexByte(s, '+'); i >= 0 { // build metadata does not take part in precedence
		s = s[:i]
	}
	var pre string
	if i := strings.IndexByte(s, '-'); i >= 0 {
		s, pre = s[:i], s[i+1:]
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return version{}, false
	}
	var n [3]int
	for i, p := range parts {
		v, err := strconv.Atoi(p)
		if err != nil || v < 0 {
			return version{}, false
		}
		n[i] = v
	}
	v := version{major: n[0], minor: n[1], patch: n[2]}
	if pre != "" {
		v.pre = strings.Split(pre, ".")
	}
	return v, true
}

// Compare orders two versions by semantic-version precedence: it returns -1, 0 or 1, and false when
// either is not a version (a development build reports "dev").
func Compare(a, b string) (int, bool) {
	x, ok1 := parse(a)
	y, ok2 := parse(b)
	if !ok1 || !ok2 {
		return 0, false
	}
	for _, p := range [][2]int{{x.major, y.major}, {x.minor, y.minor}, {x.patch, y.patch}} {
		if p[0] != p[1] {
			if p[0] < p[1] {
				return -1, true
			}
			return 1, true
		}
	}
	switch {
	case len(x.pre) == 0 && len(y.pre) == 0:
		return 0, true
	case len(x.pre) == 0: // a release is newer than its own pre-releases
		return 1, true
	case len(y.pre) == 0:
		return -1, true
	}
	for i := 0; i < len(x.pre) && i < len(y.pre); i++ {
		xi, xe := strconv.Atoi(x.pre[i])
		yi, ye := strconv.Atoi(y.pre[i])
		switch {
		case xe == nil && ye == nil:
			if xi != yi {
				if xi < yi {
					return -1, true
				}
				return 1, true
			}
		case xe == nil: // numeric identifiers rank below alphanumeric ones
			return -1, true
		case ye == nil:
			return 1, true
		default:
			if x.pre[i] != y.pre[i] {
				if x.pre[i] < y.pre[i] {
					return -1, true
				}
				return 1, true
			}
		}
	}
	switch {
	case len(x.pre) < len(y.pre):
		return -1, true
	case len(x.pre) > len(y.pre):
		return 1, true
	}
	return 0, true
}

// Due reports whether an automatic check should run now: never checked, a day since the last good
// answer, or an hour since a failure.
func Due(last Info, now time.Time) bool {
	if last.CheckedAt.IsZero() {
		return true
	}
	wait := 24 * time.Hour
	if last.Error != "" {
		wait = time.Hour
	}
	return now.Sub(last.CheckedAt) >= wait
}
