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
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
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

// Note is the release notes of one published release that is newer than the running version.
type Note struct {
	Version   string    `json:"version"` // the tag, for example v0.15.0
	Published time.Time `json:"published"`
	URL       string    `json:"url"`   // release page, https only
	Notes     string    `json:"notes"` // Markdown, as the release was published with
}

// maxNote bounds one release's notes, and maxNotes how many are kept: the page shows what an upgrade
// brings, not a changelog of everything.
const (
	maxNote  = 16 << 10
	maxNotes = 5
)

// Checker remembers the last answer.
type Checker struct {
	Repo    string
	APIBase string
	Version string
	Client  *http.Client

	mu    sync.Mutex
	last  Info
	notes []Note // newest first; only the releases newer than Version
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
	Body       string    `json:"body"`
}

// Upcoming returns the release notes of the releases newer than the running version, newest first. It is
// empty until a check has found an update, and it is kept out of Info so that the page's regular refresh
// does not carry it.
func (c *Checker) Upcoming() []Note {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Note(nil), c.notes...)
}

func clip(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= maxNote {
		return s
	}
	s = s[:maxNote]
	for len(s) > 0 && !utf8.ValidString(s) { // do not end in half a character
		s = s[:len(s)-1]
	}
	return strings.TrimSpace(s) + "\n\n…"
}

// safeURL keeps a link only when it is a plain https address.
func safeURL(u string) string {
	if !strings.HasPrefix(u, "https://") || strings.ContainsAny(u, " \t\r\n\"'<>") {
		return ""
	}
	return u
}

// fetchNotes lists the published releases and keeps the ones newer than the running version. It is only
// asked when an update exists, and is best effort: on any failure the caller keeps the newest one's notes.
func (c *Checker) fetchNotes(ctx context.Context) []Note {
	url := strings.TrimRight(c.APIBase, "/") + "/repos/" + c.Repo + "/releases?per_page=20"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "certsmith/"+c.Version)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil
	}
	var rels []release
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&rels); err != nil {
		return nil
	}
	var out []Note
	for _, r := range rels {
		if r.Draft || r.Prerelease || !tagRe.MatchString(r.Tag) {
			continue
		}
		if cmp, ok := Compare(r.Tag, c.Version); !ok || cmp <= 0 {
			continue
		}
		out = append(out, Note{Version: r.Tag, Published: r.Published, URL: safeURL(r.HTMLURL), Notes: clip(r.Body)})
	}
	sort.SliceStable(out, func(i, j int) bool { cmp, _ := Compare(out[i].Version, out[j].Version); return cmp > 0 })
	if len(out) > maxNotes {
		out = out[:maxNotes]
	}
	return out
}

var tagRe = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+([-+.][0-9A-Za-z.+-]*)?$`)

// Check asks for the latest published release and records the answer.
func (c *Checker) Check(ctx context.Context) Info {
	info := Info{Current: c.Version, Repo: c.Repo, CheckedAt: time.Now()}
	var notes []Note
	setNotes := false
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
		notes = nil
		if info.Available {
			// what the upgrade brings: every release between here and the newest (best effort)
			notes = c.fetchNotes(ctx)
			if len(notes) == 0 {
				notes = []Note{{Version: rel.Tag, Published: rel.Published, URL: safeURL(rel.HTMLURL), Notes: clip(rel.Body)}}
			}
		}
		setNotes = true
	}
	c.mu.Lock()
	c.last = info
	if setNotes { // a failed check keeps the notes of the last good one
		c.notes = notes
	}
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
