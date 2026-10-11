package engine

import (
	"path/filepath"
	"strings"
	"testing"
)

// An identifier that arrives in a request names one directory of its own and nothing else.
func TestRequestIdentifiersCannotLeaveTheirDirectory(t *testing.T) {
	e := newEngine(t)
	for _, id := range []string{"..", "../..", "../../etc", "a/b", `..\x`, ".", "", "x y", strings.Repeat("a", 100)} {
		for _, p := range []string{e.issueLogPath(id), e.callsPath(id)} {
			if !strings.HasPrefix(p, filepath.Join(e.DataDir, "certs", "_invalid")) && !strings.HasPrefix(p, filepath.Join(e.DataDir, "targets", "_invalid")) {
				t.Errorf("identifier %q gave the path %q", id, p)
			}
		}
	}
	if got := e.callsPath("0123456789"); got != filepath.Join(e.DataDir, "targets", "0123456789", "calls.json") {
		t.Errorf("a real identifier must be used as it is: %q", got)
	}
}
