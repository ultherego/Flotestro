package systemd

import (
	"strings"
	"testing"
	"time"
)

// The detail reads override files only from the drop-in directories: a
// path systemd names elsewhere is reported by path with a reason, never
// opened.
func TestDropInsOutsideTheDirectoriesAreNotRead(t *testing.T) {
	dropIns := readDropIns([]string{
		"/usr/lib/systemd/system/cron.service.d/packaged.conf",
		"/etc/shadow",
		"/etc/systemd/system/cron.service.d/../../../etc/shadow",
		"/etc/systemd/system/no-such-unit-for-flotestro.service.d/override.conf",
	})
	if len(dropIns) != 4 {
		t.Fatalf("drop-ins = %d", len(dropIns))
	}
	for _, dropIn := range dropIns[:3] {
		if dropIn.Content != "" || !strings.Contains(dropIn.Error, "outside") {
			t.Errorf("%s: content %q, error %q", dropIn.Path, dropIn.Content, dropIn.Error)
		}
	}
	// A path inside the directories that does not exist is an answer too.
	if missing := dropIns[3]; missing.Content != "" || missing.Error == "" {
		t.Errorf("missing file: %+v", missing)
	}
}

// The list of drop-ins is bounded: a unit with dozens of overrides is
// looked at on the host, not moved into the panel.
func TestDropInsAreBounded(t *testing.T) {
	paths := make([]string, 0, maxDropIns+5)
	for i := 0; i < maxDropIns+5; i++ {
		paths = append(paths, "/usr/lib/systemd/system/x.service.d/packaged.conf")
	}
	if got := len(readDropIns(paths)); got != maxDropIns {
		t.Errorf("drop-ins = %d, want %d", got, maxDropIns)
	}
}

// The main process start time is passed on as a date when systemd's words
// read as one, and as the words themselves otherwise: "n/a" is an answer.
func TestMainStartReadsSystemdWords(t *testing.T) {
	if got := mainStart("n/a"); got != "" {
		t.Errorf("n/a = %q", got)
	}
	if got := mainStart(""); got != "" {
		t.Errorf("empty = %q", got)
	}
	got := mainStart("Mon 2026-09-14 10:00:00 UTC")
	parsed, err := time.Parse(time.RFC3339, got)
	if err != nil {
		t.Fatalf("start %q is not RFC 3339: %v", got, err)
	}
	if !parsed.Equal(time.Date(2026, 9, 14, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("start = %s", parsed)
	}
	if got := mainStart("sometime last week"); got != "sometime last week" {
		t.Errorf("words = %q", got)
	}
}
