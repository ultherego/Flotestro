package backup

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/paging"
)

// The cursor is what keeps a fleet list honest between two pages: it carries
// the moment the states were judged at and the key of the last row, and it
// must come back exactly as it went out.

func TestFleetCursorSurvivesTheRoundTrip(t *testing.T) {
	now := time.Date(2026, 9, 17, 10, 30, 0, 123456000, time.UTC)
	last := time.Date(2026, 8, 1, 4, 5, 6, 0, time.UTC)
	out := FleetCursor{
		Now: now, Rank: 3, Last: paging.FormatTime(last), Hostname: "web-01",
		HostID: "3f1d5a2c-9e77-4a1b-8c2e-1d0f5b6a7c8d", Definition: "daily", Set: true,
	}
	back, err := ParseFleetCursor(out.String())
	if err != nil {
		t.Fatalf("parsing the cursor: %v", err)
	}
	if !back.Set || back.Rank != out.Rank || back.Hostname != out.Hostname ||
		back.HostID != out.HostID || back.Definition != out.Definition || back.Last != out.Last {
		t.Fatalf("cursor came back as %+v, expected %+v", back, out)
	}
	if !back.Now.Equal(now) {
		t.Errorf("judged at %s, expected %s", back.Now, now)
	}
}

// A copy that never ran has no date; its key is the instant before every
// other, so the worst rows keep their place across a page boundary.
func TestFleetCursorCarriesACopyThatNeverRan(t *testing.T) {
	out := FleetCursor{
		Now: time.Now().UTC().Truncate(time.Microsecond), Rank: 4, Last: neverKey,
		Hostname: "db-09", HostID: "3f1d5a2c-9e77-4a1b-8c2e-1d0f5b6a7c8d", Definition: "etc", Set: true,
	}
	back, err := ParseFleetCursor(out.String())
	if err != nil {
		t.Fatalf("parsing the cursor: %v", err)
	}
	if back.Last != neverKey {
		t.Errorf("last = %q, expected %q", back.Last, neverKey)
	}
}

func TestParseFleetCursorRefusesWhatThisListDidNotIssue(t *testing.T) {
	empty, err := ParseFleetCursor("")
	if err != nil || empty.Set {
		t.Fatalf("the first page is an empty cursor: %+v, %v", empty, err)
	}
	for _, token := range []string{
		"not base64 at all !!",
		paging.Encode("2026-09-17T10:00:00Z", "3", "-infinity", "web-01"),
		paging.Encode("yesterday", "3", "-infinity", "web-01", "3f1d5a2c-9e77-4a1b-8c2e-1d0f5b6a7c8d", "daily"),
		paging.Encode("2026-09-17T10:00:00Z", "worst", "-infinity", "web-01", "3f1d5a2c-9e77-4a1b-8c2e-1d0f5b6a7c8d", "daily"),
		paging.Encode("2026-09-17T10:00:00Z", "3", "soon", "web-01", "3f1d5a2c-9e77-4a1b-8c2e-1d0f5b6a7c8d", "daily"),
		paging.Encode("2026-09-17T10:00:00Z", "3", "-infinity", "web-01", "'; drop table hosts; --", "daily"),
	} {
		if _, err := ParseFleetCursor(token); !errors.Is(err, paging.ErrInvalidCursor) {
			t.Errorf("cursor %q was accepted: %v", token, err)
		}
	}
}

// The scope condition is pasted into the query, so it must narrow or
// refuse - never vanish and leave the whole fleet visible.
func TestScopeConditionNarrowsOrRefuses(t *testing.T) {
	if condition, _ := scopeCondition(nil, 0); condition != "false" {
		t.Errorf("no scope gives %q, expected false", condition)
	}
	if condition, _ := scopeCondition([]authz.Scope{{Site: authz.Wildcard, Environment: authz.Wildcard}}, 0); condition != "true" {
		t.Errorf("a global scope gives %q, expected true", condition)
	}
	condition, args := scopeCondition([]authz.Scope{{Site: "lab", Environment: "test"}}, 4)
	if !strings.Contains(condition, "$5") || !strings.Contains(condition, "$6") || len(args) != 2 {
		t.Errorf("a site scope after four parameters gives %q with %v", condition, args)
	}
}

// The thresholds are the ones the assessment judges by, in the order the
// query reads them, and the fourth is the moment of the reading itself.
func TestThresholdsFollowTheAssessment(t *testing.T) {
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	args := thresholds(now)
	if len(args) != 4 {
		t.Fatalf("%d thresholds, expected 4", len(args))
	}
	for index, want := range []time.Time{
		now.Add(-CriticalThreshold), now.Add(-WarningThreshold), now.Add(-VerificationThreshold), now,
	} {
		if got, ok := args[index].(time.Time); !ok || !got.Equal(want) {
			t.Errorf("threshold %d = %v, expected %s", index, args[index], want)
		}
	}
}
