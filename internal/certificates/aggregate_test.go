package certificates

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/paging"
)

// The fleet list is keyed on the expiry, the host and the path, and the
// key is read back out of the certificate the way the query reads it. If
// the two ever disagree a page boundary either skips a certificate or
// shows one twice - which on this screen means a deadline nobody sees.

const sampleHostID = "9b1c0e1a-4d3f-4a90-8b2c-77e6f5a4d3c2"

func TestFleetCursorSurvivesTheRoundTrip(t *testing.T) {
	out := FleetCursor{
		NotAfter: paging.FormatTime(time.Date(2026, 12, 1, 8, 0, 0, 0, time.UTC)),
		Hostname: "web-01", HostID: sampleHostID, Path: "/etc/ssl/certs/web.pem", Set: true,
	}
	back, err := ParseFleetCursor(out.String())
	if err != nil {
		t.Fatalf("parsing the cursor: %v", err)
	}
	if back != out {
		t.Fatalf("cursor came back as %+v, expected %+v", back, out)
	}
}

func TestParseFleetCursorRefusesWhatThisListDidNotIssue(t *testing.T) {
	empty, err := ParseFleetCursor("")
	if err != nil || empty.Set {
		t.Fatalf("the first page is an empty cursor: %+v, %v", empty, err)
	}
	for _, token := range []string{
		"%%%",
		paging.Encode("infinity", "web-01", sampleHostID),
		paging.Encode("in a while", "web-01", sampleHostID, "/etc/ssl/web.pem"),
		paging.Encode("infinity", "web-01", "not-a-host", "/etc/ssl/web.pem"),
	} {
		if _, err := ParseFleetCursor(token); !errors.Is(err, paging.ErrInvalidCursor) {
			t.Errorf("cursor %q was accepted: %v", token, err)
		}
	}
}

// A certificate without a date sorts last, so its key is the instant
// after every other - not an empty string, which would sort first.
func TestCursorAfterReadsTheRowTheQuerySorted(t *testing.T) {
	notAfter := time.Date(2027, 1, 15, 6, 30, 0, 0, time.UTC)
	dated := FleetRow{
		HostID: sampleHostID, Hostname: "web-01",
		Certificate: json.RawMessage(`{"path":"/etc/ssl/web.pem","not_after":"` + notAfter.Format(time.RFC3339) + `"}`),
	}
	cursor := cursorAfter(dated)
	if cursor.NotAfter != paging.FormatTime(notAfter) || cursor.Path != "/etc/ssl/web.pem" {
		t.Errorf("cursor of a dated certificate = %+v", cursor)
	}
	if !cursor.Set || cursor.HostID != sampleHostID || cursor.Hostname != "web-01" {
		t.Errorf("cursor lost the host: %+v", cursor)
	}

	undated := FleetRow{HostID: sampleHostID, Hostname: "web-01", Certificate: json.RawMessage(`{"path":"/etc/ssl/x.pem"}`)}
	if got := cursorAfter(undated); got.NotAfter != noExpiryKey {
		t.Errorf("a certificate without a date keys on %q, expected %q", got.NotAfter, noExpiryKey)
	}
}

// Every bucket the screen shows has a name here, in the order the screen
// shows them: the nearest deadline first and the certificates nobody
// could date last, apart rather than as "valid for long".
func TestTimelineBucketsAreNamedInOrder(t *testing.T) {
	want := []string{"expired", "7 days", "30 days", "90 days", "later", "no expiry"}
	if len(TimelineBuckets) != len(want) {
		t.Fatalf("%d buckets, expected %d", len(TimelineBuckets), len(want))
	}
	for i, bucket := range want {
		if TimelineBuckets[i] != bucket {
			t.Errorf("bucket %d = %q, expected %q", i, TimelineBuckets[i], bucket)
		}
	}
}

func TestScopeConditionNarrowsOrRefuses(t *testing.T) {
	if condition, _ := scopeCondition(nil, 0); condition != "false" {
		t.Errorf("no scope gives %q, expected false", condition)
	}
	if condition, _ := scopeCondition([]authz.Scope{{Site: authz.Wildcard, Environment: authz.Wildcard}}, 0); condition != "true" {
		t.Errorf("a global scope gives %q, expected true", condition)
	}
	if _, args := scopeCondition([]authz.Scope{{Site: "lab", Environment: "test"}}, 0); len(args) != 2 {
		t.Errorf("a site scope carries %d arguments, expected 2", len(args))
	}
}
