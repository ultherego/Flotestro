package vuln

import (
	"errors"
	"strings"
	"testing"

	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/paging"
)

// The fleet table is sorted in the database and paged by the key of its last
// row, so the key has to carry the order it was cut under.

const aHostID = "a4b2f1c0-3d5e-4f60-9a71-2c3d4e5f6a7b"

func TestFleetCursorSurvivesTheRoundTrip(t *testing.T) {
	out := FleetCursor{Sort: SortFixable, Primary: -12, Secondary: -40, Hostname: "web-01", HostID: aHostID, Set: true}
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
		"..",
		paging.Encode(SortAffected, "0", "0", "web-01"),
		paging.Encode("worst-first", "0", "0", "web-01", aHostID),
		paging.Encode(SortAffected, "many", "0", "web-01", aHostID),
		paging.Encode(SortAffected, "0", "some", "web-01", aHostID),
		paging.Encode(SortAffected, "0", "0", "web-01", "web-01"),
	} {
		if _, err := ParseFleetCursor(token); !errors.Is(err, paging.ErrInvalidCursor) {
			t.Errorf("cursor %q was accepted: %v", token, err)
		}
	}
}

// Every order ascends on both of its keys, because the page boundary is one
// comparison over the whole tuple.
func TestFleetKeysAscendUnderEveryOrder(t *testing.T) {
	for _, order := range []string{SortAffected, SortFixable, SortHostname, ""} {
		primary, secondary := fleetKeys(order)
		if primary == "" || secondary == "" {
			t.Fatalf("order %q has an empty key: %q, %q", order, primary, secondary)
		}
		if order == SortHostname {
			continue
		}
		if !strings.HasPrefix(primary, "-") {
			t.Errorf("order %q sorts on %q, which does not put the worst first", order, primary)
		}
	}
	// An order nobody named is the worst first, like the default of the screen;
	// the second key puts a host that could not be assessed before the clean
	// ones, because a zero with a reason is not a result.
	primary, secondary := fleetKeys("")
	byName, _ := fleetKeys(SortAffected)
	if primary != byName {
		t.Errorf("the empty order is %q, expected the same as %q", primary, SortAffected)
	}
	if !strings.Contains(secondary, unassessedSQL) {
		t.Errorf("the second key %q does not tell an unassessed host from a clean one", secondary)
	}
}

// A search text is a text, not a pattern: an operator looking for db_01
// means an underscore.
func TestEscapeLikeKeepsWildcardsOutOfASearch(t *testing.T) {
	if got := escapeLike(`db_01%`); got != `db\_01\%` {
		t.Errorf("escapeLike = %q", got)
	}
	if got := escapeLike(`a\b`); got != `a\\b` {
		t.Errorf("escapeLike = %q", got)
	}
}

// The filter narrows the table; the scope narrows what may be read at all, and
// it is always the first condition, so a filter cannot be built that forgets
// it.
func TestFleetConditionsAlwaysStartWithTheScope(t *testing.T) {
	conditions, args := fleetConditions(FleetFilter{})
	if len(conditions) != 1 || conditions[0] != "false" {
		t.Fatalf("a filter without a scope gives %v", conditions)
	}
	conditions, args = fleetConditions(FleetFilter{
		Scopes: []authz.Scope{{Site: "lab", Environment: "test"}}, Query: " web ", Severity: "critical",
	})
	if len(conditions) != 3 {
		t.Fatalf("%d conditions, expected the scope, the search and the severity: %v", len(conditions), conditions)
	}
	if !strings.Contains(conditions[0], "h.site") {
		t.Errorf("the first condition is %q, expected the scope", conditions[0])
	}
	if len(args) != 4 {
		t.Fatalf("%d arguments, expected 4: %v", len(args), args)
	}
	if args[2] != "%web%" {
		t.Errorf("the search is %v, expected the trimmed text as a pattern", args[2])
	}
}

// A host without an assessment is not a host without vulnerabilities, so the
// condition that names it must read both a missing row and a row nobody has
// evaluated yet.
func TestUnassessedReadsBothWaysAHostCanBeSilent(t *testing.T) {
	if !strings.Contains(unassessedSQL, "v.host_id is null") ||
		!strings.Contains(unassessedSQL, "v.evaluated_at is null") {
		t.Errorf("the unassessed condition is %q", unassessedSQL)
	}
}
