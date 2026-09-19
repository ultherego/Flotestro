package adminapi

import (
	"errors"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/paging"
)

// A cursor that did not come from the timeline is refused as a bad request
// rather than handed to the database: the identifier of a task row is a UUID,
// of a trail row a number, and a kind is one of the sources.
func TestTimelineCursorIsValidated(t *testing.T) {
	at := time.Date(2026, 9, 14, 8, 0, 0, 0, time.UTC)
	accepted := []timelineCursor{
		{At: at, Kind: "job", ID: "8a2f6c1e-0000-4000-8000-000000000001:finished"},
		{At: at, Kind: "session", ID: "8a2f6c1e-0000-4000-8000-000000000001:opened"},
		{At: at, Kind: "campaign", ID: "8a2f6c1e-0000-4000-8000-000000000001"},
		{At: at, Kind: "audit", ID: "42"},
		{At: at, Kind: "lifecycle", ID: "7"},
	}
	for _, cursor := range accepted {
		parsed, err := parseTimelineCursor(cursor.String())
		if err != nil || parsed.Kind != cursor.Kind || parsed.ID != cursor.ID {
			t.Errorf("%s/%s: %+v, %v", cursor.Kind, cursor.ID, parsed, err)
		}
	}
	refused := []timelineCursor{
		{At: at, Kind: "job", ID: "not-a-uuid"},
		{At: at, Kind: "job", ID: "42"},
		{At: at, Kind: "audit", ID: "8a2f6c1e-0000-4000-8000-000000000001"},
		{At: at, Kind: "trail", ID: "42"},
		{At: at, Kind: "job", ID: "8a2f6c1e-0000-4000-8000-000000000001'); drop table jobs; --"},
	}
	for _, cursor := range refused {
		if _, err := parseTimelineCursor(cursor.String()); !errors.Is(err, paging.ErrInvalidCursor) {
			t.Errorf("%s/%s was accepted: %v", cursor.Kind, cursor.ID, err)
		}
	}
	if cursor, err := parseTimelineCursor(""); err != nil || cursor.Set {
		t.Errorf("an empty cursor gave %+v, %v", cursor, err)
	}
}
