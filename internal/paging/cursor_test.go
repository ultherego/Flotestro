package paging

import (
	"errors"
	"testing"
	"time"
)

// TestCursorRoundTrip guards that a key survives the trip to the browser and
// back unchanged, including the microseconds of a timestamp: a cursor that
// lands one microsecond earlier repeats the last row on the next page.
func TestCursorRoundTrip(t *testing.T) {
	at := time.Date(2026, 9, 13, 10, 4, 5, 123456000, time.UTC)
	token := Encode(FormatTime(at), "8a2f6c1e-0000-4000-8000-000000000001")
	parts, err := Decode(token, 2)
	if err != nil {
		t.Fatalf("decoding: %v", err)
	}
	parsed, err := ParseTime(parts[0])
	if err != nil {
		t.Fatalf("parsing the time: %v", err)
	}
	if !parsed.Equal(at) {
		t.Errorf("the time came back as %s, expected %s", parsed, at)
	}
	if parts[1] != "8a2f6c1e-0000-4000-8000-000000000001" {
		t.Errorf("the identifier came back as %q", parts[1])
	}
}

// TestEmptyCursorIsTheFirstPage: no cursor is not an error, it is the start.
func TestEmptyCursorIsTheFirstPage(t *testing.T) {
	parts, err := Decode("", 2)
	if err != nil || parts != nil {
		t.Errorf("an empty cursor gave %v, %v", parts, err)
	}
}

// TestForeignCursorIsRejected: a token that did not come from this panel is
// refused instead of being read as a key of nothing.
func TestForeignCursorIsRejected(t *testing.T) {
	for _, token := range []string{"not base64!", Encode("only-one-part")} {
		if _, err := Decode(token, 2); !errors.Is(err, ErrInvalidCursor) {
			t.Errorf("%q was accepted: %v", token, err)
		}
	}
}

func TestLimitIsBounded(t *testing.T) {
	if got := Limit(0, 100, 500); got != 100 {
		t.Errorf("no limit = %d, expected the default", got)
	}
	if got := Limit(900, 100, 500); got != 500 {
		t.Errorf("an oversized limit = %d, expected the maximum", got)
	}
	if got := Limit(42, 100, 500); got != 42 {
		t.Errorf("a plain limit = %d", got)
	}
}
