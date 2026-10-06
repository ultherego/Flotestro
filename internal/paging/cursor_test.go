package paging

import (
	"encoding/base64"
	"errors"
	"strings"
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

// A part holding the old separator used to make the token decode to one part
// too many, and the caller was told the cursor was invalid. The certificate
// list pages by the path a host reported, and a path on Linux may hold a
// newline, so a host could break that list's paging.
func TestAPartHoldingTheOldSeparatorStillRoundTrips(t *testing.T) {
	cases := [][]string{
		{"2026-10-06T00:00:00Z", "agent-debian", "/etc/ssl/certs/odd\nname.pem"},
		{"a\nb", "c", "d"},
		{"", "", ""},
		{"\n\n\n", "x"},
		{strings.Repeat("p", 4096), "q"},
	}
	for _, parts := range cases {
		back, err := Decode(Encode(parts...), len(parts))
		if err != nil {
			t.Errorf("%q did not decode: %v", parts, err)
			continue
		}
		if len(back) != len(parts) {
			t.Errorf("%q came back as %q", parts, back)
			continue
		}
		for index := range parts {
			if back[index] != parts[index] {
				t.Errorf("part %d of %q came back as %q", index, parts, back[index])
			}
		}
	}
}

// And a token nobody encoded here is refused rather than read as parts.
func TestATokenThisPanelDidNotWriteIsRefused(t *testing.T) {
	for name, token := range map[string]string{
		"the old joined form":   base64.RawURLEncoding.EncodeToString([]byte("a\nb")),
		"a truncated length":    base64.RawURLEncoding.EncodeToString([]byte{2, 0, 0, 0, 2, 0, 0}),
		"a part past the end":   base64.RawURLEncoding.EncodeToString([]byte{2, 0, 0, 0, 1, 0, 0, 0, 9, 'a'}),
		"bytes nobody counted":  base64.RawURLEncoding.EncodeToString([]byte{2, 0, 0, 0, 1, 0, 0, 0, 1, 'a', 'b'}),
		"another panel's shape": base64.RawURLEncoding.EncodeToString([]byte{7, 0, 0, 0, 1, 0, 0, 0, 1, 'a'}),
		"not base64":            "!!!!",
	} {
		if _, err := Decode(token, 2); err == nil {
			t.Errorf("%s was accepted as a cursor of two parts", name)
		}
	}
}

// No parts is no cursor, which is what every caller reads as "no next page".
// The joined form spelled it as the empty string and this has to keep doing so.
func TestNoPartsIsNoCursor(t *testing.T) {
	if token := Encode(); token != "" {
		t.Errorf("a cursor of no parts is %q and not the empty string", token)
	}
	parts, err := Decode("", 0)
	if err != nil || parts != nil {
		t.Errorf("the empty token decoded to %q (%v)", parts, err)
	}
}
