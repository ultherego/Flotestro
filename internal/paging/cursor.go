// Package paging encodes the cursors of keyset-paged lists.
//
// A list of the fleet is paged by the key of its last row rather than by an
// offset: hosts enroll and tasks arrive while the operator browses, and an
// offset then skips rows or shows one twice. The key travels to the browser
// and back as one opaque string, so a screen does not have to know that the
// key of a task is a timestamp and an identifier.
package paging

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrInvalidCursor means a cursor that did not come from this panel.
var ErrInvalidCursor = errors.New("invalid cursor")

// separator joins the parts of a key. A newline cannot appear in a
// hostname, an identifier or a formatted timestamp, so it does not need
// escaping.
const separator = "\n"

// Encode renders the parts of a key as one URL-safe token.
func Encode(parts ...string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strings.Join(parts, separator)))
}

// Decode reads a token back into exactly n parts. An empty token is the
// first page and decodes to nil without an error.
func Decode(token string, n int) ([]string, error) {
	if token == "" {
		return nil, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCursor, err)
	}
	parts := strings.Split(string(raw), separator)
	if len(parts) != n {
		return nil, fmt.Errorf("%w: expected %d parts, got %d", ErrInvalidCursor, n, len(parts))
	}
	return parts, nil
}

// FormatTime renders a timestamp for a cursor. Nanoseconds keep the
// microsecond precision of the database column, so the row the cursor
// names compares equal to itself on the way back.
func FormatTime(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}

// ParseTime reads a timestamp written by FormatTime.
func ParseTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: %v", ErrInvalidCursor, err)
	}
	return parsed, nil
}

// Limit bounds a page size requested by a caller. A request without a
// limit gets the default; one asking for more than the maximum gets the
// maximum rather than an error, because the caller then pages on.
func Limit(requested, fallback, maximum int) int {
	if requested <= 0 {
		return fallback
	}
	if requested > maximum {
		return maximum
	}
	return requested
}
