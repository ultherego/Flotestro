// Package paging encodes the cursors of keyset-paged lists.
package paging

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// ErrInvalidCursor means a cursor that did not come from this panel.
var ErrInvalidCursor = errors.New("invalid cursor")

// The parts used to be joined with a newline, under a comment saying that a
// newline cannot appear in a hostname, an identifier or a formatted timestamp
// and so needs no escaping. Two of the parts are neither: the certificate list
// pages by the path the host reported, and a path on Linux may hold a newline.
// A host could therefore put one in, the token would decode to one part too
// many, and the operator would be told "invalid cursor" and could not page past
// that row - a panel view broken by what a host reported about itself.
//
// Each part now carries its own length, so no content can be read as the
// structure around it. A cursor a caller is holding from before this change
// decodes to nothing and the list starts again from its first page; cursors
// live for a page turn, so that is the whole cost.
const cursorVersion byte = 2

// Encode renders the parts of a key as one URL-safe token. No parts is no
// cursor: the joined form spelled that as the empty string, which every caller
// reads as "there is no next page", and the length-prefixed form has to keep
// saying it.
func Encode(parts ...string) string {
	if len(parts) == 0 {
		return ""
	}
	out := []byte{cursorVersion}
	var word [4]byte
	binary.BigEndian.PutUint32(word[:], uint32(len(parts)))
	out = append(out, word[:]...)
	for _, part := range parts {
		binary.BigEndian.PutUint32(word[:], uint32(len(part)))
		out = append(out, word[:]...)
		out = append(out, part...)
	}
	return base64.RawURLEncoding.EncodeToString(out)
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
	if len(raw) < 5 || raw[0] != cursorVersion {
		return nil, fmt.Errorf("%w: not a cursor of this panel", ErrInvalidCursor)
	}
	count := int(binary.BigEndian.Uint32(raw[1:5]))
	if count != n {
		return nil, fmt.Errorf("%w: expected %d parts, got %d", ErrInvalidCursor, n, count)
	}
	parts := make([]string, 0, n)
	at := 5
	for index := 0; index < count; index++ {
		if at+4 > len(raw) {
			return nil, fmt.Errorf("%w: part %d has no length", ErrInvalidCursor, index+1)
		}
		size := int(binary.BigEndian.Uint32(raw[at : at+4]))
		at += 4
		if size < 0 || at+size > len(raw) {
			return nil, fmt.Errorf("%w: part %d runs past the token", ErrInvalidCursor, index+1)
		}
		parts = append(parts, string(raw[at:at+size]))
		at += size
	}
	if at != len(raw) {
		return nil, fmt.Errorf("%w: the token carries %d bytes nobody accounted for",
			ErrInvalidCursor, len(raw)-at)
	}
	return parts, nil
}

// FormatTime renders a timestamp for a cursor.
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

// Limit bounds a page size requested by a caller.
func Limit(requested, fallback, maximum int) int {
	if requested <= 0 {
		return fallback
	}
	if requested > maximum {
		return maximum
	}
	return requested
}
