// Package canonical is the one library every side of Flotestro hashes
// documents with: the panel that records a consent, the agent that checks
// a task against it, and the root helper that checks a capability against
// the payload it carries. A digest compared across a trust boundary is only
// worth something when both sides computed it over the same bytes, and the
// bytes here are the canonical JSON of RFC 8785 - so the digest depends on
// the document alone, never on which implementation, in which language,
// printed it.
//
// A schema change never changes a digest quietly: it raises the schema
// version of the envelope and keeps the verifier of the previous version
// for the length of the migration. A hash is not an authorization either;
// where it crosses a trust boundary it travels inside a signed capability
// bound to a nonce and an expiry (package helpercap).
package canonical

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/ultherego/flotestro/internal/jcs"
)

// SchemaVersion is the layout version of the envelope this release writes.
const SchemaVersion uint32 = 1

// Envelope is the versioned document under a digest: what kind of thing is
// hashed, which one, at which revision, and its content.
type Envelope struct {
	SchemaVersion uint32          `json:"schema_version"`
	Kind          string          `json:"kind"`
	SubjectID     string          `json:"subject_id"`
	Revision      uint64          `json:"revision"`
	Payload       json.RawMessage `json:"payload"`
}

// emptyObject is the one canonical form of "no content". A zero envelope
// and an envelope whose payload is an empty document hash the same: the
// two describe the same thing, and a digest that told them apart was the
// cause of a payload_hash_mismatch nobody could explain.
var emptyObject = json.RawMessage("{}")

// Normalized returns the envelope with its payload in the one form an
// absent payload takes.
func (e Envelope) Normalized() Envelope {
	if len(bytes.TrimSpace(e.Payload)) == 0 || bytes.Equal(bytes.TrimSpace(e.Payload), []byte("null")) {
		e.Payload = emptyObject
	}
	return e
}

// SHA256 returns the digest of the envelope over its canonical bytes.
func (e Envelope) SHA256() ([32]byte, []byte, error) {
	return SHA256(e.Normalized())
}

// NormalizeRFC8785 renders a value as the canonical JSON of RFC 8785: the
// members sorted by the UTF-16 code units of their names, no whitespace,
// numbers as ECMAScript prints them, strings escaped only where the
// grammar requires it. The value goes through encoding/json first, so
// struct tags and custom marshalers keep their meaning; a json.RawMessage
// is taken as the document it holds and canonicalized again.
func NormalizeRFC8785(v any) ([]byte, error) {
	normalized, err := jcs.Canonical(v)
	if err != nil {
		return nil, fmt.Errorf("canonical: %w", err)
	}
	return normalized, nil
}

// SHA256 returns the digest of a value over its canonical bytes, together
// with the bytes, so a caller that stores or signs the document keeps
// exactly what was hashed.
func SHA256(v any) ([32]byte, []byte, error) {
	normalized, err := NormalizeRFC8785(v)
	if err != nil {
		return [32]byte{}, nil, err
	}
	return sha256.Sum256(normalized), normalized, nil
}

// Equal says whether two documents are the same document, whatever their
// spelling: the comparison is over the canonical bytes.
func Equal(a, b any) (bool, error) {
	left, err := NormalizeRFC8785(a)
	if err != nil {
		return false, err
	}
	right, err := NormalizeRFC8785(b)
	if err != nil {
		return false, err
	}
	return bytes.Equal(left, right), nil
}
