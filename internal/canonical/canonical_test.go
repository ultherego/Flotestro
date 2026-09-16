package canonical

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// The vectors are the public contract of the library: the panel, the agent
// and the helper all have to produce these bytes and these digests for
// these documents, and another implementation of the scheme has to as
// well. A vector that stops matching is a change of the contract, not a
// detail of the library.
type vectorFile struct {
	Documents []struct {
		Name      string `json:"name"`
		Input     string `json:"input"`
		Canonical string `json:"canonical"`
		SHA256    string `json:"sha256"`
	} `json:"documents"`
	Envelopes []struct {
		Name      string   `json:"name"`
		Envelope  Envelope `json:"envelope"`
		Canonical string   `json:"canonical"`
		SHA256    string   `json:"sha256"`
	} `json:"envelopes"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatalf("reading the vectors: %v", err)
	}
	var vectors vectorFile
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("decoding the vectors: %v", err)
	}
	if len(vectors.Documents) == 0 || len(vectors.Envelopes) == 0 {
		t.Fatal("the vector file is empty")
	}
	return vectors
}

func TestDocumentVectors(t *testing.T) {
	for _, vector := range loadVectors(t).Documents {
		t.Run(vector.Name, func(t *testing.T) {
			digest, normalized, err := SHA256(json.RawMessage(vector.Input))
			if err != nil {
				t.Fatalf("SHA256: %v", err)
			}
			if string(normalized) != vector.Canonical {
				t.Errorf("canonical form:\n got %s\nwant %s", normalized, vector.Canonical)
			}
			if got := hex.EncodeToString(digest[:]); got != vector.SHA256 {
				t.Errorf("digest: got %s, want %s", got, vector.SHA256)
			}
		})
	}
}

func TestEnvelopeVectors(t *testing.T) {
	for _, vector := range loadVectors(t).Envelopes {
		t.Run(vector.Name, func(t *testing.T) {
			digest, normalized, err := vector.Envelope.SHA256()
			if err != nil {
				t.Fatalf("SHA256: %v", err)
			}
			if string(normalized) != vector.Canonical {
				t.Errorf("canonical form:\n got %s\nwant %s", normalized, vector.Canonical)
			}
			if got := hex.EncodeToString(digest[:]); got != vector.SHA256 {
				t.Errorf("digest: got %s, want %s", got, vector.SHA256)
			}
		})
	}
}

// A zero envelope, an envelope with a nil payload, one with an empty
// document and one with "null" are the same thing and hash the same. The
// first vector of the file is exactly that document, so the digest is also
// pinned against it.
func TestEmptyPayloadHasOneCanonicalForm(t *testing.T) {
	variants := map[string]Envelope{
		"zero":  {},
		"nil":   {Payload: nil},
		"empty": {Payload: json.RawMessage("{}")},
		"blank": {Payload: json.RawMessage("  ")},
		"null":  {Payload: json.RawMessage("null")},
	}
	reference, _, err := Envelope{}.SHA256()
	if err != nil {
		t.Fatal(err)
	}
	for name, variant := range variants {
		digest, normalized, err := variant.SHA256()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if digest != reference {
			t.Errorf("%s hashes differently: %s", name, normalized)
		}
	}
	want := loadVectors(t).Envelopes[0]
	if want.Name != "zero envelope" {
		t.Fatalf("the first envelope vector is %q, expected the zero envelope", want.Name)
	}
	if hex.EncodeToString(reference[:]) != want.SHA256 {
		t.Errorf("the zero envelope digest %x differs from the vector %s", reference, want.SHA256)
	}
}

// The digest is the digest of the canonical bytes and nothing else: the
// same document spelled twice gives one digest, and the bytes returned are
// what was hashed.
func TestSpellingDoesNotChangeTheDigest(t *testing.T) {
	first, firstBytes, err := SHA256(json.RawMessage(`{"b":2,"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := SHA256(map[string]int{"a": 1, "b": 2})
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Errorf("the two spellings hash differently")
	}
	if sha256.Sum256(firstBytes) != first {
		t.Errorf("the returned bytes are not what was hashed")
	}
	same, err := Equal(json.RawMessage(`{"b":2,"a":1}`), map[string]int{"a": 1, "b": 2})
	if err != nil || !same {
		t.Errorf("Equal = %v, %v", same, err)
	}
}

// A value that is not a JSON document is refused rather than hashed as
// something else.
func TestInvalidDocumentIsRefused(t *testing.T) {
	if _, _, err := SHA256(json.RawMessage(`{"a":`)); err == nil {
		t.Error("a truncated document was hashed")
	}
	if _, _, err := SHA256(make(chan int)); err == nil {
		t.Error("an unencodable value was hashed")
	}
}
