package jcs

import (
	"bytes"
	"encoding/json"
	"testing"
)

// FuzzTransform feeds the canonicaliser arbitrary text.
//
// The canonical form is what gets signed and what the audit chain hashes,
// so two properties matter: a text that is accepted comes out as valid
// JSON, and the canonical form is a fixed point - canonicalising it again
// changes nothing. Anything else is refused with an error, never a panic.
func FuzzTransform(f *testing.F) {
	f.Add([]byte(`{
  "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
  "string": "€$
A'B"\\\\"\/",
  "literals": [null, true, false]
}`))
	f.Add([]byte(`{
  "€": "Euro Sign",
  "\r": "Carriage Return",
  "דּ": "Hebrew Letter Dalet With Dagesh",
  "1": "One",
  "😀": "Emoji: Grinning Face",
  "": "Control",
  "ö": "Latin Small Letter O With Diaeresis"
}`))
	f.Add([]byte(`{} {}`))
	f.Add([]byte(`{"a":1`))
	f.Add([]byte(` {"a" : 1 } `))
	f.Add([]byte(`[1e400]`))
	f.Add([]byte(`[-0, 0.0, 5e-324, 9007199254740993, 1e21]`))
	f.Add([]byte(`"\udc00"`))
	f.Add([]byte(`{"a":{"b":{"c":[[[[]]]]}}}`))
	f.Add([]byte(``))

	f.Fuzz(func(t *testing.T, raw []byte) {
		canonical, err := Transform(raw)
		if err != nil {
			return
		}
		if !json.Valid(canonical) {
			t.Fatalf("the canonical form is not JSON: %q", canonical)
		}
		again, err := Transform(canonical)
		if err != nil {
			t.Fatalf("the canonical form is refused on a second pass: %v (%q)", err, canonical)
		}
		if !bytes.Equal(canonical, again) {
			t.Fatalf("the canonical form is not a fixed point:\n%q\n%q", canonical, again)
		}
	})
}
