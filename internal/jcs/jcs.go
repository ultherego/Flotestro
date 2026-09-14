// Package jcs renders JSON in the canonical form of RFC 8785, the JSON
// Canonicalization Scheme.
//
// A fingerprint is a hash over a document, and two sides compare it: the
// panel that recorded a consent and the agent that received the task, or
// the panel today and the panel after an upgrade. encoding/json is stable
// for a given struct, but it is not a contract: it keeps the declaration
// order of fields, escapes HTML characters and formats floats in its own
// way. None of that is what another implementation would produce. The
// canonical form is: object members sorted by the UTF-16 code units of
// their names, no whitespace, numbers as ECMAScript prints them, strings
// escaped only where the grammar requires it. Any implementation of the
// RFC produces the same bytes for the same document, so a hash over them
// is a hash over the document rather than over one library's habits.
package jcs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Canonical renders a value as canonical JSON.
//
// The value goes through encoding/json first, so struct tags, omitempty and
// custom marshalers keep their meaning; the result is then rendered anew in
// the canonical form. A json.RawMessage is taken as the document it holds.
// Numbers are IEEE 754 doubles, as the RFC requires: an integer beyond 2^53
// is rounded the way every JSON parser rounds it.
func Canonical(v any) ([]byte, error) {
	encoded, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return Transform(encoded)
}

// Transform renders a JSON text in its canonical form.
func Transform(raw []byte) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var tree any
	if err := decoder.Decode(&tree); err != nil {
		return nil, fmt.Errorf("jcs: %w", err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("jcs: the text carries more than one document")
	}
	var out bytes.Buffer
	if err := write(&out, tree); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func write(out *bytes.Buffer, value any) error {
	switch typed := value.(type) {
	case nil:
		out.WriteString("null")
	case bool:
		if typed {
			out.WriteString("true")
		} else {
			out.WriteString("false")
		}
	case json.Number:
		number, err := strconv.ParseFloat(typed.String(), 64)
		if err != nil {
			return fmt.Errorf("jcs: the number %q: %w", typed.String(), err)
		}
		formatted, err := FormatNumber(number)
		if err != nil {
			return err
		}
		out.WriteString(formatted)
	case string:
		writeString(out, typed)
	case []any:
		out.WriteByte('[')
		for i, item := range typed {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := write(out, item); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })
		out.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				out.WriteByte(',')
			}
			writeString(out, key)
			out.WriteByte(':')
			if err := write(out, typed[key]); err != nil {
				return err
			}
		}
		out.WriteByte('}')
	default:
		return fmt.Errorf("jcs: a value of type %T is not JSON", value)
	}
	return nil
}

// lessUTF16 orders two member names by their UTF-16 code units, the order
// the RFC prescribes. It is the order of the code points for the Basic
// Multilingual Plane; a supplementary character sorts by its surrogates,
// so an emoji comes before U+FB33 although its code point is higher.
func lessUTF16(a, b string) bool {
	if isASCII(a) && isASCII(b) {
		return a < b
	}
	left, right := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(left) && i < len(right); i++ {
		if left[i] != right[i] {
			return left[i] < right[i]
		}
	}
	return len(left) < len(right)
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// writeString escapes a string the way RFC 8785 section 3.2.2.2 requires:
// the quotation mark, the reverse solidus and the control characters below
// U+0020, the latter with their short forms where JSON has them and with a
// lowercase \u00xx otherwise. Everything else, non-ASCII included, is
// written as it is.
func writeString(out *bytes.Buffer, s string) {
	out.WriteByte('"')
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x20 && c != '"' && c != '\\' {
			continue
		}
		out.WriteString(s[start:i])
		switch c {
		case '"':
			out.WriteString(`\"`)
		case '\\':
			out.WriteString(`\\`)
		case '\b':
			out.WriteString(`\b`)
		case '\t':
			out.WriteString(`\t`)
		case '\n':
			out.WriteString(`\n`)
		case '\f':
			out.WriteString(`\f`)
		case '\r':
			out.WriteString(`\r`)
		default:
			out.WriteString(`\u00`)
			out.WriteByte(hexDigits[c>>4])
			out.WriteByte(hexDigits[c&0xf])
		}
		start = i + 1
	}
	out.WriteString(s[start:])
	out.WriteByte('"')
}

const hexDigits = "0123456789abcdef"

// FormatNumber prints a double the way ECMAScript's Number::toString does,
// which is what the RFC prescribes for numbers: the shortest digits that
// read back as the same value, plain for magnitudes from 1e-6 up to 1e21,
// with an exponent outside that range. NaN and the infinities are not JSON
// and are refused; a negative zero prints as 0.
func FormatNumber(f float64) (string, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", fmt.Errorf("jcs: %v is not a JSON number", f)
	}
	if f == 0 {
		return "0", nil
	}
	if f < 0 {
		positive, err := FormatNumber(-f)
		return "-" + positive, err
	}
	// The shortest round-trip digits and the decimal exponent come from
	// the 'e' format: d.ddde±xx. With k digits and the value s × 10^(n-k)
	// the exponent n of the specification is the printed one plus one.
	shortest := strconv.FormatFloat(f, 'e', -1, 64)
	mantissa, exponent, _ := strings.Cut(shortest, "e")
	digits := strings.Replace(mantissa, ".", "", 1)
	printed, err := strconv.Atoi(exponent)
	if err != nil {
		return "", fmt.Errorf("jcs: the exponent of %v: %w", f, err)
	}
	k, n := len(digits), printed+1

	switch {
	case k <= n && n <= 21:
		return digits + strings.Repeat("0", n-k), nil
	case 0 < n && n <= 21:
		return digits[:n] + "." + digits[n:], nil
	case -6 < n && n <= 0:
		return "0." + strings.Repeat("0", -n) + digits, nil
	}
	sign := "+"
	if n-1 < 0 {
		sign = "-"
	}
	magnitude := strconv.Itoa(absInt(n - 1))
	if k == 1 {
		return digits + "e" + sign + magnitude, nil
	}
	return digits[:1] + "." + digits[1:] + "e" + sign + magnitude, nil
}

func absInt(value int) int {
	if value < 0 {
		return -value
	}
	return value
}
