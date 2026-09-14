package jcs

import (
	"bytes"
	"encoding/json"
	"math"
	"math/rand"
	"strconv"
	"strings"
	"testing"
)

// TestNumbersFollowTheRFCTable checks the number vectors of RFC 8785,
// appendix B: the IEEE 754 bit patterns and the text the RFC prints them as.
func TestNumbersFollowTheRFCTable(t *testing.T) {
	vectors := []struct {
		bits uint64
		want string
	}{
		{0x0000000000000000, "0"},
		{0x8000000000000000, "0"},
		{0x0000000000000001, "5e-324"},
		{0x8000000000000001, "-5e-324"},
		{0x7fefffffffffffff, "1.7976931348623157e+308"},
		{0xffefffffffffffff, "-1.7976931348623157e+308"},
		{0x4340000000000000, "9007199254740992"},
		{0xc340000000000000, "-9007199254740992"},
		{0x4430000000000000, "295147905179352830000"},
		{0x44b52d02c7e14af5, "9.999999999999997e+22"},
		{0x44b52d02c7e14af6, "1e+23"},
		{0x44b52d02c7e14af7, "1.0000000000000001e+23"},
		{0x444b1ae4d6e2ef4e, "999999999999999700000"},
		{0x444b1ae4d6e2ef4f, "999999999999999900000"},
		{0x444b1ae4d6e2ef50, "1e+21"},
		{0x3eb0c6f7a0b5ed8c, "9.999999999999997e-7"},
		{0x3eb0c6f7a0b5ed8d, "0.000001"},
		{0x41b3de4355555553, "333333333.3333332"},
		{0x41b3de4355555554, "333333333.33333325"},
		{0x41b3de4355555555, "333333333.3333333"},
		{0x41b3de4355555556, "333333333.3333334"},
		{0x41b3de4355555557, "333333333.33333343"},
		{0xbecbf647612f3696, "-0.0000033333333333333333"},
		{0x43143ff3c1cb0959, "1424953923781206.2"},
	}
	for _, vector := range vectors {
		got, err := FormatNumber(math.Float64frombits(vector.bits))
		if err != nil {
			t.Errorf("%016x: %v", vector.bits, err)
			continue
		}
		if got != vector.want {
			t.Errorf("%016x: got %s, the RFC prints %s", vector.bits, got, vector.want)
		}
	}
	for _, bits := range []uint64{0x7fffffffffffffff, 0x7ff0000000000000, 0xfff0000000000000} {
		if _, err := FormatNumber(math.Float64frombits(bits)); err == nil {
			t.Errorf("%016x is not a JSON number and was printed", bits)
		}
	}
}

// TestStringsAreEscapedAsTheRFCRequires checks section 3.2.2.2: only the
// quotation mark, the reverse solidus and the controls are escaped, the
// controls with their short forms where JSON has them and as lowercase
// \u00xx otherwise; everything above U+001F is written as it is.
func TestStringsAreEscapedAsTheRFCRequires(t *testing.T) {
	vectors := []struct {
		in   string
		want string
	}{
		{"", `""`},
		{`"`, `"\""`},
		{`\`, `"\\"`},
		{"\b\t\n\f\r", `"\b\t\n\f\r"`},
		{"\x00\x01\x1f", `"\u0000\u0001\u001f"`},
		{"\x0b\x0f\x10\x1e", `"\u000b\u000f\u0010\u001e"`},
		{"/", `"/"`},
		{"<>&'", `"<>&'"`},
		{"\x7f", "\"\x7f\""},
		{"\u0080\u00f6", "\"\u0080\u00f6\""},
		{"\u2028\u2029", "\"\u2028\u2029\""},
		{"\u20ac", "\"\u20ac\""},
		{"\U0001F600", "\"\U0001F600\""},
		// The string of the RFC's appendix A document, after JSON parsing.
		{"\u20ac$\u000f\nA'B\"\\\\\"/", "\"\u20ac$\\u000f\\nA'B\\\"\\\\\\\\\\\"/\""},
	}
	for _, vector := range vectors {
		got, err := Canonical(vector.in)
		if err != nil {
			t.Errorf("%q: %v", vector.in, err)
			continue
		}
		if string(got) != vector.want {
			t.Errorf("%q: got %s, want %s", vector.in, got, vector.want)
		}
	}
}

// TestTheAppendixDocumentCanonicalises is the sample of appendix A: the
// whole document of the RFC rendered as the RFC renders it.
func TestTheAppendixDocumentCanonicalises(t *testing.T) {
	input := `{
  "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
  "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
  "literals": [null, true, false]
}`
	want := "{\"literals\":[null,true,false]," +
		"\"numbers\":[333333333.3333333,1e+30,4.5,0.002,1e-27]," +
		"\"string\":\"\u20ac$\\u000f\\nA'B\\\"\\\\\\\\\\\"/\"}"
	got, err := Transform([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	// The same document handed in as a raw message goes the same way.
	again, err := Canonical(json.RawMessage(input))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again, got) {
		t.Fatalf("a raw message rendered differently: %s", again)
	}
}

// TestKeysSortByUTF16CodeUnits is the sorting sample of section 3.2.3: the
// emoji, a supplementary character, comes before U+FB33 because its
// surrogates are smaller, although its code point is larger.
func TestKeysSortByUTF16CodeUnits(t *testing.T) {
	input := `{
  "\u20ac": "Euro Sign",
  "\r": "Carriage Return",
  "\ufb33": "Hebrew Letter Dalet With Dagesh",
  "1": "One",
  "\ud83d\ude00": "Emoji: Grinning Face",
  "\u0080": "Control",
  "\u00f6": "Latin Small Letter O With Diaeresis"
}`
	want := "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u0080\":\"Control\"," +
		"\"\u00f6\":\"Latin Small Letter O With Diaeresis\",\"\u20ac\":\"Euro Sign\"," +
		"\"\U0001F600\":\"Emoji: Grinning Face\",\"\ufb33\":\"Hebrew Letter Dalet With Dagesh\"}"
	got, err := Transform([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

// TestStructsKeepTheirTagsAndSortTheirFields: a struct goes through
// encoding/json first, so the tags decide the names and omitempty decides
// the presence; the canonical form then orders what came out.
func TestStructsKeepTheirTagsAndSortTheirFields(t *testing.T) {
	type inner struct {
		Zulu  int     `json:"zulu"`
		Alpha string  `json:"alpha"`
		Skip  string  `json:"skip,omitempty"`
		Ratio float64 `json:"ratio"`
	}
	value := struct {
		B     inner          `json:"b"`
		A     []int          `json:"a"`
		M     map[string]any `json:"m"`
		Empty *inner         `json:"empty,omitempty"`
	}{
		B: inner{Zulu: 1, Alpha: "x", Ratio: 0.5},
		A: []int{3, 1, 2},
		M: map[string]any{"y": nil, "x": 1e21, "w": 100},
	}
	got, err := Canonical(value)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":[3,1,2],"b":{"alpha":"x","ratio":0.5,"zulu":1},"m":{"w":100,"x":1e+21,"y":null}}`
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestMoreThanOneDocumentIsRefused(t *testing.T) {
	if _, err := Transform([]byte(`{} {}`)); err == nil {
		t.Fatal("two documents were accepted as one")
	}
	if _, err := Transform([]byte(`{"a":1`)); err == nil {
		t.Fatal("a broken document was accepted")
	}
	if _, err := Canonical(map[string]any{"nan": math.NaN()}); err == nil {
		t.Fatal("NaN was accepted as a number")
	}
	if _, err := Transform([]byte(` {"a" : 1 } `)); err != nil {
		t.Fatalf("surrounding whitespace was refused: %v", err)
	}
}

// TestCanonicalIsStableAndIdempotent renders random documents: the same
// document rendered twice gives the same bytes, and the canonical text
// parsed and rendered again is unchanged.
func TestCanonicalIsStableAndIdempotent(t *testing.T) {
	random := rand.New(rand.NewSource(8785))
	for i := 0; i < 500; i++ {
		document := randomValue(random, 0)
		first, err := Canonical(document)
		if err != nil {
			t.Fatalf("document %d: %v", i, err)
		}
		second, err := Canonical(document)
		if err != nil {
			t.Fatalf("document %d again: %v", i, err)
		}
		if !bytes.Equal(first, second) {
			t.Fatalf("document %d rendered differently twice:\n%s\n%s", i, first, second)
		}
		// canonical(parse(canonical(x))) == canonical(x)
		var parsed any
		decoder := json.NewDecoder(bytes.NewReader(first))
		decoder.UseNumber()
		if err := decoder.Decode(&parsed); err != nil {
			t.Fatalf("document %d: the canonical text does not parse: %v\n%s", i, err, first)
		}
		third, err := Canonical(parsed)
		if err != nil {
			t.Fatalf("document %d reparsed: %v", i, err)
		}
		if !bytes.Equal(first, third) {
			t.Fatalf("document %d is not a fixed point:\n%s\n%s", i, first, third)
		}
		// The canonical text has no whitespace outside strings and every
		// number in it reads back as the same double.
		if bytes.Contains(stripStrings(first), []byte(" ")) || bytes.Contains(stripStrings(first), []byte("\n")) {
			t.Fatalf("document %d carries whitespace: %s", i, first)
		}
	}
}

// TestNumbersRoundTrip checks the number format on random doubles: the
// printed text parses back to the same value, and integers below 2^53 are
// printed plain.
func TestNumbersRoundTrip(t *testing.T) {
	random := rand.New(rand.NewSource(1))
	for i := 0; i < 10000; i++ {
		value := math.Float64frombits(random.Uint64())
		if math.IsNaN(value) || math.IsInf(value, 0) {
			continue
		}
		text, err := FormatNumber(value)
		if err != nil {
			t.Fatal(err)
		}
		back, err := strconv.ParseFloat(text, 64)
		if err != nil {
			t.Fatalf("%v printed as %q, which does not parse: %v", value, text, err)
		}
		if back != value && !(value == 0 && back == 0) {
			t.Fatalf("%v printed as %q, which reads back as %v", value, text, back)
		}
		if strings.Contains(text, "E") || strings.Contains(text, "e+0") || strings.Contains(text, "e-0") {
			t.Fatalf("%v printed as %q", value, text)
		}
	}
	for _, integer := range []int64{1, -1, 42, 1000000, 1 << 53, -(1 << 53), 123456789012345} {
		text, err := FormatNumber(float64(integer))
		if err != nil {
			t.Fatal(err)
		}
		if text != strconv.FormatInt(integer, 10) {
			t.Errorf("%d printed as %s", integer, text)
		}
	}
}

// randomValue builds a random JSON value of bounded depth.
func randomValue(random *rand.Rand, depth int) any {
	kind := random.Intn(7)
	if depth > 3 && kind >= 5 {
		kind = random.Intn(5)
	}
	switch kind {
	case 0:
		return nil
	case 1:
		return random.Intn(2) == 1
	case 2:
		return randomNumber(random)
	case 3:
		return randomString(random)
	case 4:
		return float64(random.Int63n(1<<53) - 1<<52)
	case 5:
		count := random.Intn(5)
		list := make([]any, 0, count)
		for i := 0; i < count; i++ {
			list = append(list, randomValue(random, depth+1))
		}
		return list
	default:
		count := random.Intn(5)
		object := map[string]any{}
		for i := 0; i < count; i++ {
			object[randomString(random)] = randomValue(random, depth+1)
		}
		return object
	}
}

func randomNumber(random *rand.Rand) float64 {
	for {
		value := math.Float64frombits(random.Uint64())
		if !math.IsNaN(value) && !math.IsInf(value, 0) {
			return value
		}
	}
}

// randomString draws from the characters that exercise the escaping and
// the sorting: controls, the quotation mark, the reverse solidus, ASCII,
// characters of the BMP above the surrogates and a supplementary one.
func randomString(random *rand.Rand) string {
	alphabet := []rune{'a', 'z', 'A', '0', '9', ' ', '"', '\\', '/', '\n', '\t', '\x01', '\x1f',
		'\x7f', '\u0080', '\u00f6', '\u20ac', '\u2028', '\ufb33', '\U0001F600', '<', '&'}
	length := random.Intn(6)
	var out strings.Builder
	for i := 0; i < length; i++ {
		out.WriteRune(alphabet[random.Intn(len(alphabet))])
	}
	return out.String()
}

// stripStrings blanks the string literals of a canonical text, so a check
// for whitespace looks at the structure alone.
func stripStrings(text []byte) []byte {
	out := make([]byte, 0, len(text))
	inString, escaped := false, false
	for _, c := range text {
		switch {
		case escaped:
			escaped = false
		case inString && c == '\\':
			escaped = true
		case c == '"':
			inString = !inString
			out = append(out, c)
		case !inString:
			out = append(out, c)
		}
	}
	return out
}
