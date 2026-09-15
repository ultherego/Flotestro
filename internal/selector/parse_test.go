package selector

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// TestParseReadsTheTextForm: every key, the operators and the
// combinators come out as the structure a JSON selector would have, so
// the text form and the typed form compile to the same SQL.
func TestParseReadsTheTextForm(t *testing.T) {
	cases := []struct {
		name string
		text string
		want string
	}{
		{"one condition", `site = warsaw`, `{"site":"warsaw"}`},
		{"no spaces", `site=warsaw`, `{"site":"warsaw"}`},
		{"tag keeps its own equals sign", `tag=role=db`, `{"tag":"role=db"}`},
		{"tag with spaces around", `tag = role=db`, `{"tag":"role=db"}`},
		{"not equal is a negation", `environment != prod`, `{"not":{"environment":"prod"}}`},
		{"double equals", `os == debian`, `{"os_family":"debian"}`},
		{"aliases", `env = prod and connection = online and lifecycle = active and release_channel = beta`,
			`{"all":[{"environment":"prod"},{"connection_state":"online"},{"lifecycle_state":"active"},{"channel":"beta"}]}`},
		{"keys in any case", `SITE = warsaw AND Tag = role`, `{"all":[{"site":"warsaw"},{"tag":"role"}]}`},
		{"and binds tighter than or", `site = a or site = b and tag = x`,
			`{"any":[{"site":"a"},{"all":[{"site":"b"},{"tag":"x"}]}]}`},
		{"parentheses override", `(site = a or site = b) and tag = x`,
			`{"all":[{"any":[{"site":"a"},{"site":"b"}]},{"tag":"x"}]}`},
		{"not binds to one condition", `not site = a and tag = x`,
			`{"all":[{"not":{"site":"a"}},{"tag":"x"}]}`},
		{"not over a group", `not (site = a or site = b)`,
			`{"not":{"any":[{"site":"a"},{"site":"b"}]}}`},
		{"double negation", `not not site = a`, `{"not":{"not":{"site":"a"}}}`},
		{"quoted value", `owner = "platform team"`, `{"owner":"platform team"}`},
		{"quoted value with an escaped quote", `owner = "the \"core\" team"`, `{"owner":"the \"core\" team"}`},
		{"health facts", `security_updates = true and reboot_required = false and failed_units = true`,
			`{"all":[{"security_updates":"true"},{"reboot_required":"false"},{"failed_units":"true"}]}`},
		{"version older than", `agent_version < 0.49.0`, `{"agent_version":"< 0.49.0"}`},
		{"version at most, no spaces", `agent_version<=0.49.0`, `{"agent_version":"<= 0.49.0"}`},
		{"version at least", `agent_version >= 0.49.0`, `{"agent_version":">= 0.49.0"}`},
		{"version newer than", `agent_version > v0.48.2`, `{"agent_version":"> v0.48.2"}`},
		{"version equal", `agent_version = 0.49.0`, `{"agent_version":"0.49.0"}`},
		{"version not equal", `agent_version != 0.49.0`, `{"not":{"agent_version":"0.49.0"}}`},
		{"os version prefix", `os_version = 12`, `{"os_version":"12"}`},
		{"relay and failure domain", `relay = edge-1 and failure_domain = rack-7`,
			`{"all":[{"relay":"edge-1"},{"failure_domain":"rack-7"}]}`},
		{"group and capability", `group = databases and capability = packages.apt`,
			`{"all":[{"group":"databases"},{"capability":"packages.apt"}]}`},
		{"a value that spells a key", `owner = site and tag = x`,
			`{"all":[{"owner":"site"},{"tag":"x"}]}`},
		{"the description of a selector parses back", `(site=warsaw and not tag=role=db)`,
			`{"all":[{"site":"warsaw"},{"not":{"tag":"role=db"}}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Parse(tc.text)
			if err != nil {
				t.Fatalf("parse %q: %v", tc.text, err)
			}
			// The encoder escapes < and > for HTML; the comparison is on
			// the decoded shape, not on the bytes.
			var want, have any
			if err := json.Unmarshal([]byte(tc.want), &want); err != nil {
				t.Fatalf("the expectation does not decode: %v", err)
			}
			encoded, _ := json.Marshal(got)
			_ = json.Unmarshal(encoded, &have)
			if !reflect.DeepEqual(have, want) {
				t.Errorf("parse %q = %s, expected %s", tc.text, encoded, tc.want)
			}
		})
	}
}

// TestParseRefusesWhatDoesNotParse: a text that does not hold together
// is refused as a syntax error naming the place, and one that parses
// into a selector no host can match is refused as an invalid selector -
// both are ErrInvalid to a handler.
func TestParseRefusesWhatDoesNotParse(t *testing.T) {
	syntax := map[string]string{
		"empty":                   ``,
		"only spaces":             `   `,
		"unknown key":             `colour = blue`,
		"missing operator":        `site warsaw`,
		"missing value":           `site =`,
		"missing right side":      `site = a and`,
		"missing left side":       `and site = a`,
		"two conditions in a row": `site = a site = b`,
		"unclosed parenthesis":    `(site = a`,
		"stray parenthesis":       `site = a)`,
		"unclosed quote":          `owner = "platform`,
		"ordering a site":         `site < warsaw`,
		"ordering a tag":          `tag >= role`,
		"operator alone":          `site = = a`,
		"bad operator":            `site => a`,
		"bare not":                `not`,
	}
	for name, text := range syntax {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(text)
			if !errors.Is(err, ErrSyntax) {
				t.Fatalf("%q parsed: %v", text, err)
			}
			if !errors.Is(err, ErrInvalid) {
				t.Errorf("a syntax error is not an invalid selector: %v", err)
			}
		})
	}

	// Values the grammar reads but no host can carry go through the same
	// validation as a JSON selector.
	invalid := map[string]string{
		"boolean spelled yes": `security_updates = yes`,
		"unknown state":       `connection = sleeping`,
		"unknown lifecycle":   `lifecycle = parked`,
		"unknown channel":     `channel = nightly`,
		"upper-case tag":      `tag = Role=db`,
		"version word":        `agent_version < latest`,
		"version prerelease":  `agent_version >= 0.49.0-rc1`,
		"too long":            `site = ` + strings.Repeat("x", maxValue+1),
	}
	for name, text := range invalid {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(text)
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("%q parsed: %v", text, err)
			}
			if errors.Is(err, ErrSyntax) {
				t.Errorf("a value no host can carry is not a syntax error: %v", err)
			}
		})
	}
}

// TestParseNamesThePlace: the error says which word and where, so the
// panel can point at it.
func TestParseNamesThePlace(t *testing.T) {
	_, err := Parse(`site = warsaw and colour = blue`)
	if err == nil || !strings.Contains(err.Error(), `"colour" at 18`) {
		t.Errorf("the error does not name the word and the place: %v", err)
	}
	_, err = Parse(`tag = role >= 2`)
	if err == nil || !strings.Contains(err.Error(), `unexpected ">="`) {
		t.Errorf("the error does not name the stray operator: %v", err)
	}
}

// TestParseCompilesLikeJSON: what the text form produces is the same
// tree a JSON selector would carry, down to the SQL.
func TestParseCompilesLikeJSON(t *testing.T) {
	fromText, err := Parse(`site = warsaw and (tag = role=db or not environment = prod) and agent_version < 0.49.0`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	fromJSON := parse(t, `{"all":[{"site":"warsaw"},{"any":[{"tag":"role=db"},{"not":{"environment":"prod"}}]},{"agent_version":"< 0.49.0"}]}`)
	sqlText, argsText, err := Compile(fromText, 0)
	if err != nil {
		t.Fatalf("compile the parsed selector: %v", err)
	}
	sqlJSON, argsJSON, err := Compile(fromJSON, 0)
	if err != nil {
		t.Fatalf("compile the JSON selector: %v", err)
	}
	if sqlText != sqlJSON {
		t.Errorf("the text form compiles to %q, the JSON form to %q", sqlText, sqlJSON)
	}
	if len(argsText) != len(argsJSON) {
		t.Errorf("the text form has %d arguments, the JSON form %d", len(argsText), len(argsJSON))
	}
}

// TestKeysNameEveryLeaf: the catalogue the panel suggests from names
// every leaf field the selector has, group references excepted, so a key
// added to the structure is not missing from the grammar.
func TestKeysNameEveryLeaf(t *testing.T) {
	e := &Expression{}
	for _, fact := range e.leaves() {
		if fact.name == "group_id" {
			continue
		}
		if keyByName(fact.name) == nil {
			t.Errorf("the leaf %s has no key in the grammar", fact.name)
		}
	}
	for _, key := range Keys {
		var probe Expression
		probe.set(key.Name, "x")
		found := false
		for _, fact := range probe.leaves() {
			if fact.name == key.Name && fact.value == "x" {
				found = true
			}
		}
		if !found {
			t.Errorf("the key %s sets no leaf", key.Name)
		}
	}
}
