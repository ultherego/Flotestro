package selector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// fakeGroups is a group directory in memory for the expander.
type fakeGroups map[string]*Group

func (f fakeGroups) Lookup(_ context.Context, ref string) (*Group, error) {
	for _, group := range f {
		if group.ID == ref || group.Name == ref {
			return group, nil
		}
	}
	return nil, nil
}

func parse(t *testing.T, text string) *Expression {
	t.Helper()
	var e Expression
	if err := json.Unmarshal([]byte(text), &e); err != nil {
		t.Fatalf("parsing %s: %v", text, err)
	}
	return &e
}

// TestCompileRendersEveryLeaf pins the SQL of every kind of leaf and the
// numbering of the parameters: the condition joins a query that already
// has parameters of its own, and a placeholder off by one would filter
// on the wrong value in silence.
func TestCompileRendersEveryLeaf(t *testing.T) {
	cases := []struct {
		name string
		in   string
		sql  string
		args []any
	}{
		{"site", `{"site":"warsaw"}`, "h.site = $3", []any{"warsaw"}},
		{"environment", `{"environment":"prod"}`, "h.environment = $3", []any{"prod"}},
		{"os family", `{"os_family":"debian"}`, "h.os_family = $3", []any{"debian"}},
		{"tag", `{"tag":"role=db"}`, "h.tags @> $3::text[]", []any{[]string{"role=db"}}},
		{"capability", `{"capability":"packages.apt"}`,
			"exists (select 1 from host_capability_registry r where r.host_id = h.id and r.name = $3 and r.available)",
			[]any{"packages.apt"}},
		{"connection", `{"connection_state":"online"}`, "h.connection_state = $3", []any{"online"}},
		{"lifecycle", `{"lifecycle_state":"active"}`, "h.lifecycle_state = $3", []any{"active"}},
		{"owner", `{"owner":"team-x"}`, "h.owner = $3", []any{"team-x"}},
		{"channel", `{"channel":"beta"}`, "h.release_channel = $3", []any{"beta"}},
		{"static group", `{"group_id":"0b0e7a3e-0000-4000-8000-000000000001"}`,
			"exists (select 1 from host_group_members m where m.group_id = $3::uuid and m.host_id = h.id)",
			[]any{"0b0e7a3e-0000-4000-8000-000000000001"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sql, args, err := Compile(parse(t, tc.in), 2)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			if sql != tc.sql {
				t.Errorf("sql = %q, expected %q", sql, tc.sql)
			}
			if !reflect.DeepEqual(args, tc.args) {
				t.Errorf("args = %#v, expected %#v", args, tc.args)
			}
		})
	}
}

// TestCompileNestsCombinators checks that all, any and not compose with
// parentheses and that the parameters are numbered in reading order.
func TestCompileNestsCombinators(t *testing.T) {
	e := parse(t, `{"all":[
		{"site":"warsaw"},
		{"any":[{"tag":"role=db"},{"tag":"role=cache"}]},
		{"not":{"lifecycle_state":"retired"}}
	]}`)
	sql, args, err := Compile(e, 0)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	want := "(h.site = $1 and (h.tags @> $2::text[] or h.tags @> $3::text[]) and not h.lifecycle_state = $4)"
	if sql != want {
		t.Errorf("sql = %q, expected %q", sql, want)
	}
	wantArgs := []any{"warsaw", []string{"role=db"}, []string{"role=cache"}, "retired"}
	if !reflect.DeepEqual(args, wantArgs) {
		t.Errorf("args = %#v, expected %#v", args, wantArgs)
	}
}

// TestCompileRefusesAnUnexpandedGroup guards the order of the steps: a
// group is resolved by the expander, and the compiler must not invent a
// membership test from a name.
func TestCompileRefusesAnUnexpandedGroup(t *testing.T) {
	_, _, err := Compile(parse(t, `{"group":"databases"}`), 0)
	if !errors.Is(err, ErrUnexpanded) {
		t.Fatalf("err = %v, expected ErrUnexpanded", err)
	}
	if _, _, err := Compile(nil, 0); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a nil selector compiled: %v", err)
	}
}

// TestValidateRefusesWhatDoesNotHoldTogether lists the shapes a client
// may send by mistake; each is refused with a reason naming the place.
func TestValidateRefusesWhatDoesNotHoldTogether(t *testing.T) {
	cases := map[string]string{
		"empty node":            `{}`,
		"two fields at once":    `{"site":"warsaw","tag":"role=db"}`,
		"a combinator and leaf": `{"all":[{"site":"a"}],"site":"b"}`,
		"empty child":           `{"all":[{}]}`,
		"upper-case tag key":    `{"tag":"Role=db"}`,
		"tag with a space":      `{"tag":"role = db"}`,
		"unknown state":         `{"connection_state":"sleeping"}`,
		"unknown lifecycle":     `{"lifecycle_state":"parked"}`,
		"unknown channel":       `{"channel":"nightly"}`,
		"internal group id":     `{"group_id":"0b0e7a3e-0000-4000-8000-000000000001"}`,
		"padded value":          `{"site":" warsaw"}`,
		"too long":              `{"owner":"` + strings.Repeat("x", maxValue+1) + `"}`,
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			err := parse(t, text).Validate()
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("%s passed validation: %v", text, err)
			}
		})
	}

	valid := []string{
		`{"site":"warsaw"}`,
		`{"tag":"role"}`,
		`{"tag":"tier=gold"}`,
		`{"tag":"os.version=12.4"}`,
		`{"group":"databases"}`,
		`{"channel":"beta"}`,
		`{"any":[{"site":"a"},{"not":{"environment":"prod"}}]}`,
	}
	for _, text := range valid {
		if err := parse(t, text).Validate(); err != nil {
			t.Errorf("%s was refused: %v", text, err)
		}
	}
}

// TestValidateBoundsTheShape: a selector nobody can read before approving
// is refused rather than compiled.
func TestValidateBoundsTheShape(t *testing.T) {
	deep := &Expression{Site: "a"}
	for i := 0; i < MaxDepth; i++ {
		deep = &Expression{Not: deep}
	}
	if err := deep.Validate(); !errors.Is(err, ErrInvalid) {
		t.Errorf("a selector %d levels deep passed: %v", MaxDepth+1, err)
	}

	wide := &Expression{}
	for i := 0; i < MaxNodes; i++ {
		wide.Any = append(wide.Any, Expression{Site: "a"})
	}
	if err := wide.Validate(); !errors.Is(err, ErrInvalid) {
		t.Errorf("a selector with %d nodes passed: %v", MaxNodes+1, err)
	}
}

// TestExpandResolvesGroups: a static group becomes a membership test, a
// dynamic group is replaced by its selector, and the input stays as it
// was - the campaign records what was asked for, not what it resolved to.
func TestExpandResolvesGroups(t *testing.T) {
	groups := fakeGroups{
		"static": {ID: "0b0e7a3e-0000-4000-8000-000000000001", Name: "databases", Kind: KindStatic},
		"dynamic": {ID: "0b0e7a3e-0000-4000-8000-000000000002", Name: "gold-tier", Kind: KindDynamic,
			Selector: parse(t, `{"all":[{"tag":"tier=gold"},{"group":"databases"}]}`)},
	}
	in := parse(t, `{"any":[{"group":"databases"},{"group":"gold-tier"}]}`)
	before, _ := json.Marshal(in)

	out, err := Expand(context.Background(), in, groups)
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	after, _ := json.Marshal(in)
	if string(before) != string(after) {
		t.Error("the expander changed its input")
	}

	sql, args, err := Compile(out, 0)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	want := "(exists (select 1 from host_group_members m where m.group_id = $1::uuid and m.host_id = h.id)" +
		" or (h.tags @> $2::text[]" +
		" and exists (select 1 from host_group_members m where m.group_id = $3::uuid and m.host_id = h.id)))"
	if sql != want {
		t.Errorf("sql = %q, expected %q", sql, want)
	}
	if len(args) != 3 || args[0] != groups["static"].ID || args[2] != groups["static"].ID {
		t.Errorf("args = %#v", args)
	}
}

// TestExpandRefusesACycleAndAMissingGroup: a group that refers to itself
// through others has no answer; a group that does not exist is named,
// not silently matched to nothing.
func TestExpandRefusesACycleAndAMissingGroup(t *testing.T) {
	groups := fakeGroups{
		"a": {ID: "0b0e7a3e-0000-4000-8000-00000000000a", Name: "a", Kind: KindDynamic,
			Selector: parse(t, `{"all":[{"site":"x"},{"group":"b"}]}`)},
		"b": {ID: "0b0e7a3e-0000-4000-8000-00000000000b", Name: "b", Kind: KindDynamic,
			Selector: parse(t, `{"group":"a"}`)},
	}
	_, err := Expand(context.Background(), parse(t, `{"group":"a"}`), groups)
	if !errors.Is(err, ErrCycle) {
		t.Fatalf("err = %v, expected ErrCycle", err)
	}
	_, err = Expand(context.Background(), parse(t, `{"group":"nobody"}`), groups)
	if !errors.Is(err, ErrUnknownGroup) {
		t.Fatalf("err = %v, expected ErrUnknownGroup", err)
	}
}

// TestDescribeReadsInOneLine: the audit detail and the scope bar show the
// selector to people without a parser.
func TestDescribeReadsInOneLine(t *testing.T) {
	e := parse(t, `{"all":[{"site":"warsaw"},{"not":{"tag":"role=db"}}]}`)
	if got := e.Describe(); got != "(site=warsaw and not tag=role=db)" {
		t.Errorf("describe = %q", got)
	}
}

// TestExpandRecountsTheNodes: the bound on the size holds after the
// expansion too. A selector of a few references passes validation; the
// dynamic groups behind them must not blow it up past what the database
// is asked to evaluate.
func TestExpandRecountsTheNodes(t *testing.T) {
	// A dynamic group with a wide "any": each reference adds all of it.
	tags := make([]string, 0, MaxNodes/2)
	for i := 0; i < MaxNodes/2; i++ {
		tags = append(tags, fmt.Sprintf(`{"tag":"t=%d"}`, i))
	}
	groups := fakeGroups{
		"wide": {ID: "0b0e7a3e-0000-4000-8000-000000000001", Name: "wide", Kind: KindDynamic,
			Selector: parse(t, `{"any":[`+strings.Join(tags, ",")+`]}`)},
	}
	one := parse(t, `{"group":"wide"}`)
	if err := one.Validate(); err != nil {
		t.Fatalf("a single reference failed validation: %v", err)
	}
	if _, err := Expand(context.Background(), one, groups); err != nil {
		t.Fatalf("a single reference failed to expand: %v", err)
	}
	three := parse(t, `{"all":[{"group":"wide"},{"group":"wide"},{"group":"wide"}]}`)
	if err := three.Validate(); err != nil {
		t.Fatalf("three references failed validation: %v", err)
	}
	if _, err := Expand(context.Background(), three, groups); !errors.Is(err, ErrInvalid) {
		t.Fatalf("three references expanded past the bound: %v", err)
	}
}
