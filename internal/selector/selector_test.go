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
// numbering of the parameters: the condition joins a query that already has
// parameters of its own, and a placeholder off by one would filter on the
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
		{"os version prefix", `{"os_version":"12"}`, "starts_with(h.os_version, $3)", []any{"12"}},
		// The health facts leave a host that has not reported out of both
		// answers: the column is null, and null compares with nothing.
		{"security updates pending", `{"security_updates":"true"}`, "h.pending_security_updates > 0", nil},
		{"no security updates", `{"security_updates":"false"}`, "h.pending_security_updates = 0", nil},
		{"reboot required", `{"reboot_required":"true"}`, "h.reboot_required = true", nil},
		{"no reboot required", `{"reboot_required":"false"}`, "h.reboot_required = false", nil},
		{"failed units", `{"failed_units":"true"}`, "h.failed_units > 0", nil},
		{"no failed units", `{"failed_units":"false"}`, "h.failed_units = 0", nil},
		{"agent older than", `{"agent_version":"< 0.49.0"}`,
			"(h.agent_version ~ '^v?\\d+(\\.\\d+)*' and " + VersionParts("h") + " < string_to_array($3, '.')::int[])",
			[]any{"0.49.0"}},
		{"agent at least", `{"agent_version":">=v0.49.0"}`,
			"(h.agent_version ~ '^v?\\d+(\\.\\d+)*' and " + VersionParts("h") + " >= string_to_array($3, '.')::int[])",
			[]any{"0.49.0"}},
		{"agent exactly", `{"agent_version":"0.49.0"}`,
			"(h.agent_version ~ '^v?\\d+(\\.\\d+)*' and " + VersionParts("h") + " = string_to_array($3, '.')::int[])",
			[]any{"0.49.0"}},
		{"relay by id", `{"relay":"0b0e7a3e-0000-4000-8000-000000000009"}`,
			"exists (select 1 from agent_sessions s where s.host_id = h.id and s.ended_at is null and s.relay_id = $3::uuid)",
			[]any{"0b0e7a3e-0000-4000-8000-000000000009"}},
		{"relay by name", `{"relay":"edge-1"}`,
			"exists (select 1 from agent_sessions s join relays r on r.id = s.relay_id" +
				" where s.host_id = h.id and s.ended_at is null and r.name = $3)",
			[]any{"edge-1"}},
		{"failure domain", `{"failure_domain":"rack-7"}`, "h.failure_domain = $3", []any{"rack-7"}},
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
			if len(args) == 0 && len(tc.args) == 0 {
				return
			}
			if !reflect.DeepEqual(args, tc.args) {
				t.Errorf("args = %#v, expected %#v", args, tc.args)
			}
		})
	}
}

// TestVersionPartsMatchesTheHostList: the version condition of a selector
// reads the same pattern the host list matches, so "agent_version < x" in a
// campaign and "behind" on the dashboard order the versions alike.
func TestVersionPartsMatchesTheHostList(t *testing.T) {
	want := `string_to_array(substring(h.agent_version from '^v?(\d+(?:\.\d+)*)'), '.')::int[]`
	if got := VersionParts("h"); got != want {
		t.Errorf("VersionParts = %q, expected %q", got, want)
	}
}

// TestParseVersionComparison reads the forms an agent_version leaf may
// take and refuses what is not a version.
func TestParseVersionComparison(t *testing.T) {
	cases := map[string]VersionComparison{
		"< 0.49.0":   {"<", "0.49.0"},
		"<=0.49":     {"<=", "0.49"},
		">= v1.2.3":  {">=", "1.2.3"},
		"> 0.49.0":   {">", "0.49.0"},
		"= 0.49.0":   {"=", "0.49.0"},
		"0.49.0":     {"=", "0.49.0"},
		"v0.49.0.1":  {"=", "0.49.0.1"},
		"  < 0.49.0": {"<", "0.49.0"},
	}
	for in, want := range cases {
		got, err := ParseVersionComparison(in)
		if err != nil {
			t.Errorf("%q was refused: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("%q = %+v, expected %+v", in, got, want)
		}
	}
	for _, in := range []string{"", "<", "latest", "0.49.0-rc1", "!= 0.49.0", "1.2.3.4.5", "< 0.49.0 and"} {
		if _, err := ParseVersionComparison(in); !errors.Is(err, ErrInvalid) {
			t.Errorf("%q passed as a version comparison: %v", in, err)
		}
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

// TestCompileRefusesAnUnexpandedGroup guards the order of the steps: a group
// is resolved by the expander, and the compiler must not invent a membership
// test from a name.
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
		"yes is not a boolean":  `{"security_updates":"yes"}`,
		"reboot 1":              `{"reboot_required":"1"}`,
		"failed units count":    `{"failed_units":"2"}`,
		"version word":          `{"agent_version":"latest"}`,
		"version prerelease":    `{"agent_version":"< 0.49.0-rc1"}`,
		"version not equal":     `{"agent_version":"!= 0.49.0"}`,
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
		`{"security_updates":"true"}`,
		`{"reboot_required":"false"}`,
		`{"failed_units":"true"}`,
		`{"agent_version":"< 0.49.0"}`,
		`{"agent_version":"0.49.0"}`,
		`{"os_version":"12"}`,
		`{"relay":"edge-1"}`,
		`{"failure_domain":"rack-7"}`,
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
// dynamic group is replaced by its selector, and the input stays as it was -
// the campaign records what was asked for, not what it resolved to.
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
// through others has no answer; a group that does not exist is named, not
// silently matched to nothing.
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
	// A version leaf carries its operator; the line reads as a comparison.
	e = parse(t, `{"any":[{"agent_version":"<0.49.0"},{"security_updates":"true"}]}`)
	if got := e.Describe(); got != "(agent_version < 0.49.0 or security_updates=true)" {
		t.Errorf("describe = %q", got)
	}
}

// TestExpandRecountsTheNodes: the bound on the size holds after the expansion
// too.
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

// countingGroups counts the lookups an expansion makes.
type countingGroups struct {
	fakeGroups
	lookups int
}

func (c *countingGroups) Lookup(ctx context.Context, ref string) (*Group, error) {
	c.lookups++
	return c.fakeGroups.Lookup(ctx, ref)
}

// TestExpandStopsAtTheBound: the bound holds during the expansion, not only
// after it.
func TestExpandStopsAtTheBound(t *testing.T) {
	const width = 16
	groups := &countingGroups{fakeGroups: fakeGroups{}}
	leaves := make([]string, 0, width)
	for i := 0; i < width; i++ {
		leaves = append(leaves, fmt.Sprintf(`{"tag":"t=%d"}`, i))
	}
	groups.fakeGroups["d"] = &Group{ID: "0b0e7a3e-0000-4000-8000-00000000000d", Name: "d", Kind: KindDynamic,
		Selector: parse(t, `{"any":[`+strings.Join(leaves, ",")+`]}`)}
	for _, link := range []struct{ name, next string }{{"c", "d"}, {"b", "c"}, {"a", "b"}} {
		refs := make([]string, 0, width)
		for i := 0; i < width; i++ {
			refs = append(refs, `{"group":"`+link.next+`"}`)
		}
		groups.fakeGroups[link.name] = &Group{ID: "0b0e7a3e-0000-4000-8000-00000000000" + link.name,
			Name: link.name, Kind: KindDynamic, Selector: parse(t, `{"any":[`+strings.Join(refs, ",")+`]}`)}
	}

	_, err := Expand(context.Background(), parse(t, `{"group":"a"}`), groups)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("the chain expanded: %v", err)
	}
	// The full tree is width^4 leaves and width^3 lookups of d alone; the
	// bound is reached within the first few references.
	if groups.lookups > MaxNodes {
		t.Errorf("the expansion made %d lookups past the bound of %d nodes", groups.lookups, MaxNodes)
	}
}

// TestExpandCountsStaticReferencesOnce: a reference to a static group is one
// membership test, and the running count must agree with the finished tree - a
// selector at the bound made of such references is still valid.
func TestExpandCountsStaticReferencesOnce(t *testing.T) {
	groups := fakeGroups{
		"static": {ID: "0b0e7a3e-0000-4000-8000-000000000001", Name: "databases", Kind: KindStatic},
	}
	refs := make([]string, 0, MaxNodes-1)
	for i := 0; i < MaxNodes-1; i++ {
		refs = append(refs, `{"group":"databases"}`)
	}
	full := parse(t, `{"any":[`+strings.Join(refs, ",")+`]}`)
	if err := full.Validate(); err != nil {
		t.Fatalf("a selector at the bound failed validation: %v", err)
	}
	expanded, err := Expand(context.Background(), full, groups)
	if err != nil {
		t.Fatalf("a selector at the bound failed to expand: %v", err)
	}
	if got := expanded.count(); got != MaxNodes {
		t.Errorf("the expanded selector has %d nodes, expected %d", got, MaxNodes)
	}
}
