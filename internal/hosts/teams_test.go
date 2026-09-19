package hosts

import (
	"strings"
	"testing"

	"github.com/ultherego/flotestro/internal/authz"
)

// The narrowing of a listing and the authorisation of a single read have to
// answer the same question.

func TestScopeSQLReadsATeamOnTheTeamColumn(t *testing.T) {
	team := "1e83b0e4-0000-4000-8000-000000000001"
	for _, test := range []struct {
		name   string
		scopes []authz.Scope
		want   string
		args   []any
	}{
		{
			name: "no scope is no host",
			want: "false",
		},
		{
			name:   "a global scope lifts the condition",
			scopes: []authz.Scope{{Site: authz.Wildcard, Environment: authz.Wildcard}},
			want:   "",
		},
		{
			// The case the site columns alone would read as the whole fleet. The
			// wildcards are what the binding carries; the team is what it means.
			name:   "a team scope compares the team column alone",
			scopes: []authz.Scope{{Site: authz.Wildcard, Environment: authz.Wildcard, Team: team}},
			want:   "(h.team_id = $1::uuid)",
			args:   []any{team},
		},
		{
			name: "a team and a site scope are two ways in",
			scopes: []authz.Scope{
				{Site: authz.Wildcard, Environment: authz.Wildcard, Team: team},
				{Site: "lab", Environment: "test"},
			},
			want: "(h.team_id = $1::uuid or (h.site = $2 and h.environment = $3))",
			args: []any{team, "lab", "test"},
		},
		{
			name:   "an unknown site narrows to nothing",
			scopes: []authz.Scope{{Site: "", Environment: "test"}},
			want:   "((false and h.environment = $1))",
			args:   []any{"test"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			condition, args := ScopeSQL(test.scopes, "h.site", "h.environment", "h.team_id", 0)
			if condition != test.want {
				t.Errorf("condition = %q, expected %q", condition, test.want)
			}
			if len(args) != len(test.args) {
				t.Fatalf("%d arguments, expected %d: %v", len(args), len(test.args), args)
			}
			for i := range args {
				if args[i] != test.args[i] {
					t.Errorf("argument %d = %v, expected %v", i+1, args[i], test.args[i])
				}
			}
		})
	}
}

// The placeholders are numbered from where the caller's own parameters
// end, so a condition concatenated after them reads its own arguments.
func TestScopeSQLNumbersAfterTheOffset(t *testing.T) {
	team := "1e83b0e4-0000-4000-8000-000000000002"
	condition, args := ScopeSQL([]authz.Scope{
		{Site: authz.Wildcard, Environment: authz.Wildcard, Team: team},
	}, "h.site", "h.environment", "h.team_id", 4)
	if condition != "(h.team_id = $5::uuid)" {
		t.Errorf("condition = %q", condition)
	}
	if len(args) != 1 || args[0] != team {
		t.Errorf("arguments = %v", args)
	}
}

// TestScopeSQLAgreesWithMatches is the guard that keeps the listing and the
// single read from drifting apart: for every combination of binding and host
// below, the condition either names the host's column value or refuses,
func TestScopeSQLAgreesWithMatches(t *testing.T) {
	mine := "1e83b0e4-0000-4000-8000-00000000000a"
	theirs := "1e83b0e4-0000-4000-8000-00000000000b"
	bindings := []authz.Scope{
		{Site: authz.Wildcard, Environment: authz.Wildcard},
		{Site: "lab", Environment: authz.Wildcard},
		{Site: authz.Wildcard, Environment: authz.Wildcard, Team: mine},
	}
	targets := []struct {
		name string
		host Host
	}{
		{"a host of the team", Host{Site: "lab", Environment: "test", TeamID: mine}},
		{"a host of another team", Host{Site: "lab", Environment: "test", TeamID: theirs}},
		{"a host of no team", Host{Site: "lab", Environment: "test"}},
		{"a host of another site", Host{Site: "dc1", Environment: "prod", TeamID: theirs}},
	}
	for _, binding := range bindings {
		for _, target := range targets {
			scope := ScopeOf(&target.host)
			matches := binding.Matches(scope)
			condition, args := ScopeSQL([]authz.Scope{binding}, "h.site", "h.environment", "h.team_id", 0)
			// The condition is read the way the database would read it: an empty
			// condition is every row, "false" is none, and a comparison holds when its
			// argument is the host's value.
			var selects bool
			switch {
			case condition == "":
				selects = true
			case strings.Contains(condition, "false"):
				selects = false
			case strings.Contains(condition, "h.team_id"):
				selects = len(args) == 1 && args[0] == scope.Team
			default:
				selects = true
				for _, arg := range args {
					if arg != scope.Site && arg != scope.Environment {
						selects = false
					}
				}
			}
			if selects != matches {
				t.Errorf("%s under %s: the listing says %v, the read says %v (condition %q, args %v)",
					target.name, binding.String(), selects, matches, condition, args)
			}
		}
	}
}

func TestNormalizeTeamNameRefusesWhatCannotBeRead(t *testing.T) {
	if _, err := NormalizeTeamName("   "); err == nil {
		t.Error("a team without a name was accepted")
	}
	if _, err := NormalizeTeamName("data\nplatform"); err == nil {
		t.Error("a name with a line break was accepted: it would forge a second row in the trail")
	}
	if _, err := NormalizeTeamName(strings.Repeat("a", MaxTeamNameLength+1)); err == nil {
		t.Error("a name past the bound was accepted")
	}
	name, err := NormalizeTeamName("  data platform  ")
	if err != nil || name != "data platform" {
		t.Errorf("a plain name came back as %q, %v", name, err)
	}
}

// A team is named by its identifier everywhere a boundary is drawn: a
// name would follow a rename into somebody else's group.
func TestValidTeamIDTakesIdentifiersOnly(t *testing.T) {
	if ValidTeamID("data platform") {
		t.Error("a team name passed as an identifier")
	}
	if !ValidTeamID("1e83b0e4-0000-4000-8000-00000000000a") {
		t.Error("an identifier was refused")
	}
}
