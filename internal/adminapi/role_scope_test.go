package adminapi

import (
	"testing"

	"github.com/ultherego/flotestro/internal/authz"
)

// A grant says in words what it reaches. Every shape that would leave the
// binding wider than the caller wrote down is refused, and the team is the one
// category that cannot say "any" by being empty.
func TestRoleRequestRefusesWhatWouldWidenTheBinding(t *testing.T) {
	team := "1e83b0e4-0000-4000-8000-00000000000a"
	for _, test := range []struct {
		name    string
		request roleRequest
	}{
		{
			name:    "no team scope at all",
			request: roleRequest{Site: "lab", Environment: "test"},
		},
		{
			name: "a mode nobody defined",
			request: roleRequest{Site: "lab", Environment: "test",
				TeamScope: &teamScopeRequest{Mode: "all"}},
		},
		{
			name: "an empty mode",
			request: roleRequest{Site: "lab", Environment: "test",
				TeamScope: &teamScopeRequest{}},
		},
		{
			name: "any with a team named anyway",
			request: roleRequest{Site: "lab", Environment: "test",
				TeamScope: &teamScopeRequest{Mode: "any", TeamID: team}},
		},
		{
			name: "exact without a team",
			request: roleRequest{Site: "lab", Environment: "test",
				TeamScope: &teamScopeRequest{Mode: "exact"}},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := test.request.scope(); err == nil {
				t.Error("the request was accepted")
			}
		})
	}
}

// What the two accepted shapes mean, spelled out: a mode of any is every team,
// a mode of exact is that team and no other, and the categories nobody narrowed
// come back as wildcards rather than as empty fields.
func TestRoleRequestReadsTheTwoShapesItAccepts(t *testing.T) {
	team := "1e83b0e4-0000-4000-8000-00000000000b"
	any, err := roleRequest{Site: "lab", Environment: "test",
		TeamScope: &teamScopeRequest{Mode: "Any"}}.scope()
	if err != nil {
		t.Fatalf("mode any was refused: %v", err)
	}
	if !any.TeamAny || any.Team != "" {
		t.Errorf("mode any came back as %s", any.String())
	}
	if any.TeamScope()["mode"] != "any" {
		t.Errorf("the scope answers %v about its team", any.TeamScope())
	}
	exact, err := roleRequest{Site: "lab", Environment: "test",
		TeamScope: &teamScopeRequest{Mode: " exact ", TeamID: " " + team + " "},
		Owners:    []string{" alice ", ""}, Tags: []string{"db"}}.scope()
	if err != nil {
		t.Fatalf("mode exact was refused: %v", err)
	}
	if exact.TeamAny || exact.Team != team {
		t.Errorf("mode exact came back as %s", exact.String())
	}
	if len(exact.Owners) != 1 || exact.Owners[0] != "alice" {
		t.Errorf("the owners came back as %v", exact.Owners)
	}
	// A category the caller left out is the one place a wildcard is written for
	// them, because a grant with no owners at all would reach nothing.
	if len(exact.Tags) != 1 || exact.Tags[0] != "db" {
		t.Errorf("the tags came back as %v", exact.Tags)
	}
	// A grant naming a site still narrows something, so it keeps a condition on
	// the listing; only a grant naming nothing at all lifts it.
	if any.Covers() {
		t.Error("a grant naming a site reads as reaching the whole fleet")
	}
}

// Nobody hands out access they do not hold. The comparison is on the effective
// scope of every permission the role carries.
func TestMayGrantRefusesWideningTheActorsOwnAccess(t *testing.T) {
	team := "1e83b0e4-0000-4000-8000-00000000000c"
	other := "1e83b0e4-0000-4000-8000-00000000000d"
	operatorOfTeam := authz.Principal{
		Subject:  "operator",
		Bindings: []authz.Binding{{Role: authz.RoleOperator, Scope: authz.OfTeam(team)}},
	}
	if err := mayGrant(operatorOfTeam, authz.RoleOperator, authz.OfTeam(team)); err != nil {
		t.Errorf("the team it holds was refused: %v", err)
	}
	if err := mayGrant(operatorOfTeam, authz.RoleOperator, authz.OfTeam(other)); err == nil {
		t.Error("another team was granted")
	}
	// The case raw columns would pass: both bindings carry the same wildcards for
	// site and environment, and differ only in what the team column means.
	if err := mayGrant(operatorOfTeam, authz.RoleOperator,
		authz.Placement(authz.Wildcard, authz.Wildcard)); err == nil {
		t.Error("any team was granted by somebody bound to one team")
	}
	if err := mayGrant(operatorOfTeam, authz.RolePlatformAdmin, authz.OfTeam(team)); err == nil {
		t.Error("a role carrying more permissions than the actor holds was granted")
	}
	global := authz.Principal{
		Subject:  "admin",
		Bindings: []authz.Binding{{Role: authz.RolePlatformAdmin, Scope: authz.GlobalScope}},
	}
	if err := mayGrant(global, authz.RoleOperator, authz.OfTeam(team)); err != nil {
		t.Errorf("a global administrator was refused one team: %v", err)
	}
}
