package jobs

import (
	"strings"
	"testing"

	"github.com/ultherego/flotestro/internal/authz"
)

// The filter carries the bindings as authz holds them, so that no category is
// lost on the way: a scope reduced to a site, an environment and a team leaves
// the other three empty, and an empty category reaches no row - which once hid
// the whole list from an administrator.
func TestTheJobListKeepsEveryScopeCategory(t *testing.T) {
	filter := ListFilter{Scopes: []authz.Scope{authz.GlobalScope}}
	conditions, args := filter.conditions()
	if len(conditions) != 0 || len(args) != 0 {
		t.Fatalf("a global scope gives %v with %v, expected no condition at all", conditions, args)
	}

	filter = ListFilter{Scopes: []authz.Scope{authz.Placement("lab", "test")}}
	conditions, args = filter.conditions()
	if len(conditions) != 1 {
		t.Fatalf("a placement gives %d conditions, expected one", len(conditions))
	}
	if strings.Contains(conditions[0], "false") {
		t.Errorf("a placement gives %q, which reaches no row", conditions[0])
	}
	if !strings.Contains(conditions[0], "h.site = $1") ||
		!strings.Contains(conditions[0], "h.environment = $2") {
		t.Errorf("a placement gives %q, expected the site and the environment", conditions[0])
	}
	if len(args) != 2 || args[0] != "lab" || args[1] != "test" {
		t.Errorf("a placement gives the arguments %v, expected lab and test", args)
	}
}

// A team binding narrows by the team and by nothing else, and the list has the
// column to compare it against.
func TestTheJobListNarrowsByTeam(t *testing.T) {
	team := "6a1c0b02-0000-4000-8000-000000000001"
	conditions, args := ListFilter{Scopes: []authz.Scope{authz.OfTeam(team)}}.conditions()
	if len(conditions) != 1 || !strings.Contains(conditions[0], "h.team_id = $1::uuid") {
		t.Fatalf("a team binding gives %v, expected a condition on the team", conditions)
	}
	if len(args) != 1 || args[0] != team {
		t.Errorf("a team binding gives the arguments %v, expected the team", args)
	}
}
