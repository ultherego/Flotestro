package authz

import "testing"

func principalWith(bindings ...Binding) Principal {
	return Principal{ID: "p1", Subject: "test", Bindings: bindings}
}

func TestAScopeLimitsAPermission(t *testing.T) {
	// The operator has rights only on staging in Warsaw.
	operator := principalWith(Binding{
		Role:  RoleOperator,
		Scope: Placement("warsaw", "staging"),
	})

	if !operator.Can(PermUnitRestart, Scope{Site: "warsaw", Environment: "staging"}) {
		t.Error("no permission within its own scope")
	}
	// The same host in another environment is already out of scope.
	if operator.Can(PermUnitRestart, Scope{Site: "warsaw", Environment: "prod"}) {
		t.Error("the permission leaked into another environment")
	}
	if operator.Can(PermUnitRestart, Scope{Site: "west", Environment: "staging"}) {
		t.Error("the permission leaked into another site")
	}
}

func TestAnAsteriskInTheTargetDoesNotWidenPermissions(t *testing.T) {
	// A global operation has a target with an asterisk.
	operator := principalWith(Binding{
		Role:  RolePlatformAdmin,
		Scope: Placement("warsaw", "staging"),
	})
	if operator.Can(PermHostEnrollCreate, GlobalScope) {
		t.Fatal("a narrow assignment covered a global operation")
	}

	global := principalWith(Binding{Role: RolePlatformAdmin, Scope: GlobalScope})
	if !global.Can(PermHostEnrollCreate, GlobalScope) {
		t.Fatal("an assignment with an asterisk did not cover a global operation")
	}
}

func TestOrderingIsSeparatedFromApproving(t *testing.T) {
	// Whoever orders a change should not approve it. The operator and the
	// approver have disjoint permissions for those two steps.
	if RoleOperator.Has(PermJobApprove) {
		t.Error("the operator can approve their own changes")
	}
	if RoleApprover.Has(PermJobCreate) {
		t.Error("the approver can order changes")
	}
	if !RoleOperator.Has(PermJobCreate) || !RoleApprover.Has(PermJobApprove) {
		t.Error("the roles do not have their basic permissions")
	}
}

func TestAReadingRoleDoesNotChangeState(t *testing.T) {
	mutating := []Permission{
		PermJobCreate, PermJobApprove, PermJobCancel,
		PermUnitStart, PermUnitStop, PermUnitRestart, PermUnitReload,
		PermHostEnrollCreate, PermPrincipalManage,
	}
	for _, role := range []Role{RoleViewer, RoleAuditor} {
		for _, permission := range mutating {
			if role.Has(permission) {
				t.Errorf("the role %s has a state-changing permission: %s", role, permission)
			}
		}
	}
}

func TestTheAuditorSeesTheAuditAndTheViewerDoesNot(t *testing.T) {
	if !RoleAuditor.Has(PermAuditRead) {
		t.Error("the auditor does not see the audit trail")
	}
	if RoleViewer.Has(PermAuditRead) {
		t.Error("the viewer sees the audit trail")
	}
}

func TestOperationsHaveSeparatePermissions(t *testing.T) {
	// There is no single broad permission covering every unit operation; each
	// has its own.
	unitPermissions := []Permission{PermUnitStart, PermUnitStop, PermUnitRestart, PermUnitReload}
	seen := map[Permission]bool{}
	for _, permission := range unitPermissions {
		if seen[permission] {
			t.Errorf("the permission %s repeats", permission)
		}
		seen[permission] = true
		if !RoleOperator.Has(permission) {
			t.Errorf("the operator does not have the permission %s", permission)
		}
	}
}

func TestAnIdentityWithoutRolesCanDoNothing(t *testing.T) {
	for _, permission := range []Permission{PermHostRead, PermJobRead, PermUnitRestart, PermAuditRead} {
		if (Anonymous).Can(permission, Scope{Site: "warsaw", Environment: "staging"}) {
			t.Errorf("the anonymous identity has the permission %s", permission)
		}
	}
}

func TestAnEmptyAssignmentScopeDoesNotMatch(t *testing.T) {
	// An assignment without a scope must not behave like an asterisk.
	broken := principalWith(Binding{Role: RolePlatformAdmin, Scope: Scope{}})
	if broken.Can(PermHostRead, Scope{Site: "warsaw", Environment: "staging"}) {
		t.Fatal("an empty assignment covered a specific scope")
	}
}

// TestScopeSQLHasTheSameSemanticsAsMatches guards that narrowing lists agrees
// with authorisation, over all five categories.
func TestScopeSQLHasTheSameSemanticsAsMatches(t *testing.T) {
	hosts := HostColumns("h")

	if condition, args := ScopeSQL([]Scope{GlobalScope}, hosts, 0); condition != "" || args != nil {
		t.Errorf("a scope that narrows by nothing must not narrow: %q %v", condition, args)
	}

	condition, args := ScopeSQL([]Scope{Placement("lab", "test")}, hosts, 0)
	if condition != "((h.site = $1 and h.environment = $2))" {
		t.Errorf("the condition of a placement = %q", condition)
	}
	if len(args) != 2 || args[0] != "lab" || args[1] != "test" {
		t.Errorf("arguments = %v", args)
	}

	// An asterisk in one dimension lifts the condition only in that one.
	condition, args = ScopeSQL([]Scope{Placement(Wildcard, "prod")}, hosts, 0)
	if condition != "(h.environment = $1)" || len(args) != 1 || args[0] != "prod" {
		t.Errorf("a placement of one dimension: %q %v", condition, args)
	}

	// The numbering of parameters accounts for those already used in the query.
	condition, _ = ScopeSQL([]Scope{Placement("lab", "test")}, hosts, 3)
	if condition != "((h.site = $4 and h.environment = $5))" {
		t.Errorf("parameter offset: %q", condition)
	}

	// An empty value matches nothing - exactly as in Matches.
	if (Scope{Site: "", Environment: "test"}).Matches(Scope{Site: "lab", Environment: "test"}) {
		t.Fatal("an empty dimension must not match")
	}
	condition, _ = ScopeSQL([]Scope{{Site: "", Environment: "test", TeamAny: true,
		Owners: []string{Wildcard}, Tags: []string{Wildcard}}}, hosts, 0)
	if condition != "((false and h.environment = $1))" {
		t.Errorf("an empty dimension in SQL = %q", condition)
	}

	// No scopes must not mean access to everything.
	if condition, _ := ScopeSQL(nil, hosts, 0); condition != "false" {
		t.Errorf("no scopes = %q, expected a false condition", condition)
	}
}

// A binding narrowed by a category the query cannot express reaches no row. The
// mistake this guards against is the opposite answer: a listing that cannot
// compare owners quietly showing every owner's hosts to somebody bound to one.
func TestScopeSQLRefusesWhatItCannotCompare(t *testing.T) {
	owned := Scope{Site: Wildcard, Environment: Wildcard, TeamAny: true,
		Owners: []string{"payments"}, Tags: []string{Wildcard}}
	tagged := Scope{Site: Wildcard, Environment: Wildcard, TeamAny: true,
		Owners: []string{Wildcard}, Tags: []string{"pci"}}
	team := OfTeam("1e83b0e4-0000-4000-8000-00000000000a")

	for _, test := range []struct {
		name  string
		scope Scope
		want  string
	}{
		{"an owner is compared where there is a column", owned,
			"(coalesce(h.owner, '') = any($1::text[]))"},
		{"a tag is compared where there is a column", tagged,
			"(coalesce(h.tags, '{}') && $1::text[])"},
		{"a team is compared where there is a column", team, "(h.team_id = $1::uuid)"},
	} {
		t.Run(test.name, func(t *testing.T) {
			condition, _ := ScopeSQL([]Scope{test.scope}, HostColumns("h"), 0)
			if condition != test.want {
				t.Errorf("condition = %q, expected %q", condition, test.want)
			}
		})
	}

	// The same bindings against a table that knows only a placement: each of them
	// narrows by something the table cannot answer, so none reaches a row.
	orders := Placements("e.site", "e.environment")
	for _, scope := range []Scope{owned, tagged, team} {
		if condition, _ := ScopeSQL([]Scope{scope}, orders, 0); condition != "(false)" {
			t.Errorf("%s against a placement table = %q, expected no row", scope.String(), condition)
		}
	}
	// A placement still reaches the rows it names.
	if condition, _ := ScopeSQL([]Scope{Placement("lab", "test")}, orders, 0); condition !=
		"((e.site = $1 and e.environment = $2))" {
		t.Errorf("a placement against a placement table = %q", condition)
	}
}
