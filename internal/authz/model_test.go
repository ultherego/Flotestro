package authz

import "testing"

func principalWith(bindings ...Binding) Principal {
	return Principal{ID: "p1", Subject: "test", Bindings: bindings}
}

func TestAScopeLimitsAPermission(t *testing.T) {
	// The operator has rights only on staging in Warsaw.
	operator := principalWith(Binding{
		Role:  RoleOperator,
		Scope: Scope{Site: "warsaw", Environment: "staging"},
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
	// A global operation has a target with an asterisk. A narrow assignment
	// must not cover it, because otherwise the operator of one environment
	// would manage the whole system.
	operator := principalWith(Binding{
		Role:  RolePlatformAdmin,
		Scope: Scope{Site: "warsaw", Environment: "staging"},
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
// with authorisation. The two rules drifting apart produced a panel in which
// an administrator with a global scope saw an empty fleet while an operator
// limited to one environment saw their hosts correctly: the asterisk reached
// the query as an ordinary value and matched nothing.
func TestScopeSQLHasTheSameSemanticsAsMatches(t *testing.T) {
	global := []Scope{{Site: Wildcard, Environment: Wildcard}}
	if condition, args := ScopeSQL(global, "site", "environment", 0); condition != "" || args != nil {
		t.Errorf("a global scope must not narrow: %q %v", condition, args)
	}

	narrow := []Scope{{Site: "lab", Environment: "test"}}
	condition, args := ScopeSQL(narrow, "site", "environment", 0)
	if condition != "((site = $1 and environment = $2))" {
		t.Errorf("the condition of a narrow scope = %q", condition)
	}
	if len(args) != 2 || args[0] != "lab" || args[1] != "test" {
		t.Errorf("arguments = %v", args)
	}

	// An asterisk in one dimension lifts the condition only in that one.
	partial := []Scope{{Site: Wildcard, Environment: "prod"}}
	condition, args = ScopeSQL(partial, "site", "environment", 0)
	if condition != "((environment = $1))" || len(args) != 1 || args[0] != "prod" {
		t.Errorf("partial scope: %q %v", condition, args)
	}

	// The numbering of parameters accounts for those already used in the query.
	condition, _ = ScopeSQL(narrow, "h.site", "h.environment", 3)
	if condition != "((h.site = $4 and h.environment = $5))" {
		t.Errorf("parameter offset: %q", condition)
	}

	// An empty value matches nothing - exactly as in Matches.
	if (Scope{Site: "", Environment: "test"}).Matches(Scope{Site: "lab", Environment: "test"}) {
		t.Fatal("an empty dimension must not match")
	}
	condition, _ = ScopeSQL([]Scope{{Site: "", Environment: "test"}}, "site", "environment", 0)
	if condition != "((false and environment = $1))" {
		t.Errorf("an empty dimension in SQL = %q", condition)
	}

	// No scopes must not mean access to everything.
	if condition, _ := ScopeSQL(nil, "site", "environment", 0); condition != "false" {
		t.Errorf("no scopes = %q, expected a false condition", condition)
	}
}
