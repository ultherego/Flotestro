package authz

import (
	"testing"
	"time"
)

func TestAnExpiredBindingGrantsNothing(t *testing.T) {
	yesterday := time.Now().Add(-24 * time.Hour)
	tomorrow := time.Now().Add(24 * time.Hour)

	// A rotation that ended yesterday: the binding is still on record and
	// still on the listing, but it decides nothing any more.
	expired := principalWith(Binding{Role: RoleOperator, Scope: GlobalScope, ValidUntil: &yesterday})
	if expired.Can(PermUnitRestart, Scope{Site: "warsaw", Environment: "staging"}) {
		t.Error("an expired binding granted a permission")
	}
	if expired.CanAnywhere(PermUnitRestart) {
		t.Error("an expired binding granted a permission somewhere")
	}
	if len(expired.Permissions()) != 0 {
		t.Errorf("an expired binding lists permissions: %v", expired.Permissions())
	}
	if len(expired.ScopesFor(PermUnitRestart)) != 0 {
		t.Errorf("an expired binding lists scopes: %v", expired.ScopesFor(PermUnitRestart))
	}
	if len(expired.Roles()) != 0 {
		t.Errorf("an expired binding lists roles: %v", expired.Roles())
	}
	if len(expired.Bindings) != 1 {
		t.Error("the expired binding fell off the record")
	}

	// The same binding with a day left, and one without a date at all,
	// both grant as before.
	for name, principal := range map[string]Principal{
		"until tomorrow": principalWith(Binding{Role: RoleOperator, Scope: GlobalScope, ValidUntil: &tomorrow}),
		"open-ended":     principalWith(Binding{Role: RoleOperator, Scope: GlobalScope}),
	} {
		if !principal.Can(PermUnitRestart, Scope{Site: "warsaw", Environment: "staging"}) {
			t.Errorf("%s: the binding does not grant", name)
		}
	}
}

func TestAnExpiredBindingDoesNotHideALiveOne(t *testing.T) {
	yesterday := time.Now().Add(-24 * time.Hour)
	// The operator role ended; the viewer role, granted without a date,
	// stays. The dead binding must not take the live one with it.
	principal := principalWith(
		Binding{Role: RoleOperator, Scope: GlobalScope, ValidUntil: &yesterday},
		Binding{Role: RoleViewer, Scope: GlobalScope},
	)
	if principal.Can(PermUnitRestart, GlobalScope) {
		t.Error("the expired operator role still grants")
	}
	if !principal.Can(PermHostRead, GlobalScope) {
		t.Error("the live viewer role does not grant")
	}
	if roles := principal.Roles(); len(roles) != 1 || roles[0] != string(RoleViewer) {
		t.Errorf("roles = %v", roles)
	}
}

func TestBindingActiveIsDecidedAtTheGivenMoment(t *testing.T) {
	deadline := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	binding := Binding{Role: RoleViewer, Scope: GlobalScope, ValidUntil: &deadline}
	if !binding.Active(deadline.Add(-time.Second)) {
		t.Error("a binding a second before its deadline is not active")
	}
	// The deadline itself is past: "valid until noon" ends at noon.
	if binding.Active(deadline) {
		t.Error("a binding at its deadline is still active")
	}
	if !(Binding{Role: RoleViewer, Scope: GlobalScope}).Active(deadline.Add(100 * 365 * 24 * time.Hour)) {
		t.Error("a binding without a deadline expired")
	}
}
