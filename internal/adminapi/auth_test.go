package adminapi

import (
	"testing"

	"github.com/ultherego/flotestro/internal/authz"
)

func TestLocalPathRejectsExternalRedirects(t *testing.T) {
	// The redirect target after login comes from a query parameter. Without
	// validation the login would become an open redirect used in phishing:
	// the user sees the trusted panel address and lands somewhere else.
	rejected := []string{
		"https://evil.example.com/",
		"//evil.example.com/",
		"http://evil.example.com",
		"javascript:alert(1)",
		"evil.example.com/path",
	}
	for _, value := range rejected {
		if got := localPath(value); got != "" {
			t.Errorf("accepted the external target %q as %q", value, got)
		}
	}
}

func TestLocalPathAcceptsLocalPaths(t *testing.T) {
	accepted := map[string]string{
		"/":               "/",
		"/hosts":          "/hosts",
		"/campaigns/123":  "/campaigns/123",
		"/hosts?site=lab": "/hosts",
	}
	for value, want := range accepted {
		if got := localPath(value); got != want {
			t.Errorf("localPath(%q) = %q, want %q", value, got, want)
		}
	}
	if got := localPath(""); got != "" {
		t.Errorf("an empty target gave %q", got)
	}
}

// TestCollectionsDoNotRequireGlobalScope guards against the regression that
// gave an operator limited to one environment a refusal on half the panel:
// the dashboard, campaigns and tasks checked the permission in the global
// scope, which a narrow binding never satisfies.
func TestCollectionsDoNotRequireGlobalScope(t *testing.T) {
	operator := authz.Principal{
		Subject: "jkowalski", Kind: "user",
		Bindings: []authz.Binding{{
			Role:  authz.RoleOperator,
			Scope: authz.Scope{Site: "lab", Environment: "test"},
		}},
	}

	// The global scope is not satisfied - and that is exactly why the
	// collections must not ask for it.
	if operator.Can(authz.PermCampaignRead, authz.GlobalScope) {
		t.Fatal("a narrow binding should not satisfy the global target")
	}
	for _, permission := range []authz.Permission{
		authz.PermHostRead, authz.PermJobRead, authz.PermCampaignRead,
	} {
		if !operator.CanAnywhere(permission) {
			t.Errorf("the operator must have %s in their scope", permission)
		}
		if len(operator.ScopesFor(permission)) != 1 {
			t.Errorf("%s: expected one scope", permission)
		}
	}
	// Permissions the role does not have still must not appear.
	if operator.CanAnywhere(authz.PermAuditRead) {
		t.Error("the operator has no audit read right")
	}
}

// TestPrincipalPermissionsAreComplete checks the list the interface hides
// sections by. Guessing by role names in the browser drifts from the policy
// at every change of it.
func TestPrincipalPermissionsAreComplete(t *testing.T) {
	principal := authz.Principal{
		Bindings: []authz.Binding{
			{Role: authz.RoleViewer, Scope: authz.Scope{Site: "lab"}},
			{Role: authz.RoleApprover, Scope: authz.GlobalScope},
		},
	}
	permissions := map[string]bool{}
	for _, permission := range principal.Permissions() {
		permissions[permission] = true
	}

	for _, expected := range []string{"host.read", "campaign.read", "job.approve", "audit.read"} {
		if !permissions[expected] {
			t.Errorf("the permission %s is missing from the principal summary", expected)
		}
	}
	// The sum must not add anything none of the roles has.
	if permissions["pki.rotate"] {
		t.Error("the summary holds a permission outside the assigned roles")
	}
}
