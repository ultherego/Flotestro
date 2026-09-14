package adminapi

import (
	"net/http"
	"net/http/httptest"
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
		// A backslash is read as a slash by browsers, so this is
		// //evil.example.com in disguise; the rest are characters no
		// route of the panel has.
		`/\evil.example.com/`,
		`\\evil.example.com`,
		"/hosts\n",
		"/hosts<script>",
		"/hosts;id",
		// Percent-encoded, the same characters pass the raw check and come
		// out of the decoder as the backslash, the double slash, or the
		// tab a browser strips before it reads "//evil" as a host.
		"/%5Cevil.example.com",
		"/%5c%5cevil.example.com",
		"/%2F%2Fevil.example.com",
		"/%2Fevil.example.com",
		"/%09/evil.example.com",
		"/%0A/evil.example.com",
		"/%00",
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
		"/hosts%2F1":      "/hosts/1",
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
		Subject: "jsmith", Kind: "user",
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

// TestBudgetScopeFollowsTheKey: a site budget is the site's to change, a
// fleet-wide one - and a pattern over every site - is the fleet's. An
// operator of one site raising the global mutation budget would move every
// campaign of every other site.
func TestBudgetScopeFollowsTheKey(t *testing.T) {
	siteOperator := authz.Principal{
		Subject: "waw-admin", Kind: "user",
		Bindings: []authz.Binding{{
			Role: authz.RolePlatformAdmin, Scope: authz.Scope{Site: "warsaw", Environment: "*"},
		}},
	}
	for key, allowed := range map[string]bool{
		"site:warsaw:packages":  true,
		"site:krakow:packages":  false,
		"site:*:packages":       false,
		"global:mutations":      false,
		"backend:copies:backup": false,
	} {
		if got := siteOperator.Can(authz.PermBudgetWrite, budgetScope(key)); got != allowed {
			t.Errorf("%s: allowed=%v, expected %v", key, got, allowed)
		}
	}
}

// TestLoginStateIsBoundToTheBrowser: the callback of the provider is
// accepted only in the browser that started the login. A state somebody
// else started, replayed here, would log this browser into their account.
func TestLoginStateIsBoundToTheBrowser(t *testing.T) {
	s := &Server{}
	recorder := httptest.NewRecorder()
	s.setLoginStateCookie(recorder, httptest.NewRequest(http.MethodGet, "/auth/login", nil), "state-1")
	cookies := recorder.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].Value == "state-1" {
		t.Fatalf("login cookie = %+v", cookies)
	}

	callback := httptest.NewRequest(http.MethodGet, "/auth/callback?state=state-1", nil)
	callback.AddCookie(cookies[0])
	if !loginStateMatches(callback, "state-1") {
		t.Error("the browser that started the login was refused")
	}
	if loginStateMatches(callback, "state-2") {
		t.Error("a state of another login passed with this browser's cookie")
	}
	if loginStateMatches(httptest.NewRequest(http.MethodGet, "/auth/callback", nil), "state-1") {
		t.Error("a callback without the cookie passed")
	}
}
