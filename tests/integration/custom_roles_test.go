//go:build integration

package integration

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// A role this installation defined grants exactly what it was defined with,
// and nothing on either side of that.
//
// It runs here because every part of the answer is in the database: a role is
// a row, its permissions are rows, the binding that names it is a third, and
// the request is decided by a join across all three. The Go tests can show
// that a binding carrying a list grants that list; only a running panel can
// show that the list arrives.
func TestARoleThisInstallationDefinedGrantsWhatItSays(t *testing.T) {
	h := newHarness(t)
	name := "shift_lead_" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")

	var created struct {
		Role        string   `json:"role"`
		BuiltIn     bool     `json:"built_in"`
		Permissions []string `json:"permissions"`
	}
	h.do(http.MethodPost, "/api/v1/roles", map[string]any{
		"role":        name,
		"description": "Reads the fleet and restarts a unit. Nothing else.",
		"permissions": []string{"host.read", "unit.restart", "job.read", "job.create"},
		"reason":      "the integration suite defines a role of this installation's own",
	}, &created, http.StatusCreated)
	t.Cleanup(func() {
		h.do(http.MethodDelete, "/api/v1/roles/"+name, map[string]any{
			"reason": "the integration suite removes the role it defined",
		}, nil, http.StatusNoContent)
	})
	if created.BuiltIn {
		t.Error("a role defined here came back as one of the product's own")
	}
	if len(created.Permissions) != 4 {
		t.Errorf("the role came back carrying %v", created.Permissions)
	}

	// The catalogue tells the two kinds apart, and says the product's roles
	// carry what the code says rather than what any row says.
	var catalogue struct {
		Items []struct {
			Role        string   `json:"role"`
			BuiltIn     bool     `json:"built_in"`
			Permissions []string `json:"permissions"`
			Bindings    int      `json:"bindings"`
		} `json:"items"`
	}
	h.get("/api/v1/roles", &catalogue)
	var mine, viewer *struct {
		Role        string   `json:"role"`
		BuiltIn     bool     `json:"built_in"`
		Permissions []string `json:"permissions"`
		Bindings    int      `json:"bindings"`
	}
	for i := range catalogue.Items {
		switch catalogue.Items[i].Role {
		case name:
			mine = &catalogue.Items[i]
		case "viewer":
			viewer = &catalogue.Items[i]
		}
	}
	if mine == nil || viewer == nil {
		t.Fatalf("the catalogue is missing %s or viewer", name)
	}
	if viewer == nil || !viewer.BuiltIn || len(viewer.Permissions) == 0 {
		t.Error("the product's own role came back without its compiled permissions")
	}
	if mine.Bindings != 0 {
		t.Errorf("a role nobody is bound to says it has %d bindings", mine.Bindings)
	}

	// Now the thing worth running a panel for: an identity holding only this
	// role, and what its own token can and cannot do.
	token := h.createPrincipal("shift-lead-"+uuid.NewString()[:8], []map[string]string{{"role": name}})
	holder := h.withToken(token)

	var whoami struct {
		ID          string   `json:"id"`
		Roles       []string `json:"roles"`
		Permissions []string `json:"permissions"`
	}
	holder.get("/api/v1/whoami", &whoami)
	// The binding has to go before the role does: a role somebody holds
	// cannot be deleted, and an identity cannot be deleted at all, so
	// without this the role outlives every run and the removal above
	// answers role_in_use. Cleanups run in reverse order, so this one -
	// registered later - runs before the role's.
	t.Cleanup(func() {
		if whoami.ID != "" {
			h.do(http.MethodDelete, "/api/v1/principals/"+whoami.ID+"/roles/"+name, map[string]any{
				"reason": "the integration suite frees the role it defined",
			}, nil, http.StatusNoContent)
		}
	})
	if len(whoami.Roles) != 1 || whoami.Roles[0] != name {
		t.Errorf("the identity holds %v rather than the role it was given", whoami.Roles)
	}
	granted := map[string]bool{}
	for _, permission := range whoami.Permissions {
		granted[permission] = true
	}
	for _, permission := range []string{"host.read", "unit.restart", "job.read", "job.create"} {
		if !granted[permission] {
			t.Errorf("the role was defined with %s and the session does not carry it", permission)
		}
	}
	// The other side, which is the whole point of defining a narrow role: the
	// powers of the role it would otherwise have taken - operator - are not
	// there.
	for _, permission := range []string{"system.reboot", "packages.install", "host.decommission", "principal.manage"} {
		if granted[permission] {
			t.Errorf("the role carries %s, which it was not defined with", permission)
		}
	}
	// And the panel answers the same way to a request, not only to whoami.
	holder.do(http.MethodGet, "/api/v1/hosts", nil, nil, http.StatusOK)
	holder.do(http.MethodGet, "/api/v1/principals", nil, nil, http.StatusForbidden)
}

// The refusals around a role of one's own, each of which protects something
// different.
func TestWhatTheInstallationMayNotDoToARole(t *testing.T) {
	h := newHarness(t)

	// A built-in role is the product's: not editable, not removable. The
	// permissions of one are in the code, and a row that disagreed with the
	// code would be a second answer to one question.
	h.do(http.MethodPut, "/api/v1/roles/operator", map[string]any{
		"permissions": []string{"host.read"},
		"reason":      "the integration suite checks a built-in role is refused",
	}, nil, http.StatusConflict)
	h.do(http.MethodDelete, "/api/v1/roles/platform_admin", map[string]any{
		"reason": "the integration suite checks a built-in role is refused",
	}, nil, http.StatusConflict)

	// A permission this product does not define is refused rather than
	// stored: a role carrying one would read as a right nobody can grant and
	// nobody can take away.
	h.do(http.MethodPost, "/api/v1/roles", map[string]any{
		"role":        "role_with_a_wish",
		"permissions": []string{"host.read", "fleet.do.whatever"},
		"reason":      "the integration suite checks an invented permission is refused",
	}, nil, http.StatusBadRequest)

	// A role carrying nothing is refused: it would appear on every screen as
	// a role somebody holds.
	h.do(http.MethodPost, "/api/v1/roles", map[string]any{
		"role":        "role_with_nothing",
		"permissions": []string{},
		"reason":      "the integration suite checks an empty role is refused",
	}, nil, http.StatusBadRequest)

	// A name the product already uses is refused rather than shadowing it.
	h.do(http.MethodPost, "/api/v1/roles", map[string]any{
		"role":        "operator",
		"permissions": []string{"host.read"},
		"reason":      "the integration suite checks a name collision is refused",
	}, nil, http.StatusConflict)

	// A role somebody is bound to cannot be deleted out from under them. The
	// database holds to this with a foreign key, so it is true for a script
	// and a hand at psql as well as for this endpoint.
	name := "rota_" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	h.do(http.MethodPost, "/api/v1/roles", map[string]any{
		"role":        name,
		"permissions": []string{"host.read"},
		"reason":      "the integration suite checks a role in use cannot be deleted",
	}, nil, http.StatusCreated)
	subject := "rota-holder-" + uuid.NewString()[:8]
	h.createPrincipal(subject, []map[string]string{{"role": name}})
	h.do(http.MethodDelete, "/api/v1/roles/"+name, map[string]any{
		"reason": "the integration suite expects this refusal",
	}, nil, http.StatusConflict)

	// A name that is no role at all is refused where a binding is written,
	// rather than stored and discovered later.
	h.do(http.MethodPost, "/api/v1/principals", map[string]any{
		"subject": "holder-of-nothing-" + uuid.NewString()[:8],
		"roles": []map[string]any{{
			"role": "a_role_nobody_defined", "team_scope": map[string]string{"mode": "any"},
		}},
		"reason": "the integration suite checks an unknown role is refused",
	}, nil, http.StatusBadRequest)
}

// An edit takes a permission away from everybody bound to the role, which is
// the thing an installation has to be able to see afterwards.
func TestNarrowingARoleTakesThePermissionFromItsHolders(t *testing.T) {
	h := newHarness(t)
	name := "deputy_" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	h.do(http.MethodPost, "/api/v1/roles", map[string]any{
		"role":        name,
		"permissions": []string{"host.read", "job.read", "job.create", "unit.restart"},
		"reason":      "the integration suite narrows a role while somebody holds it",
	}, nil, http.StatusCreated)

	token := h.createPrincipal("deputy-"+uuid.NewString()[:8], []map[string]string{{"role": name}})
	holder := h.withToken(token)
	var before struct {
		Permissions []string `json:"permissions"`
	}
	holder.get("/api/v1/whoami", &before)
	if !holdsPermission(before.Permissions, "unit.restart") {
		t.Fatalf("the holder never had unit.restart: %v", before.Permissions)
	}

	h.do(http.MethodPut, "/api/v1/roles/"+name, map[string]any{
		"permissions": []string{"host.read", "job.read"},
		"reason":      "the integration suite narrows the role",
	}, nil, http.StatusOK)

	// The same token, the same session: the narrowing reaches it because the
	// permissions are read with the binding on every request rather than
	// cached when the session began.
	var after struct {
		Permissions []string `json:"permissions"`
	}
	holder.get("/api/v1/whoami", &after)
	if holdsPermission(after.Permissions, "unit.restart") {
		t.Error("the holder still carries unit.restart after it was taken out of the role")
	}
	if !holdsPermission(after.Permissions, "host.read") {
		t.Error("the holder lost a permission the role kept")
	}
}

func holdsPermission(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
