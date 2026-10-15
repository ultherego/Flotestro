//go:build integration

package integration

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
)

// A group mapping narrowed to an owner and a tag keeps that narrowing through
// the database.
//
// The API documented owners and tags on this endpoint, accepted them and threw
// them away until 15.10: the scope was built with site and environment only,
// and the other categories were filled with a wildcard. An administrator who
// narrowed a role to one owner was handed a rule reaching every owner, with
// nothing on screen or in the answer to say so.
//
// This runs it against the installation, because the narrowing lives in two
// array columns and a unique index that had to be replaced - none of which the
// Go tests touch.
func TestAGroupMappingKeepsItsOwnerAndTagThroughTheDatabase(t *testing.T) {
	h := newHarness(t)

	group := "e2e-owners-" + uuid.NewString()[:8]
	var created struct {
		ID          string   `json:"id"`
		Role        string   `json:"role"`
		Site        string   `json:"site"`
		Environment string   `json:"environment"`
		Owners      []string `json:"owners"`
		Tags        []string `json:"tags"`
	}
	h.do(http.MethodPost, "/api/v1/group-mappings", map[string]any{
		"issuer":      "https://issuer.example/realms/flotestro",
		"group_name":  group,
		"role":        "operator",
		"site":        "lab",
		"environment": "test",
		"owners":      []string{"team-a"},
		"tags":        []string{"db"},
		"reason":      "the integration suite checks that a narrowing survives",
	}, &created, http.StatusCreated)
	t.Cleanup(func() {
		if created.ID != "" {
			h.do(http.MethodDelete, "/api/v1/group-mappings/"+created.ID, nil, nil, http.StatusNoContent)
		}
	})

	if len(created.Owners) != 1 || created.Owners[0] != "team-a" {
		t.Errorf("the answer says the owners are %v, want the one that was asked for", created.Owners)
	}
	if len(created.Tags) != 1 || created.Tags[0] != "db" {
		t.Errorf("the answer says the tags are %v, want the one that was asked for", created.Tags)
	}

	// And the listing says the same, which is what the screen reads.
	var listed struct {
		Items []struct {
			ID     string   `json:"id"`
			Owners []string `json:"owners"`
			Tags   []string `json:"tags"`
		} `json:"items"`
	}
	h.get("/api/v1/group-mappings", &listed)
	found := false
	for _, item := range listed.Items {
		if item.ID != created.ID {
			continue
		}
		found = true
		if len(item.Owners) != 1 || item.Owners[0] != "team-a" || len(item.Tags) != 1 || item.Tags[0] != "db" {
			t.Errorf("the listing widened the rule back out: owners %v tags %v", item.Owners, item.Tags)
		}
	}
	if !found {
		t.Error("the mapping that was created is not in the listing")
	}

	// A rule that reaches nobody is refused where it is written: an emptied
	// category is not a category left out.
	h.do(http.MethodPost, "/api/v1/group-mappings", map[string]any{
		"issuer":     "https://issuer.example/realms/flotestro",
		"group_name": group + "-empty",
		"role":       "viewer",
		"owners":     []string{},
		"reason":     "an emptied category must not be stored",
	}, nil, http.StatusBadRequest)
}
