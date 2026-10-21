//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// A mapping of a group to a role hands that role to everybody in the group, so
// it is a grant like any other and has to be held to the same rule: nobody gives
// a role wider than the one they hold themselves. A role definition that carries
// principal.manage and nothing else once sufficed to map a group to
// platform_admin, because the mapping route asked only whether the role existed.
func TestAMappingCannotHandOutAWiderRoleThanTheOneItsAuthorHolds(t *testing.T) {
	h := newHarness(t)
	suffix := strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	roleName := "mapper_" + suffix

	h.do(http.MethodPost, "/api/v1/roles", map[string]any{
		"role":        roleName,
		"description": "May manage identities and nothing else.",
		"permissions": []string{"principal.manage", "host.read"},
		"reason":      "the integration suite defines a role that can manage identities and no more",
	}, nil, http.StatusCreated)
	t.Cleanup(func() {
		h.do(http.MethodDelete, "/api/v1/roles/"+roleName, map[string]any{
			"reason": "the integration suite removes the role it defined",
		}, nil, 0)
	})
	mapper := h.withToken(h.createPrincipal("mapper-"+suffix, []map[string]string{{"role": roleName}}))

	group := "escalation-" + suffix
	var created struct {
		ID string `json:"id"`
	}
	request := func(role string) map[string]any {
		return map[string]any{
			"issuer":     "https://issuer.example/realms/flotestro",
			"group_name": group,
			"role":       role,
			"reason":     "the integration suite tries a mapping wider than its author's role",
		}
	}
	remove := func(id string) {
		h.do(http.MethodDelete, "/api/v1/group-mappings/"+id+"?reason="+
			url.QueryEscape("the integration suite removes the mapping it made"), nil, nil, 0)
	}

	// The wider role: refused, like a direct grant of it.
	status := postStatus(mapper, "/api/v1/group-mappings", request("platform_admin"), &created)
	if created.ID != "" {
		remove(created.ID)
		t.Fatalf("a group was mapped to platform_admin by an identity that holds only %s (status %d)", roleName, status)
	}
	if status != http.StatusForbidden {
		t.Fatalf("the wider mapping answered %d, expected 403 scope_escalation", status)
	}

	// The control: a mapping of a role the author does hold is theirs to give.
	created.ID = ""
	status = postStatus(mapper, "/api/v1/group-mappings", request(roleName), &created)
	if created.ID != "" {
		remove(created.ID)
	}
	if status != http.StatusCreated {
		t.Fatalf("a mapping of the author's own role answered %d, expected 201", status)
	}
}

// postStatus makes a request as the harness's identity and answers its status,
// whatever it is: the harness's own do wants one status in advance.
func postStatus(h *harness, path string, body any, out any) int {
	h.t.Helper()
	encoded, _ := json.Marshal(body)
	request, err := http.NewRequest(http.MethodPost, h.api+path, bytes.NewReader(encoded))
	if err != nil {
		h.t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+h.token)
	response, err := h.client.Do(request)
	if err != nil {
		h.t.Fatalf("POST %s: %v", path, err)
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(response.Body)
	if out != nil && len(raw) > 0 {
		_ = json.Unmarshal(raw, out)
	}
	return response.StatusCode
}
