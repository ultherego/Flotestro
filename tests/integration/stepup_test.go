//go:build integration

package integration

import (
	"net/http"
	"testing"
)

// TestChangingAccessRulesRequiresAReason checks the condition of the
// operation with the greatest impact. A group-to-role mapping decides whom
// the identity provider lets in and with which permissions, so it cannot be
// carried out without a justification recorded in the audit log.
func TestChangingAccessRulesRequiresAReason(t *testing.T) {
	h := newHarness(t)
	group := uniqueSubject("flotestro-test-group")

	for name, reason := range map[string]string{
		"no reason":        "",
		"reason too short": "because",
	} {
		t.Run(name, func(t *testing.T) {
			var problem struct {
				Code string `json:"code"`
			}
			h.do(http.MethodPost, "/api/v1/group-mappings", map[string]any{
				"group_name": group, "role": "viewer", "reason": reason,
				// A missing reason is a defect of the request, not of the
				// session: re-authentication would not fix it.
			}, &problem, http.StatusBadRequest)
			if problem.Code != "reason_required" {
				t.Errorf("code = %q, expected reason_required", problem.Code)
			}
		})
	}

	var mapping struct {
		ID string `json:"id"`
	}
	reason := "granting the viewer role to the test team"
	h.do(http.MethodPost, "/api/v1/group-mappings", map[string]any{
		"group_name": group, "role": "viewer", "reason": reason,
	}, &mapping, http.StatusCreated)
	t.Cleanup(func() {
		h.do(http.MethodDelete,
			"/api/v1/group-mappings/"+mapping.ID+"?reason=cleanup+after+the+integration+test",
			nil, nil, http.StatusNoContent)
	})

	// Deletion is the same change of an access rule, so the condition is the
	// same.
	var problem struct {
		Code string `json:"code"`
	}
	h.do(http.MethodDelete, "/api/v1/group-mappings/"+mapping.ID, nil, &problem, http.StatusBadRequest)
	if problem.Code != "reason_required" {
		t.Errorf("deletion without a reason: code = %q", problem.Code)
	}

	// The audit trail must carry the reason and the basis on which the
	// operation passed. An automated identity cannot be described as
	// re-authenticated, because there is no human behind it.
	var audit struct {
		Items []struct {
			Action  string         `json:"action"`
			Outcome string         `json:"outcome"`
			Detail  map[string]any `json:"detail"`
		} `json:"items"`
	}
	h.get("/api/v1/audit?limit=50", &audit)

	found := false
	for _, event := range audit.Items {
		if event.Action != "group_mapping.create" || event.Outcome != "success" {
			continue
		}
		if event.Detail["group"] != group {
			continue
		}
		found = true
		if event.Detail["purpose"] != reason {
			t.Errorf("the audit entry does not carry the reason: %+v", event.Detail)
		}
		if event.Detail["authentication"] != "api_token" {
			t.Errorf("the audit entry does not tell a token from a session: %+v", event.Detail)
		}
		if event.Detail["reauthenticated"] != false {
			t.Errorf("the audit entry attributes re-authentication to a token: %+v", event.Detail)
		}
		if _, present := event.Detail["acr"]; present {
			t.Errorf("the audit entry attributes an authentication level to a token: %+v", event.Detail)
		}
	}
	if !found {
		t.Fatalf("no audit entry about creating the mapping of group %s", group)
	}

	// A refusal leaves a trace too: an attempt to change an access rule is
	// an event worth recording regardless of the outcome.
	denials := 0
	for _, event := range audit.Items {
		if event.Action == "group_mapping.create" && event.Outcome == "denied" {
			denials++
		}
	}
	if denials == 0 {
		t.Error("the refusals for a missing reason did not reach the audit log")
	}
}
