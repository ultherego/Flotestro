//go:build integration

package integration

import (
	"net/http"
	"testing"
)

// TestChangingAccessRulesRequiresAReason checks the condition of the operation
// with the greatest impact.
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

	// The audit trail must carry the reason and the basis on which the operation
	// passed.
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

// TestApprovingACriticalPayloadRequiresAReason is the other half of the rule
// the panel now follows: fresh authentication is demanded of an approval of a
// critical or destructive payload, and the step-up policy demands a reason
// with it.
//
// The approval used to pass with nothing but the payload hash, so the record
// of the riskiest consent in the product said who and what, never why. Two
// call sites of the panel sent no reason at all, which is the half of this
// change the suite is here to keep: a rule the interface cannot satisfy is a
// rule that gets reverted.
func TestApprovingACriticalPayloadRequiresAReason(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	// A reboot is critical by classification and asks only for systemd, so it
	// is the cheapest critical payload to order. It is never approved here, and
	// the job is cancelled at the end of the test, so no host restarts for it.
	job := h.createOperation(host.ID, map[string]any{
		"action": "system.reboot", "reason": "ordering a critical payload to test its approval",
		"payload": map[string]any{"reboot": map[string]any{
			"delay_seconds": 3600, "reason": "Flotestro: never approved, this job is cancelled",
		}},
	})
	if !job.RequiresApproval {
		absent(h.t, "this installation does not hold a reboot for approval, so there is no approval to test")
	}
	t.Cleanup(func() {
		h.do(http.MethodPost, "/api/v1/jobs/"+job.ID+"/cancel",
			map[string]any{"reason": "cleanup after the approval reason test"}, nil, http.StatusOK)
	})

	for name, reason := range map[string]string{
		"no reason":        "",
		"reason too short": "because",
	} {
		t.Run(name, func(t *testing.T) {
			var problem struct {
				Code string `json:"code"`
			}
			body := map[string]any{"payload_hash": job.PayloadHash}
			if reason != "" {
				body["reason"] = reason
			}
			h.do(http.MethodPost, "/api/v1/jobs/"+job.ID+"/approve", body, &problem, http.StatusBadRequest)
			if problem.Code != "reason_required" {
				t.Errorf("code = %q, expected reason_required", problem.Code)
			}
		})
	}
}
