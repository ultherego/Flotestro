//go:build integration

package integration

import (
	"net/http"
	"testing"
)

const hostnameReason = "integration test of the hostname operation"

// TestHostnameSetIsGuarded checks the gates of a rename without renaming a lab
// host: a name the host would refuse is refused when the order is placed.
func TestHostnameSetIsGuarded(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	// Neither of these orders comes into being: validation refuses the
	// name before a job exists, so nothing waits for approval.
	for name, hostname := range map[string]string{
		"upper case":  "Web02",
		"a space":     "web 02",
		"a shell":     "web02;reboot",
		"localhost":   "localhost",
		"empty":       "",
		"a bad label": "-web02",
	} {
		t.Run(name, func(t *testing.T) {
			var problem struct {
				Code string `json:"code"`
			}
			h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations", map[string]any{
				"action": "system.hostname.set", "reason": hostnameReason,
				"target_confirmation": host.Hostname,
				"payload":             map[string]any{"hostname": map[string]any{"hostname": hostname}},
			}, &problem, http.StatusBadRequest)
			if problem.Code != "invalid_payload" {
				t.Errorf("code = %q, expected invalid_payload", problem.Code)
			}
		})
	}

	// A valid name without the typed target: a click is not a decision to
	// take a name away from everything that knows the host by it.
	var problem struct {
		Code string `json:"code"`
	}
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations", map[string]any{
		"action": "system.hostname.set", "reason": hostnameReason,
		"payload": map[string]any{"hostname": map[string]any{"hostname": "renamed-by-a-test"}},
	}, &problem, http.StatusBadRequest)
	if problem.Code != "target_confirmation_required" {
		t.Errorf("code = %q, expected target_confirmation_required", problem.Code)
	}

	// The catalogue lists the operation with its contract.
	var catalogue struct {
		Items []struct {
			Action       string `json:"action"`
			Mutating     bool   `json:"mutating"`
			Risk         string `json:"risk"`
			LockClass    string `json:"lock_class"`
			CampaignMode string `json:"campaign_mode"`
			CancelMode   string `json:"cancel_mode"`
			Rollback     string `json:"rollback"`
		} `json:"items"`
	}
	h.get("/api/v1/actions", &catalogue)
	found := false
	for _, item := range catalogue.Items {
		if item.Action != "system.hostname.set" {
			continue
		}
		found = true
		if !item.Mutating || item.Risk != "critical" {
			t.Errorf("the rename is listed as mutating=%v risk=%s", item.Mutating, item.Risk)
		}
		if item.CancelMode != "impossible_after_start" {
			t.Errorf("cancel_mode = %q, expected impossible_after_start", item.CancelMode)
		}
		if item.LockClass != "host" {
			t.Errorf("lock_class = %q, expected host", item.LockClass)
		}
		// A rename runs in a campaign only with a name per host: the plan
		// of every target is the name the order gave it.
		if item.CampaignMode != "per_host_plan" {
			t.Errorf("campaign_mode = %q, expected per_host_plan: a rename names every host", item.CampaignMode)
		}
	}
	if !found {
		t.Fatal("the catalogue does not list system.hostname.set")
	}

	// The other new operations are listed as well, each with a contract.
	listed := map[string]bool{}
	for _, item := range catalogue.Items {
		listed[item.Action] = true
	}
	for _, action := range []string{
		"docker.container.logs", "localuser.groups.set", "localuser.expiry.set",
		"localuser.delete", "storage.smart.read",
	} {
		if !listed[action] {
			t.Errorf("the catalogue does not list %s", action)
		}
	}
}
