//go:build integration

package integration

// The signed capability of the root helper (chapter 3 of the remediation
// document).

import (
	"testing"
	"time"
)

// TestAUnitRestartCarriesAVerifiedHelperCapability: a service restart ordered
// through the API succeeds under prefer, and the dispatch event on the trail
// names the capability the helper verified.
func TestAUnitRestartCarriesAVerifiedHelperCapability(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	job, attempts := h.runOperation(host.ID, map[string]any{
		"action":  "unit.restart",
		"payload": unitPayload("cron.service"),
	}, 90*time.Second)
	if job.State != "succeeded" {
		t.Fatalf("state = %s, error code = %s: %s", job.State, job.ResultErrorCode, job.ResultMessage)
	}
	if len(attempts) == 0 {
		t.Fatal("no recorded execution attempt")
	}

	var page auditPage
	h.get("/api/v1/audit?action=job.dispatch&target_id="+job.ID+"&limit=5", &page)
	if len(page.Items) == 0 {
		t.Fatal("no job.dispatch event for the job")
	}
	var detail hostView
	h.get("/api/v1/hosts/"+host.ID, &detail)
	supported := helperCapabilitySupported(detail)
	for _, event := range page.Items {
		id, _ := event.Detail["capability_id"].(string)
		switch {
		case supported && id == "":
			t.Errorf("the dispatch of %s to a host that forwards capabilities names no capability_id: %v", job.ID, event.Detail)
		case !supported && id != "":
			t.Errorf("the dispatch of %s to a host without the support names a capability: %v", job.ID, event.Detail)
		}
		if id != "" {
			if key, _ := event.Detail["capability_key_id"].(string); key == "" {
				t.Errorf("the dispatch names the capability %s without its key", id)
			}
		}
	}
}

// TestTheHostReportsItsHelperCapabilityMode: the host detail lists the helper.
func TestTheHostReportsItsHelperCapabilityMode(t *testing.T) {
	h := newHarness(t)
	for _, family := range []string{"debian", "rhel"} {
		host := h.hostByFamily(family)
		var detail hostView
		h.get("/api/v1/hosts/"+host.ID, &detail)
		var adapter *hostCapability
		for i := range detail.Capabilities {
			if detail.Capabilities[i].Name == "helper.capability" {
				adapter = &detail.Capabilities[i]
			}
		}
		if adapter == nil {
			t.Errorf("%s: the host lists no helper.capability adapter (agent from before the capability?)", family)
			continue
		}
		if !adapter.Available {
			t.Errorf("%s: the adapter is reported unavailable: %s", family, adapter.Reason)
		}
		modes := 0
		for _, mode := range []string{"observe", "prefer", "enforce"} {
			if adapter.Features[mode] {
				modes++
			}
		}
		switch {
		case modes > 1:
			t.Errorf("%s: more than one mode is reported: %v", family, adapter.Features)
		case modes == 0 && adapter.Reason == "":
			t.Errorf("%s: no mode and no reason for it", family)
		case modes == 0:
			t.Logf("%s: the helper has not reported its mode yet: %s", family, adapter.Reason)
		}
	}
}

// helperCapabilitySupported says whether the host announced the support.
func helperCapabilitySupported(host hostView) bool {
	for _, capability := range host.Capabilities {
		if capability.Name == "helper.capability" && capability.Available {
			return true
		}
	}
	return false
}
