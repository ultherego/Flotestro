//go:build integration

package integration

import (
	"net/http"
	"strings"
	"testing"
)

const recordReason = "integration test of the directory DNS records"

type zoneView struct {
	Name    string `json:"name"`
	Reverse bool   `json:"reverse"`
}

type recordView struct {
	Zone   string   `json:"zone"`
	Name   string   `json:"name"`
	Type   string   `json:"type"`
	Values []string `json:"values"`
}

type directoryChange struct {
	ID    string `json:"id"`
	State string `json:"state"`
	Plan  struct {
		Summary   string   `json:"summary"`
		Steps     []string `json:"steps"`
		Conflicts []string `json:"conflicts"`
	} `json:"plan"`
}

// directoryAvailable says whether the installation has a directory
// connection.
func directoryAvailable(t *testing.T, h *harness) bool {
	t.Helper()
	var state struct {
		Configured bool `json:"configured"`
		Reachable  bool `json:"reachable"`
	}
	h.get("/api/v1/identity/status", &state)
	return state.Configured && state.Reachable
}

// TestDirectoryRecordPlansTheReverseRecord guards the rule that is skipped
// most often: the PTR record is a separate, visible plan step, not a detail
// of writing the A record.
func TestDirectoryRecordPlansTheReverseRecord(t *testing.T) {
	h := newHarness(t)
	if !directoryAvailable(t, h) {
		t.Skip("this installation has no directory connection")
	}

	var zones struct {
		Items []zoneView `json:"items"`
	}
	h.get("/api/v1/identity/dns/zones", &zones)
	var zone string
	for _, item := range zones.Items {
		if !item.Reverse {
			zone = item.Name
			break
		}
	}
	if zone == "" {
		t.Skip("the directory has no forward zone")
	}

	var change directoryChange
	h.do(http.MethodPost, "/api/v1/identity/changes", map[string]any{
		"action": "dns.record.ensure",
		"payload": map[string]any{"dns": map[string]any{
			"zone": zone, "name": "flotestro-test", "type": "A",
			"value": "192.168.56.199", "reverse": true,
		}},
	}, &change, http.StatusCreated)
	t.Cleanup(func() {
		h.do(http.MethodPost, "/api/v1/identity/changes/"+change.ID+"/cancel", nil, nil, 0)
	})

	// The plan must list both records separately: forward and reverse.
	if len(change.Plan.Steps) < 2 {
		t.Fatalf("the plan has %d steps: %+v", len(change.Plan.Steps), change.Plan.Steps)
	}
	reverse := false
	for _, step := range change.Plan.Steps {
		if strings.Contains(step, "PTR") {
			reverse = true
		}
	}
	if !reverse {
		t.Fatalf("the plan does not list the reverse record: %+v", change.Plan.Steps)
	}
}

// TestDirectoryRecordRejectsBadMaterial guards the boundary: a record the
// directory would reject is to fall out when ordered, not after approval.
func TestDirectoryRecordRejectsBadMaterial(t *testing.T) {
	h := newHarness(t)
	if !directoryAvailable(t, h) {
		t.Skip("this installation has no directory connection")
	}

	bad := map[string]map[string]any{
		"an address that is a name": {
			"zone": "flotestro.test", "name": "web", "type": "A", "value": "web.example.test",
		},
		"a type the panel does not write": {
			"zone": "flotestro.test", "name": "@", "type": "NS", "value": "ipa.flotestro.test.",
		},
		"a zone name with a space": {
			"zone": "flotestro test", "name": "web", "type": "A", "value": "10.0.0.5",
		},
		"a reverse record for a CNAME": {
			"zone": "flotestro.test", "name": "alias", "type": "CNAME",
			"value": "web.flotestro.test.", "reverse": true,
		},
	}
	for name, payload := range bad {
		t.Run(name, func(t *testing.T) {
			h.do(http.MethodPost, "/api/v1/identity/changes", map[string]any{
				"action": "dns.record.ensure", "reason": recordReason,
				"payload": map[string]any{"dns": payload},
			}, nil, http.StatusBadRequest)
		})
	}
}
