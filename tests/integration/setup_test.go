//go:build integration

package integration

import (
	"net/http"
	"testing"
)

// setupView mirrors the first-run checklist.
type setupView struct {
	Steps []struct {
		Key    string `json:"key"`
		State  string `json:"state"`
		Detail string `json:"detail"`
		Path   string `json:"path"`
	} `json:"steps"`
	Done          int    `json:"done"`
	Total         int    `json:"total"`
	Complete      bool   `json:"complete"`
	Next          string `json:"next"`
	BootstrapLive bool   `json:"bootstrap_live"`
}

// connectionTestView mirrors the answer of a test button.
type connectionTestView struct {
	OK        bool   `json:"ok"`
	Reason    string `json:"reason"`
	Detail    string `json:"detail"`
	Summary   string `json:"summary"`
	ElapsedMS int64  `json:"elapsed_ms"`
	Provider  *struct {
		Issuer string `json:"issuer"`
		Keys   int    `json:"keys"`
	} `json:"provider"`
	Connector *struct {
		Principal      string `json:"principal"`
		KeytabReadable bool   `json:"keytab_readable"`
	} `json:"connector"`
}

// The keys every checklist carries, in the order the steps are taken. A
// step the installation lacks is still listed, as optional: the screen
// is a fixed list with states, not a list that shrinks.
var setupStepKeys = []string{
	"identity_provider", "group_mapping", "bootstrap_token", "directory", "hosts",
	"relay", "policy", "alert_rule", "notification_channel", "fleet_ca",
}

// TestSetupChecklistNamesEveryStep checks that the checklist lists the
// steps in order, each with a state, a sentence and a page, and that the
// lab - which has group mappings and hosts - reports those two as done.
func TestSetupChecklistNamesEveryStep(t *testing.T) {
	h := newHarness(t)
	var checklist setupView
	h.get("/api/v1/setup", &checklist)

	if len(checklist.Steps) != len(setupStepKeys) {
		t.Fatalf("expected %d steps, got %d", len(setupStepKeys), len(checklist.Steps))
	}
	states := map[string]string{}
	for i, step := range checklist.Steps {
		if step.Key != setupStepKeys[i] {
			t.Errorf("step %d is %q, expected %q", i, step.Key, setupStepKeys[i])
		}
		switch step.State {
		case "done", "undone", "warning", "optional":
		default:
			t.Errorf("step %s has the state %q", step.Key, step.State)
		}
		if step.Detail == "" || step.Path == "" {
			t.Errorf("step %s lacks a detail or a path: %+v", step.Key, step)
		}
		states[step.Key] = step.State
	}
	if states["group_mapping"] != "done" {
		t.Errorf("the lab has group mappings; the step reads %q", states["group_mapping"])
	}
	if states["hosts"] != "done" {
		t.Errorf("the lab has enrolled hosts; the step reads %q", states["hosts"])
	}
	if checklist.Total == 0 || checklist.Done > checklist.Total {
		t.Errorf("the counters make no sense: %d of %d", checklist.Done, checklist.Total)
	}
	if checklist.Complete != (checklist.Next == "") {
		t.Errorf("complete=%v disagrees with next=%q", checklist.Complete, checklist.Next)
	}
	// The next step is the first undone one, never a warning or an
	// optional step: those do not hold the fleet back.
	for _, step := range checklist.Steps {
		if step.State == "undone" {
			if checklist.Next != step.Key {
				t.Errorf("next is %q, but the first undone step is %q", checklist.Next, step.Key)
			}
			break
		}
	}
}

// TestSetupChecklistIsReadByAViewer checks that the checklist needs no
// permission beyond a valid identity: a viewer sees the same list, read
// only, while the test buttons stay behind their permissions.
func TestSetupChecklistIsReadByAViewer(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	viewer := h.withToken(h.createPrincipal(uniqueSubject("setup-viewer"), []map[string]string{
		{"role": "viewer", "site": host.Site, "environment": host.Environment},
	}))

	var checklist setupView
	viewer.get("/api/v1/setup", &checklist)
	if len(checklist.Steps) != len(setupStepKeys) {
		t.Fatalf("the viewer got %d steps, expected %d", len(checklist.Steps), len(setupStepKeys))
	}
	// The identity provider test reveals the issuer and the key count;
	// that is the settings screen's information, not a viewer's.
	viewer.do(http.MethodPost, "/api/v1/setup/test-oidc", nil, nil, http.StatusForbidden)

	// Without a token there is no checklist either.
	h.withToken("").do(http.MethodGet, "/api/v1/setup", nil, nil, http.StatusUnauthorized)
}

// TestSetupDirectoryTestAnswersWithAVerdict checks that the directory test
// answers 200 either way: ok with the directory's own summary when the
// connector reaches it, or a typed reason when it does not - never a bare
// server error, because an unreachable directory is a finding.
func TestSetupDirectoryTestAnswersWithAVerdict(t *testing.T) {
	h := newHarness(t)
	var result connectionTestView
	h.do(http.MethodPost, "/api/v1/setup/test-directory", nil, &result, http.StatusOK)
	if result.OK {
		if result.Summary == "" || result.Connector == nil || result.Connector.Principal == "" {
			t.Errorf("a passed test names the summary and the connector: %+v", result)
		}
		return
	}
	switch result.Reason {
	case "directory_disabled", "directory_unreachable", "keytab_unreadable":
	default:
		t.Errorf("a failed test carries a typed reason, got %q (%s)", result.Reason, result.Detail)
	}
}

// TestSetupIdentityProviderTestAnswersWithAVerdict checks the same of the
// identity provider test: the lab's Keycloak answers with its issuer and
// at least one signing key, and a panel without a provider says so.
func TestSetupIdentityProviderTestAnswersWithAVerdict(t *testing.T) {
	h := newHarness(t)
	var result connectionTestView
	h.do(http.MethodPost, "/api/v1/setup/test-oidc", nil, &result, http.StatusOK)
	if result.OK {
		if result.Provider == nil || result.Provider.Issuer == "" || result.Provider.Keys == 0 {
			t.Errorf("a passed test names the issuer and counts the keys: %+v", result)
		}
		return
	}
	switch result.Reason {
	case "oidc_disabled", "discovery_unreachable", "issuer_mismatch", "jwks_missing", "jwks_unreachable", "jwks_empty":
	default:
		t.Errorf("a failed test carries a typed reason, got %q (%s)", result.Reason, result.Detail)
	}
}
