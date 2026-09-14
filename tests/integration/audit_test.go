//go:build integration

package integration

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/audit"
)

// TestReadingTheTrailIsOnTheTrail checks that a read of the audit log is
// itself an audit event, with the filter it asked with: whoever looked at
// what somebody did is part of the story of an incident.
func TestReadingTheTrailIsOnTheTrail(t *testing.T) {
	h := newHarness(t)
	marker := uniqueSubject("nobody")

	// A read narrowed to an actor that does not exist returns nothing -
	// and still leaves an event naming the filter.
	var empty auditPage
	h.get("/api/v1/audit?actor="+marker+"&limit=5", &empty)
	if len(empty.Items) != 0 {
		t.Fatalf("a made-up actor has %d events", len(empty.Items))
	}

	var reads auditPage
	h.get("/api/v1/audit?action=audit.read&limit=50", &reads)
	found := false
	for _, event := range reads.Items {
		if event.Detail["filter_actor"] == marker {
			found = true
			if event.Outcome != "success" {
				t.Errorf("the read is recorded as %s", event.Outcome)
			}
			if event.Detail["limit"] != float64(5) {
				t.Errorf("the read does not carry its limit: %v", event.Detail)
			}
		}
	}
	if !found {
		t.Fatal("the read of the trail left no event on the trail")
	}
}

// TestTheExportChainVerifies checks that an export of the trail is a file
// whose hash chain the offline verifier accepts, and that the export
// itself is on the trail.
func TestTheExportChainVerifies(t *testing.T) {
	h := newHarness(t)
	since := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	file := h.text("/api/v1/audit/export?since=" + since)

	report, err := audit.VerifyChain(strings.NewReader(file))
	if err != nil {
		t.Fatalf("the export does not verify: %v\n%s", err, truncate([]byte(file), 600))
	}
	if report.Count == 0 {
		t.Fatal("the export of the last hour holds no events")
	}
	lines := strings.Split(strings.TrimSpace(file), "\n")
	if int64(len(lines)) != report.Count+1 {
		t.Errorf("%d lines for %d events and a closing line", len(lines), report.Count)
	}
	if !strings.HasPrefix(lines[len(lines)-1], `{"count":`) {
		t.Errorf("the closing line = %s", lines[len(lines)-1])
	}

	// A file somebody edited must not pass: the chain is the whole point.
	tampered := strings.Replace(file, `"outcome":"success"`, `"outcome":"denied"`, 1)
	if tampered == file {
		t.Skip("no successful event to tamper with")
	}
	if _, err := audit.VerifyChain(strings.NewReader(tampered)); err == nil {
		t.Error("a tampered export verified")
	}

	var exports auditPage
	h.get("/api/v1/audit?action=audit.export&limit=20", &exports)
	found := false
	for _, event := range exports.Items {
		if event.Detail["filter_since"] == since {
			found = true
		}
	}
	if !found {
		t.Error("the export left no event on the trail")
	}
}

// TestAnExpiredBindingGrantsNothingAtTheDoor checks that a role bound with
// a validity already past grants nothing, and that one with time left
// grants as before.
func TestAnExpiredBindingGrantsNothingAtTheDoor(t *testing.T) {
	h := newHarness(t)
	yesterday := time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339)
	tomorrow := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)

	expired := h.withToken(h.createPrincipal(uniqueSubject("expired-viewer"), []map[string]string{
		{"role": "viewer", "valid_until": yesterday},
	}))
	expired.do(http.MethodGet, "/api/v1/hosts", nil, nil, http.StatusForbidden)

	var whoami struct {
		Bindings []struct {
			Role string `json:"role"`
		} `json:"bindings"`
	}
	expired.get("/api/v1/whoami", &whoami)
	if len(whoami.Bindings) != 0 {
		t.Errorf("the expired binding is still part of the identity: %+v", whoami.Bindings)
	}

	live := h.withToken(h.createPrincipal(uniqueSubject("rotation-viewer"), []map[string]string{
		{"role": "viewer", "valid_until": tomorrow},
	}))
	live.do(http.MethodGet, "/api/v1/hosts", nil, nil, http.StatusOK)

	// A date that is not a date is the caller's mistake, not "no date".
	var problem struct {
		Code string `json:"code"`
	}
	h.do(http.MethodPost, "/api/v1/principals", map[string]any{
		"subject": uniqueSubject("bad-date"),
		"roles":   []map[string]string{{"role": "viewer", "valid_until": "next tuesday"}},
		"reason":  "identity prepared for an integration test",
	}, &problem, http.StatusBadRequest)
	if problem.Code != "invalid_binding" {
		t.Errorf("code = %q, expected invalid_binding", problem.Code)
	}
}

// TestTheAccessReviewFlagsAFreshAdministrator checks that the review lists
// every identity with what the reviewer should look at: an administrator
// without an expiry is a question, whatever the answer turns out to be.
func TestTheAccessReviewFlagsAFreshAdministrator(t *testing.T) {
	h := newHarness(t)
	admin := uniqueSubject("review-admin")
	h.createPrincipal(admin, []map[string]string{{"role": "platform_admin"}})
	ended := uniqueSubject("review-ended")
	h.createPrincipal(ended, []map[string]string{
		{"role": "operator", "valid_until": time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)},
	})

	var review struct {
		Items []struct {
			Subject  string   `json:"subject"`
			Flags    []string `json:"flags"`
			Bindings []struct {
				Role    string `json:"role"`
				Expired bool   `json:"expired"`
			} `json:"bindings"`
		} `json:"items"`
		Flagged int `json:"flagged"`
	}
	h.get("/api/v1/access/review", &review)

	seenAdmin, seenEnded := false, false
	for _, item := range review.Items {
		switch item.Subject {
		case admin:
			seenAdmin = true
			if !contains(item.Flags, "admin_without_expiry") {
				t.Errorf("the fresh administrator carries the flags %v", item.Flags)
			}
			if contains(item.Flags, "unused_90_days") {
				t.Errorf("an identity created a moment ago is flagged as unused: %v", item.Flags)
			}
		case ended:
			seenEnded = true
			if len(item.Bindings) != 1 || !item.Bindings[0].Expired {
				t.Errorf("the ended binding is not shown as expired: %+v", item.Bindings)
			}
		}
	}
	if !seenAdmin || !seenEnded {
		t.Fatalf("the review lacks the test identities (admin %v, ended %v)", seenAdmin, seenEnded)
	}
	if review.Flagged == 0 {
		t.Error("the review counts nothing as flagged")
	}

	// The same review as a file for the record, one row per identity.
	csv := h.text("/api/v1/access/review?format=csv")
	if !strings.HasPrefix(csv, "subject,") {
		t.Errorf("the CSV does not start with its header: %s", truncate([]byte(csv), 100))
	}
	if !strings.Contains(csv, admin) || !strings.Contains(csv, "admin_without_expiry") {
		t.Errorf("the CSV lacks the administrator or the flag")
	}

	// Making a review is on the trail: an auditor asks when access was
	// last reviewed before anything else.
	var reviews auditPage
	h.get("/api/v1/audit?action=access.review&limit=5", &reviews)
	if len(reviews.Items) == 0 {
		t.Error("the review left no event on the trail")
	}
}

// TestSettingsMaskTheSecrets checks that the settings screen names the
// identity provider and shows the client secret as set or not, never as
// its value.
func TestSettingsMaskTheSecrets(t *testing.T) {
	h := newHarness(t)
	var settings struct {
		Source string `json:"source"`
		Areas  []struct {
			Key   string `json:"key"`
			Facts []struct {
				Key        string `json:"key"`
				Value      any    `json:"value"`
				Secret     bool   `json:"secret"`
				Configured *bool  `json:"configured"`
			} `json:"facts"`
		} `json:"areas"`
	}
	h.get("/api/v1/settings", &settings)
	if settings.Source == "" {
		t.Error("the settings do not say where they are set")
	}

	var issuer, secret any
	var secretMarked bool
	var configured *bool
	for _, area := range settings.Areas {
		if area.Key != "identity" {
			continue
		}
		for _, fact := range area.Facts {
			switch fact.Key {
			case "issuer":
				issuer = fact.Value
			case "client_secret":
				secret, secretMarked, configured = fact.Value, fact.Secret, fact.Configured
			}
		}
	}
	if issuer == nil {
		t.Fatal("the settings lack the identity provider")
	}
	if name, _ := issuer.(string); name == "" {
		t.Error("the settings do not name the issuer; the test fleet has a provider")
	}
	if !secretMarked || configured == nil {
		t.Errorf("the client secret is not marked as a secret: %v", secret)
	}
	if value, _ := secret.(string); value != "" && value != "********" {
		t.Errorf("the client secret is shown: %q", value)
	}

	// The screen is for whoever administers the panel, not for a viewer.
	viewer := h.withToken(h.createPrincipal(uniqueSubject("settings-viewer"), []map[string]string{
		{"role": "viewer"},
	}))
	viewer.do(http.MethodGet, "/api/v1/settings", nil, nil, http.StatusForbidden)
}

func contains(items []string, wanted string) bool {
	for _, item := range items {
		if item == wanted {
			return true
		}
	}
	return false
}
