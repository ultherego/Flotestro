//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

type secretVersionView struct {
	Version   int        `json:"version"`
	SizeBytes int        `json:"size_bytes"`
	CreatedBy string     `json:"created_by"`
	Destroyed *time.Time `json:"destroyed_at"`
}

type secretView struct {
	ID             string              `json:"id"`
	Name           string              `json:"name"`
	Description    string              `json:"description"`
	CurrentVersion int                 `json:"current_version"`
	CreatedBy      string              `json:"created_by"`
	RetiredAt      *time.Time          `json:"retired_at"`
	Versions       []secretVersionView `json:"versions"`
}

type managedFileView struct {
	Path                 string `json:"path"`
	DesiredSHA256        string `json:"desired_sha256"`
	DesiredSecret        string `json:"desired_secret"`
	DesiredSecretVersion int    `json:"desired_secret_version"`
	ObservedSHA256       string `json:"observed_sha256"`
	Exists               bool   `json:"exists"`
	Drift                bool   `json:"drift"`
	DriftUnknownReason   string `json:"drift_unknown_reason"`
}

const secretReason = "integration test of the secret store"

// newSecret creates a secret with a name unique to the run and makes sure it
// is retired after the test.
func newSecret(t *testing.T, h *harness, value string) secretView {
	t.Helper()
	name := fmt.Sprintf("integration.%d", time.Now().UnixNano())
	var secret secretView
	h.do(http.MethodPost, "/api/v1/secrets", map[string]any{
		"name": name, "description": secretReason, "value": value,
	}, &secret, http.StatusCreated)
	t.Cleanup(func() {
		h.do(http.MethodPost, "/api/v1/secrets/"+name+"/retire", nil, nil, 0)
	})
	return secret
}

// TestSecretValueDoesNotLeaveThroughTheAPI guards the property the store
// exists for in the first place: the value goes in and does not come out.
func TestSecretValueDoesNotLeaveThroughTheAPI(t *testing.T) {
	h := newHarness(t)
	value := "this-must-not-be-in-the-response-" + fmt.Sprint(time.Now().UnixNano())
	secret := newSecret(t, h, value)

	if secret.CurrentVersion != 1 || len(secret.Versions) != 1 {
		t.Fatalf("secret after creation = %+v", secret)
	}
	// The size is metadata, so it may be shown; the content may not.
	if secret.Versions[0].SizeBytes != len(value) {
		t.Errorf("version size = %d, the value has %d bytes",
			secret.Versions[0].SizeBytes, len(value))
	}

	// Neither the list nor the details may carry the value anywhere.
	for _, path := range []string{"/api/v1/secrets", "/api/v1/secrets/" + secret.Name} {
		var raw json.RawMessage
		h.do(http.MethodGet, path, nil, &raw, http.StatusOK)
		if strings.Contains(string(raw), value) {
			t.Fatalf("%s returned the secret value", path)
		}
	}
}

// TestSecretMustExistBeforeOrdering guards that a typo in the name falls out
// when ordered, not minutes later on the host.
func TestSecretMustExistBeforeOrdering(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	secret := newSecret(t, h, "value-for-the-boundary-test")

	// A non-existent secret.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations", map[string]any{
		"action": "file.ensure", "reason": secretReason,
		"payload": map[string]any{"file": map[string]any{
			"path": "/etc/flotestro-test.conf", "mode": "600",
			"content_secret": map[string]any{"name": "no.such.secret"},
		}},
	}, nil, http.StatusBadRequest)

	// A version out of range.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations", map[string]any{
		"action": "file.ensure", "reason": secretReason,
		"payload": map[string]any{"file": map[string]any{
			"path": "/etc/flotestro-test.conf", "mode": "600",
			"content_secret": map[string]any{"name": secret.Name, "version": 99},
		}},
	}, nil, http.StatusBadRequest)

	// Plain content and a secret at once: it is unclear what lands in the
	// file.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations", map[string]any{
		"action": "file.ensure", "reason": secretReason,
		"payload": map[string]any{"file": map[string]any{
			"path": "/etc/flotestro-test.conf", "mode": "600", "content": "plain content",
			"content_secret": map[string]any{"name": secret.Name},
		}},
	}, nil, http.StatusBadRequest)

	// A retired secret can no longer be issued.
	h.do(http.MethodPost, "/api/v1/secrets/"+secret.Name+"/retire", nil, nil, http.StatusOK)
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations", map[string]any{
		"action": "file.ensure", "reason": secretReason,
		"payload": map[string]any{"file": map[string]any{
			"path": "/etc/flotestro-test.conf", "mode": "600",
			"content_secret": map[string]any{"name": secret.Name},
		}},
	}, nil, http.StatusConflict)
}

// TestRotationKeepsTheOlderVersions checks that a rotation adds a version
// rather than replacing the only one: a host with a lease on an earlier
// version is to get it.
func TestRotationKeepsTheOlderVersions(t *testing.T) {
	h := newHarness(t)
	secret := newSecret(t, h, "first-value")

	var afterRotation secretView
	h.do(http.MethodPost, "/api/v1/secrets/"+secret.Name+"/rotate",
		map[string]any{"value": "second-value"}, &afterRotation, http.StatusOK)
	if afterRotation.CurrentVersion != 2 || len(afterRotation.Versions) != 2 {
		t.Fatalf("secret after the rotation = %+v", afterRotation)
	}

	// Destroying a version leaves a trace that it existed.
	var afterDestruction secretView
	h.do(http.MethodDelete, "/api/v1/secrets/"+secret.Name+"/versions/1", nil,
		&afterDestruction, http.StatusOK)
	var version1 secretVersionView
	for _, version := range afterDestruction.Versions {
		if version.Version == 1 {
			version1 = version
		}
	}
	if version1.Version != 1 || version1.Destroyed == nil {
		t.Errorf("version 1 after destruction = %+v", version1)
	}
	if afterDestruction.CurrentVersion != 2 {
		t.Errorf("destroying the old version moved the current version: %d", afterDestruction.CurrentVersion)
	}
}

// TestFileFromASecretLeavesNoValueInThePanel is a whole-path test: the value
// reaches the host, and the panel holds neither it nor its digest.
func TestFileFromASecretLeavesNoValueInThePanel(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	value := "integration-test-value-" + fmt.Sprint(time.Now().UnixNano())
	secret := newSecret(t, h, value)
	path := "/etc/flotestro-secret-test.conf"

	t.Cleanup(func() {
		h.runOperation(host.ID, map[string]any{
			"action": "file.remove", "reason": secretReason,
			"payload": map[string]any{"file": map[string]any{"path": path}},
		}, 2*time.Minute)
	})

	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "file.ensure", "reason": secretReason,
		"payload": map[string]any{"file": map[string]any{
			"path": path, "mode": "600",
			"content_secret": map[string]any{"name": secret.Name},
		}},
	}, 2*time.Minute)
	if job.State != "succeeded" {
		t.Fatalf("write from a secret: state = %s, %s", job.State, lastMessage(attempts))
	}

	// The job carries a reference, never the value.
	var raw json.RawMessage
	h.do(http.MethodGet, "/api/v1/jobs/"+job.ID, nil, &raw, http.StatusOK)
	if strings.Contains(string(raw), value) {
		t.Error("the secret value ended up in the job")
	}
	if !strings.Contains(string(raw), secret.Name) {
		t.Error("the job does not carry the secret reference")
	}
	// The attempt result must not carry it either.
	h.do(http.MethodGet, "/api/v1/jobs/"+job.ID+"/attempts", nil, &raw, http.StatusOK)
	if strings.Contains(string(raw), value) {
		t.Error("the secret value ended up in the attempt result")
	}

	// The desired state is the secret name and version - without a content
	// digest.
	var files struct {
		Items []managedFileView `json:"items"`
	}
	h.do(http.MethodGet, "/api/v1/hosts/"+host.ID+"/files", nil, &files, http.StatusOK)
	var view managedFileView
	for _, file := range files.Items {
		if file.Path == path {
			view = file
		}
	}
	if view.Path == "" {
		t.Fatal("the panel did not record the desired state of the file")
	}
	if view.DesiredSecret != secret.Name || view.DesiredSecretVersion != 1 {
		t.Errorf("desired state = %+v", view)
	}
	if view.DesiredSHA256 != "" {
		t.Error("the panel recorded the digest of content that came from the store")
	}
	// The panel does not pretend a conformance it did not check.
	if view.Drift {
		t.Error("the panel reports drift of a file whose content it does not compare")
	}
	if view.DriftUnknownReason == "" {
		t.Error("no content comparison without an explanation")
	}
	// The host does not report the digest of such a file either.
	if view.ObservedSHA256 != "" {
		t.Error("the host reported the digest of content that came from the store")
	}

	// The audit trail holds the fact of issuing, not the value.
	var audit json.RawMessage
	h.do(http.MethodGet, "/api/v1/hosts/"+host.ID+"/audit?limit=50", nil, &audit, http.StatusOK)
	if strings.Contains(string(audit), value) {
		t.Error("the secret value ended up in the audit log")
	}
}
