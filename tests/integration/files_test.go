//go:build integration

package integration

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

type fileView struct {
	Path           string `json:"path"`
	DesiredSHA256  string `json:"desired_sha256"`
	ObservedSHA256 string `json:"observed_sha256"`
	Mode           string `json:"mode"`
	Exists         bool   `json:"exists"`
	Drift          bool   `json:"drift"`
	UpdatedBy      string `json:"updated_by"`
}

type versionView struct {
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
	AppliedBy string `json:"applied_by"`
}

const filesReason = "integration test of the files module"
const testPath = "/etc/flotestro-test.conf"

// TestForbiddenFileDoesNotReachTheHost guards the boundary that separates
// this module from a root file manager: the password hash file, a private
// key and a sudo rule have modules of their own and are not editable here.
func TestForbiddenFileDoesNotReachTheHost(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	for _, path := range []string{
		"/etc/shadow", "/etc/sudoers", "/etc/sudoers.d/admin",
		"/etc/ssh/ssh_host_ed25519_key", "/root/.ssh/authorized_keys",
		"/etc/pam.d/sshd", "../etc/motd",
	} {
		t.Run(path, func(t *testing.T) {
			h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
				map[string]any{"action": "file.ensure", "reason": filesReason,
					"payload": map[string]any{"file": map[string]any{
						"path": path, "content": "x\n"}}},
				nil, http.StatusBadRequest)
		})
	}
}

// TestFileOutsideTheAllowlistIsRejectedByTheHost checks the second level:
// the path scope is set by the host administrator, not by the order.
func TestFileOutsideTheAllowlistIsRejectedByTheHost(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "file.ensure", "reason": filesReason,
		"payload": map[string]any{"file": map[string]any{
			"path": "/var/lib/flotestro-out-of-scope.conf", "content": "x\n"}},
	}, 2*time.Minute)
	if job.State == "succeeded" {
		t.Fatal("the host wrote a file outside the allowlist")
	}
	message := lastMessage(attempts)
	if !strings.Contains(message, "allowlist") {
		t.Errorf("refusal without a reason: %q", message)
	}
	// The refusal says where the scope is set: the operator is to know what
	// to do next, not only that it cannot be done.
	if !strings.Contains(message, "files.allow") {
		t.Errorf("the refusal does not point at the source of the scope: %q", message)
	}
}

// TestManagedFileLifecycle walks the whole path: a write, drift after a
// change outside the panel, a rollback to a version and removal.
func TestManagedFileLifecycle(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	t.Cleanup(func() {
		state := managedFile(t, h, host.ID, testPath)
		h.runOperation(host.ID, map[string]any{
			"action": "file.remove", "reason": filesReason,
			"payload": map[string]any{"file": map[string]any{
				"path": testPath, "expected_sha256": state.ObservedSHA256}},
		}, 2*time.Minute)
	})

	first := "key = first\n"
	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "file.ensure", "reason": filesReason,
		"payload": map[string]any{"file": map[string]any{
			"path": testPath, "content": first, "mode": "640"}},
	}, 2*time.Minute)
	if job.State != "succeeded" {
		t.Fatalf("first write: state = %s, %s", job.State, lastMessage(attempts))
	}
	// A file the panel knows no check for is told so outright: missing
	// validation is a fact, not silence.
	if !strings.Contains(lastMessage(attempts), "no validator") {
		t.Errorf("write without validation information: %q", lastMessage(attempts))
	}

	state := managedFile(t, h, host.ID, testPath)
	if !state.Exists || state.Drift {
		t.Fatalf("state after the write = %+v", state)
	}
	if state.ObservedSHA256 != state.DesiredSHA256 {
		t.Errorf("digests = %s vs %s", state.ObservedSHA256, state.DesiredSHA256)
	}
	firstDigest := state.DesiredSHA256

	// The second write requires the digest of the content the operator
	// looked at.
	job, attempts = h.runOperation(host.ID, map[string]any{
		"action": "file.ensure", "reason": filesReason,
		"payload": map[string]any{"file": map[string]any{
			"path": testPath, "content": "key = second\n", "mode": "640"}},
	}, 2*time.Minute)
	if job.State == "succeeded" {
		t.Fatal("the panel overwrote an existing file without a digest")
	}
	if !strings.Contains(lastMessage(attempts), "digest") {
		t.Errorf("refusal without a reason: %q", lastMessage(attempts))
	}

	job, attempts = h.runOperation(host.ID, map[string]any{
		"action": "file.ensure", "reason": filesReason,
		"payload": map[string]any{"file": map[string]any{
			"path": testPath, "content": "key = second\n", "mode": "640",
			"expected_sha256": state.ObservedSHA256}},
	}, 2*time.Minute)
	if job.State != "succeeded" {
		t.Fatalf("second write: state = %s, %s", job.State, lastMessage(attempts))
	}

	// The history carries both versions, so it is possible to go back to
	// the first.
	versions := fileHistory(t, h, host.ID, testPath)
	if len(versions) < 2 {
		t.Fatalf("versions in the history = %d", len(versions))
	}
	state = managedFile(t, h, host.ID, testPath)
	job, attempts = h.runOperation(host.ID, map[string]any{
		"action": "file.rollback", "reason": filesReason,
		"payload": map[string]any{"file": map[string]any{
			"path": testPath, "version_sha256": firstDigest,
			"expected_sha256": state.ObservedSHA256, "mode": "640"}},
	}, 2*time.Minute)
	if job.State != "succeeded" {
		t.Fatalf("rollback to a version: state = %s, %s", job.State, lastMessage(attempts))
	}
	after := managedFile(t, h, host.ID, testPath)
	if after.DesiredSHA256 != firstDigest || after.Drift {
		t.Errorf("state after the rollback = %+v", after)
	}
}

// TestFileReadCarriesContentAndDigest checks the path that precedes every
// write: without a read the operator has no digest to bind their change to.
func TestFileReadCarriesContentAndDigest(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	job, _ := h.runOperation(host.ID, map[string]any{
		"action":  "file.read",
		"payload": map[string]any{"file": map[string]any{"path": "/etc/hosts"}},
	}, 90*time.Second)
	if job.State != "succeeded" {
		t.Fatalf("read: state = %s", job.State)
	}

	var response struct {
		Items []struct {
			Detail struct {
				Kind      string `json:"kind"`
				Content   string `json:"content"`
				SHA256    string `json:"sha256"`
				Truncated bool   `json:"truncated"`
			} `json:"detail"`
		} `json:"items"`
	}
	h.do(http.MethodGet, "/api/v1/jobs/"+job.ID+"/attempts", nil, &response, http.StatusOK)
	if len(response.Items) == 0 {
		t.Fatal("job without attempts")
	}
	detail := response.Items[len(response.Items)-1].Detail
	if detail.Content == "" || len(detail.SHA256) != 64 {
		t.Errorf("read = %+v", detail)
	}
	if !strings.Contains(detail.Content, "localhost") {
		t.Errorf("content of /etc/hosts = %q", detail.Content[:min(60, len(detail.Content))])
	}
}

func managedFile(t *testing.T, h *harness, hostID, path string) fileView {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		var response struct {
			Items []fileView `json:"items"`
		}
		h.do(http.MethodGet, "/api/v1/hosts/"+hostID+"/files", nil, &response, http.StatusOK)
		for _, file := range response.Items {
			if file.Path == path {
				return file
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("file %s is not managed", path)
		}
		time.Sleep(2 * time.Second)
	}
}

func fileHistory(t *testing.T, h *harness, hostID, path string) []versionView {
	t.Helper()
	var response struct {
		Items []versionView `json:"items"`
	}
	h.do(http.MethodGet, "/api/v1/hosts/"+hostID+"/files/history?path="+path,
		nil, &response, http.StatusOK)
	return response.Items
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
