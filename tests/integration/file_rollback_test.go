//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// keptVersionView is one copy of a file the host itself kept, as the host
// reports it in the files fragment of the inventory.
type keptVersionView struct {
	SHA256     string    `json:"sha256"`
	SizeBytes  int64     `json:"size_bytes"`
	Mode       string    `json:"mode"`
	Owner      string    `json:"owner"`
	Group      string    `json:"group"`
	KeptAt     time.Time `json:"kept_at"`
	OrderedBy  string    `json:"ordered_by"`
	FromSecret bool      `json:"from_secret"`
}

// observedFileView is what the host really has, as the files tab shows it.
type observedFileView struct {
	Path           string `json:"path"`
	ObservedSHA256 string `json:"observed_sha256"`
	ObservedMode   string `json:"observed_mode"`
	Exists         bool   `json:"exists"`
	Drift          bool   `json:"drift"`
}

type fragmentFileView struct {
	Path     string            `json:"path"`
	SHA256   string            `json:"sha256"`
	Mode     string            `json:"mode"`
	Exists   bool              `json:"exists"`
	Versions []keptVersionView `json:"versions"`
}

const rollbackReason = "integration test of the file version store"
const rollbackPath = "/etc/flotestro-rollback-test.conf"

// TestFileRollbackRestoresAVersionTheHostKept closes the half of the file
// module that was missing: the panel could name a version, but nothing on the
// host kept one, so a return was a write of whatever the panel happened to
func TestFileRollbackRestoresAVersionTheHostKept(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	t.Cleanup(func() {
		state := managedFile(t, h, host.ID, rollbackPath)
		h.runOperation(host.ID, map[string]any{
			"action": "file.remove", "reason": rollbackReason,
			"payload": map[string]any{"file": map[string]any{
				"path": rollbackPath, "expected_sha256": state.ObservedSHA256}},
		}, 2*time.Minute)
	})

	first := "key = first\n"
	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "file.ensure", "reason": rollbackReason,
		"payload": map[string]any{"file": map[string]any{
			"path": rollbackPath, "content": first, "mode": "640"}},
	}, 2*time.Minute)
	if job.State != "succeeded" {
		t.Fatalf("first write: state = %s, %s", job.State, lastMessage(attempts))
	}
	state := observedFile(t, h, host.ID, rollbackPath)
	firstDigest := state.ObservedSHA256
	if state.ObservedMode != "0640" {
		t.Fatalf("mode after the first write = %q", state.ObservedMode)
	}

	// The second write changes both the content and the permissions, so the
	// return has something to prove on each.
	second := "key = second\n"
	job, attempts = h.runOperation(host.ID, map[string]any{
		"action": "file.ensure", "reason": rollbackReason,
		"payload": map[string]any{"file": map[string]any{
			"path": rollbackPath, "content": second, "mode": "600",
			"expected_sha256": firstDigest}},
	}, 2*time.Minute)
	if job.State != "succeeded" {
		t.Fatalf("second write: state = %s, %s", job.State, lastMessage(attempts))
	}
	if !strings.Contains(lastMessage(attempts), "previous content is kept") {
		t.Errorf("the write does not say what it kept: %q", lastMessage(attempts))
	}

	// The host reports its copies, so the panel can offer one instead of
	// asking the operator for a checksum nobody can see.
	versions := keptVersions(t, h, host.ID, rollbackPath)
	if len(versions) == 0 {
		t.Fatal("the host reports no kept version of a file it overwrote")
	}
	kept := findVersion(versions, firstDigest)
	if kept == nil {
		t.Fatalf("the content that was replaced is not among the kept versions: %+v", versions)
	}
	if kept.Mode != "0640" {
		t.Errorf("the version was kept without the permissions it had: %+v", kept)
	}
	if kept.SizeBytes != int64(len(first)) || kept.KeptAt.IsZero() || kept.OrderedBy == "" {
		t.Errorf("the kept version says too little about itself: %+v", kept)
	}

	// A checksum this host never kept is refused with its own code rather
	// than answered with the newest copy.
	job, attempts = h.runOperation(host.ID, map[string]any{
		"action": "file.rollback", "reason": rollbackReason,
		"payload": map[string]any{"file": map[string]any{
			"path":            rollbackPath,
			"version_sha256":  strings.Repeat("ab", 32),
			"expected_sha256": observedFile(t, h, host.ID, rollbackPath).ObservedSHA256,
		}},
	}, 2*time.Minute)
	if job.State == "succeeded" {
		t.Fatal("a return to a version the host never had was carried out")
	}
	if len(attempts) == 0 {
		t.Fatal("no attempt was recorded")
	}
	if code := attempts[len(attempts)-1].ErrorCode; code != "file_version_unknown" {
		t.Fatalf("refusal = %s (%s), want file_version_unknown",
			code, lastMessage(attempts))
	}
	if after := observedFile(t, h, host.ID, rollbackPath); after.ObservedSHA256 == firstDigest {
		t.Error("the refused return put the first version back anyway")
	}

	// The return to the first version names it by checksum and carries no
	// mode: the permissions come back from the copy itself.
	now := observedFile(t, h, host.ID, rollbackPath)
	job, attempts = h.runOperation(host.ID, map[string]any{
		"action": "file.rollback", "reason": rollbackReason,
		"payload": map[string]any{"file": map[string]any{
			"path": rollbackPath, "version_sha256": firstDigest,
			"expected_sha256": now.ObservedSHA256}},
	}, 2*time.Minute)
	if job.State != "succeeded" {
		t.Fatalf("return to the first version: state = %s, %s", job.State, lastMessage(attempts))
	}

	restored := observedFile(t, h, host.ID, rollbackPath)
	if restored.ObservedSHA256 != firstDigest {
		t.Errorf("the file did not come back to the version that was named: %+v", restored)
	}
	if restored.ObservedMode != "0640" {
		t.Errorf("the permissions did not come back with the content: %q", restored.ObservedMode)
	}
	// The content itself is read from the host rather than taken on trust
	// from the checksum the panel holds.
	if content := readFileContent(t, h, host.ID, rollbackPath); content != first {
		t.Errorf("content after the return = %q, want %q", content, first)
	}
}

// observedFile returns what the host reports about one managed file.
func observedFile(t *testing.T, h *harness, hostID, path string) observedFileView {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		var response struct {
			Items []observedFileView `json:"items"`
		}
		h.do(http.MethodGet, "/api/v1/hosts/"+hostID+"/files", nil, &response, http.StatusOK)
		for _, file := range response.Items {
			if file.Path == path {
				return file
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the file %s is not managed", path)
		}
		time.Sleep(2 * time.Second)
	}
}

// keptVersions reads what the host says it keeps for one path.
func keptVersions(t *testing.T, h *harness, hostID, path string) []keptVersionView {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for {
		var fragment struct {
			Payload struct {
				Files []fragmentFileView `json:"files"`
			} `json:"payload"`
		}
		h.do(http.MethodGet, "/api/v1/hosts/"+hostID+"/inventory/files", nil, &fragment, http.StatusOK)
		for _, file := range fragment.Payload.Files {
			if file.Path == path && len(file.Versions) > 0 {
				return file.Versions
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the host reports no kept version of %s", path)
		}
		time.Sleep(2 * time.Second)
	}
}

func findVersion(versions []keptVersionView, digest string) *keptVersionView {
	for i := range versions {
		if versions[i].SHA256 == digest {
			return &versions[i]
		}
	}
	return nil
}

// readFileContent asks the host for the file as it is now.
func readFileContent(t *testing.T, h *harness, hostID, path string) string {
	t.Helper()
	job, attempts := h.runOperation(hostID, map[string]any{
		"action": "file.read", "reason": rollbackReason,
		"payload": map[string]any{"file": map[string]any{"path": path}},
	}, 90*time.Second)
	if job.State != "succeeded" {
		t.Fatalf("reading %s: state = %s, %s", path, job.State, lastMessage(attempts))
	}
	var response struct {
		Items []struct {
			Detail json.RawMessage `json:"detail"`
		} `json:"items"`
	}
	h.do(http.MethodGet, "/api/v1/jobs/"+job.ID+"/attempts", nil, &response, http.StatusOK)
	if len(response.Items) == 0 {
		t.Fatalf("the read of %s left no attempt", path)
	}
	var detail struct {
		Content string `json:"content"`
	}
	if err := json.Unmarshal(response.Items[len(response.Items)-1].Detail, &detail); err != nil {
		t.Fatalf("the read did not carry the content: %v", err)
	}
	return detail.Content
}
