//go:build integration

package integration

import (
	"net/http"
	"testing"
	"time"
)

// A digest is not a secret. It travels in the results of tasks, in the plan an
// operator looks at, in the operation journal and in the answers of the API,
// which reach a wider circle than the content of the file. The endpoint that
// returns a version used to ask only whether the caller holds file.read
// somewhere and then select the row by its digest alone, so whoever knew one
// could read the configuration of a site they have no access to.
func TestAFileVersionIsNotReadableOutsideItsScope(t *testing.T) {
	h := newHarness(t)
	h.requireHealthy()

	host := h.hostByFamily("debian")
	// The file is this test's own: another test manages testPath and removes it
	// again, so depending on it would make this test pass or fail by the order
	// the suite happens to run in.
	path := "/etc/flotestro-version-scope.conf"
	t.Cleanup(func() {
		h.runOperation(host.ID, map[string]any{
			"action": "file.remove", "reason": "cleanup after the version scope test",
			"payload": map[string]any{"file": map[string]any{"path": path}},
		}, 2*time.Minute)
	})
	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "file.ensure", "reason": "a version to read inside and outside its scope",
		"payload": map[string]any{"file": map[string]any{
			"path": path, "content": "key = scope\n", "mode": "640"}},
	}, 2*time.Minute)
	if job.State != "succeeded" {
		t.Fatalf("the file was not written: state = %s, %s", job.State, lastMessage(attempts))
	}

	file := managedFile(t, h, host.ID, path)
	if file.DesiredSHA256 == "" {
		t.Fatalf("the managed file %s on %s carries no version to read", path, host.Hostname)
	}

	// The owner of the host reads it, which is the behaviour that has to keep
	// working: a scope check that refuses everybody would pass the half of
	// this test below and take the feature with it.
	var mine struct {
		SHA256  string `json:"sha256"`
		Content string `json:"content"`
	}
	h.do(http.MethodGet, "/api/v1/files/versions/"+file.DesiredSHA256, nil, &mine, http.StatusOK)
	if mine.SHA256 != file.DesiredSHA256 {
		t.Fatalf("the version came back as %s, want %s", mine.SHA256, file.DesiredSHA256)
	}

	// Somebody who holds file.read in another site knows the digest - it is in
	// every plan and every result - and must not get the content.
	stranger := h.withToken(h.createPrincipal(uniqueSubject("operator-another-site"),
		[]map[string]string{{"role": "operator", "site": "nowhere", "environment": "nowhere"}}))
	// Not found rather than forbidden: saying "you may not read this one"
	// would confirm that the digest names something.
	stranger.do(http.MethodGet, "/api/v1/files/versions/"+file.DesiredSHA256,
		nil, nil, http.StatusNotFound)
}
