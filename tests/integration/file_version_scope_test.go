//go:build integration

package integration

import (
	"net/http"
	"testing"
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
	file := managedFile(t, h, host.ID, testPath)
	if file.DesiredSHA256 == "" {
		t.Fatalf("the managed file %s on %s carries no version to read", testPath, host.Hostname)
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
