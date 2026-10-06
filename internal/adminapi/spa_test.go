package adminapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A path the router does not know goes to index.html, because the panel's own
// routes exist only in the browser. Under /api/ that is wrong in the way that
// hides a mistake: the caller gets 200 and a page, a JSON reader gets "invalid
// character '<'", and a wrong path looks like a working one. A scenario asked
// /api/v1/pki/ca of a panel that serves /api/v1/pki and nobody noticed until
// the first complete run reached it.
func TestAnUnknownAPIPathIsNotThePanelPage(t *testing.T) {
	root := t.TempDir()
	page := "<!doctype html><title>panel</title>"
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte(page), 0o600); err != nil {
		t.Fatal(err)
	}
	handler := SPAHandler(root)

	for _, path := range []string{"/api", "/api/", "/api/v1/pki/ca", "/api/v2/anything"} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusNotFound {
			t.Errorf("%s answered %d, expected 404", path, recorder.Code)
		}
		if strings.Contains(recorder.Body.String(), "<!doctype") {
			t.Errorf("%s answered with the panel page", path)
		}
		var document map[string]any
		if err := json.Unmarshal(recorder.Body.Bytes(), &document); err != nil {
			t.Errorf("%s did not answer a problem document: %v", path, err)
			continue
		}
		if document["code"] != "no_such_route" {
			t.Errorf("%s answered the code %v", path, document["code"])
		}
	}

	// And a browser path still reaches the page, which is what the catch-all
	// is for: a view of the panel is not a route of the API.
	for _, path := range []string{"/", "/hosts", "/campaigns/abc", "/apiary"} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "<!doctype") {
			t.Errorf("%s answered %d without the panel page", path, recorder.Code)
		}
	}
}
