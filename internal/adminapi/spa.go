package adminapi

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// SPAHandler serves the built panel. Paths unknown to the router go to
// index.html, because the panel routes exist only on the browser side.
//
// The handler deliberately does not serve paths starting with /api, /auth
// or /healthz: those belong to the API and must return an error, not an
// HTML page.
func SPAHandler(root string) http.Handler {
	if root == "" {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			problem(w, http.StatusNotFound, "web_ui_disabled",
				"the web panel is not built; set its directory with --web-root")
		})
	}

	files := http.FileServer(http.Dir(root))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := filepath.Clean(r.URL.Path)
		// filepath.Clean removes "..", but it is checked explicitly: the path
		// comes from the network and must not leave the panel directory.
		if strings.Contains(clean, "..") {
			problem(w, http.StatusBadRequest, "invalid_path", "invalid path")
			return
		}

		if clean != "/" {
			if info, err := os.Stat(filepath.Join(root, clean)); err == nil && !info.IsDir() {
				// Assets with a hash in the name are immutable, so they may be
				// cached for long; index.html never.
				if strings.HasPrefix(clean, "/assets/") {
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				}
				files.ServeHTTP(w, r)
				return
			}
		}

		w.Header().Set("Cache-Control", "no-store")
		http.ServeFile(w, r, filepath.Join(root, "index.html"))
	})
}
