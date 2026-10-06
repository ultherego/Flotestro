package adminapi

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// SPAHandler serves the built panel. Paths unknown to the router go to index.
// html, because the panel routes exist only on the browser side - except under
// /api/, where an unknown path is an unknown route and says so.
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

		// A path under /api/ that reached the catch-all is an API route this
		// panel does not serve, and the browser never navigates there. Served
		// the index, it answered 200 with a page - so a client asking a wrong
		// path got what looks like success, and a caller reading JSON got
		// "invalid character '<'". That is how an integration scenario asked
		// /api/v1/pki/ca of a panel that serves /api/v1/pki and nobody noticed
		// until the first run that reached it, on 06.10.
		if clean == "/api" || strings.HasPrefix(clean, "/api/") {
			problem(w, http.StatusNotFound, "no_such_route",
				"this panel serves no "+r.Method+" "+r.URL.Path+
					"; the routes it serves are in its OpenAPI document at /api/v1/openapi.json")
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

// inlineScriptHashes reads index. html once and returns the CSP source
// expressions of its inline scripts.
func inlineScriptHashes(root string) []string {
	if root == "" {
		return nil
	}
	page, err := os.ReadFile(filepath.Join(root, "index.html"))
	if err != nil {
		return nil
	}
	var hashes []string
	rest := string(page)
	for {
		start := strings.Index(rest, "<script>")
		if start < 0 {
			break
		}
		rest = rest[start+len("<script>"):]
		end := strings.Index(rest, "</script>")
		if end < 0 {
			break
		}
		sum := sha256.Sum256([]byte(rest[:end]))
		hashes = append(hashes, "'sha256-"+base64.StdEncoding.EncodeToString(sum[:])+"'")
		rest = rest[end:]
	}
	return hashes
}
