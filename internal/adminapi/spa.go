package adminapi

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// SPAHandler serwuje zbudowany panel. Sciezki nieznane routerowi trafiaja do
// index.html, bo trasy panelu istnieja tylko po stronie przegladarki.
//
// Handler celowo nie obsluguje sciezek zaczynajacych sie od /api, /auth ani
// /healthz: te naleza do API i musza zwracac blad, a nie strone HTML.
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
		// filepath.Clean usuwa "..", ale sprawdzamy jawnie: sciezka pochodzi
		// z sieci i nie moze wyjsc poza katalog panelu.
		if strings.Contains(clean, "..") {
			problem(w, http.StatusBadRequest, "invalid_path", "invalid path")
			return
		}

		if clean != "/" {
			if info, err := os.Stat(filepath.Join(root, clean)); err == nil && !info.IsDir() {
				// Zasoby z hashem w nazwie sa niezmienne, wiec moga byc
				// cache'owane na dlugo; index.html nigdy.
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
