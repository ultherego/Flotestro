package adminapi

import (
	"net/http"

	"github.com/ultherego/flotestro/internal/authz"
)

// handleIdentityStatus opisuje stan polaczenia z katalogiem.
func (s *Server) handleIdentityStatus(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, authz.PermIdentityRead, authz.GlobalScope, "identity", ""); !ok {
		return
	}
	if s.directory == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"configured": false,
			"detail":     "connector katalogu nie jest skonfigurowany",
		})
		return
	}

	summary, err := s.directory.Ping(r.Context())
	if err != nil {
		// Niedostepny katalog nie jest bledem panelu: raportujemy stan, a nie
		// udajemy, ze danych nie ma.
		writeJSON(w, http.StatusOK, map[string]any{
			"configured": true,
			"reachable":  false,
			"principal":  s.directory.Principal(),
			"error":      err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"configured": true,
		"reachable":  true,
		"principal":  s.directory.Principal(),
		"summary":    summary,
	})
}

// directoryHandler buduje handler odczytu jednego zasobu katalogu.
// Kazdy z nich wymaga uprawnienia identity.read w zakresie globalnym: katalog
// obejmuje cala flote, a nie pojedyncze srodowisko.
func directoryHandler[T any](s *Server, name string,
	load func(*Server, *http.Request) ([]T, error)) http.HandlerFunc {
	return directoryHandlerFor(s, name, authz.PermIdentityRead, load)
}

// policyHandler obsluguje zasoby opisujace dostep i podniesienie uprawnien.
func policyHandler[T any](s *Server, name string,
	load func(*Server, *http.Request) ([]T, error)) http.HandlerFunc {
	return directoryHandlerFor(s, name, authz.PermIdentityPolicyRead, load)
}

func directoryHandlerFor[T any](s *Server, name string, permission authz.Permission,
	load func(*Server, *http.Request) ([]T, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := s.authorize(w, r, permission, authz.GlobalScope, "identity", name); !ok {
			return
		}
		if s.directory == nil {
			problem(w, http.StatusNotImplemented, "directory_disabled",
				"connector katalogu nie jest skonfigurowany")
			return
		}
		items, err := load(s, r)
		if err != nil {
			// Awaria katalogu jest stanem, nie bledem wewnetrznym panelu.
			problem(w, http.StatusBadGateway, "directory_unavailable", err.Error())
			return
		}
		if items == nil {
			items = []T{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items, "count": len(items)})
	}
}
