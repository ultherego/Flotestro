package adminapi

import (
	"net/http"

	"github.com/ultherego/flotestro/internal/authz"
)

// handleIdentityStatus describes the state of the directory connection.
func (s *Server) handleIdentityStatus(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, authz.PermIdentityRead, authz.GlobalScope, "identity", ""); !ok {
		return
	}
	if s.directory == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"configured": false,
			"detail":     "no directory connector is configured",
		})
		return
	}

	summary, err := s.directory.Ping(r.Context())
	if err != nil {
		// An unavailable directory is not a panel error: the state is
		// reported instead of pretending there is no data.
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

// directoryHandler builds a read handler for one directory resource.
// Each of them requires the identity.read permission in the global scope:
// the directory covers the whole fleet, not a single environment.
func directoryHandler[T any](s *Server, name string,
	load func(*Server, *http.Request) ([]T, error)) http.HandlerFunc {
	return directoryHandlerFor(s, name, authz.PermIdentityRead, load)
}

// policyHandler serves the resources describing access and privilege
// elevation.
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
				"no directory connector is configured")
			return
		}
		items, err := load(s, r)
		if err != nil {
			// A directory failure is a state, not an internal panel error.
			problem(w, http.StatusBadGateway, "directory_unavailable", err.Error())
			return
		}
		if items == nil {
			items = []T{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items, "count": len(items)})
	}
}
