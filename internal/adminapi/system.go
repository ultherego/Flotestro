package adminapi

import (
	"net/http"

	"github.com/ultherego/flotestro/internal/authz"
)

// The system module of a host: the platform picture travels in the inventory
// fragment like every other module, so the tab reads it from the generic
// module endpoint.

// handleHostSystemHistory lists the platforms the host was seen on, the most
// recent first.
func (s *Server) handleHostSystemHistory(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	_, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	if _, ok := s.authorize(w, r, authz.PermInventoryRead, scope, "host", hostID); !ok {
		return
	}
	entries, err := s.hosts.SystemHistory(r.Context(), hostID)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": entries, "count": len(entries)})
}
