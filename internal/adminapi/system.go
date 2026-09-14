package adminapi

import (
	"net/http"

	"github.com/ultherego/flotestro/internal/authz"
)

// The system module of a host: the platform picture travels in the
// inventory fragment like every other module, so the tab reads it from
// the generic module endpoint. What the panel adds is the history - the
// kernels and releases it has seen the host on - which no single report
// carries.

// handleHostSystemHistory lists the platforms the host was seen on, the
// most recent first. An empty list is a host the panel has not heard
// from since the history was introduced, not a host without a kernel.
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
