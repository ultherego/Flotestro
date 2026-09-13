package adminapi

import (
	"net/http"
	"strings"

	"github.com/ultherego/flotestro/internal/authz"
)

// handleHostLocalAccounts returns the accounts seen on the host.
//
// The data comes from the last agent report, not from querying the host on
// demand. The answer carries the observation timestamp so the operator
// knows how fresh this knowledge is; the panel does not pretend to see the
// host in real time.
func (s *Server) handleHostLocalAccounts(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	_, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	if _, ok := s.authorize(w, r, authz.PermLocalUserRead, scope, "host", hostID); !ok {
		return
	}

	accounts, err := s.inventory.LocalAccounts(r.Context(), hostID)
	if err != nil {
		s.fail(w, err)
		return
	}

	// System accounts belong to services and clutter the view; they are
	// available through an explicit filter, because at times it is necessary
	// to confirm that a service account exists.
	filter := strings.TrimSpace(r.URL.Query().Get("source"))
	filtered := accounts[:0:0]
	for _, account := range accounts {
		if filter != "" && account.Source != filter {
			continue
		}
		if filter == "" && account.Source == "system" {
			continue
		}
		filtered = append(filtered, account)
	}

	writeJSON(w, http.StatusOK, map[string]any{"accounts": filtered})
}
