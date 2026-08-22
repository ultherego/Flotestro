package adminapi

import (
	"net/http"
	"strings"

	"github.com/ultherego/flotestro/internal/authz"
)

// handleHostLocalAccounts zwraca konta widziane na hoscie.
//
// Dane pochodza z ostatniego raportu agenta, a nie z odpytania hosta na
// zadanie. Odpowiedz niesie znacznik obserwacji, zeby operator wiedzial,
// jak swieza jest ta wiedza; panel nie udaje, ze widzi host w czasie
// rzeczywistym.
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

	// Konta systemowe naleza do uslug i zasmiecaja widok; sa dostepne
	// jawnym filtrem, bo czasem trzeba potwierdzic, ze konto uslugi istnieje.
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
