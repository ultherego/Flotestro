package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"

	"github.com/ultherego/flotestro/internal/authz"
	managedfiles "github.com/ultherego/flotestro/internal/files"
	modul "github.com/ultherego/flotestro/internal/modules/files"
)

var odciskHex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// plikWidok laczy stan docelowy z tym, co host naprawde ma.
//
// Rozjazd miedzy jednym a drugim jest cala trescia tej zakladki: plik
// zmieniony poza panelem wyglada tak samo jak plik zgodny, dopoki nie
// porowna sie odciskow.
type plikWidok struct {
	managedfiles.StanDocelowy
	ObservedSHA256 string `json:"observed_sha256,omitempty"`
	Exists         bool   `json:"exists"`
	Drift          bool   `json:"drift"`
	// DriftUnknownReason mowi, dlaczego panel nie porownuje tresci. Cisza
	// w tym miejscu wygladalaby jak zgodnosc.
	DriftUnknownReason string `json:"drift_unknown_reason,omitempty"`
	Mode               string `json:"observed_mode,omitempty"`
	Owner              string `json:"observed_owner,omitempty"`
	UnavailableReason  string `json:"unavailable_reason,omitempty"`
}

// handleListManagedFiles zwraca pliki zarzadzane na hoscie.
func (s *Server) handleListManagedFiles(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	_, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	if _, ok := s.authorize(w, r, authz.PermFilePlan, scope, "host", hostID); !ok {
		return
	}

	stany, err := s.files.Lista(r.Context(), hostID)
	if err != nil {
		s.fail(w, err)
		return
	}

	// Stan faktyczny pochodzi z inwentarza: to host mowi, jak plik wyglada
	// teraz, a nie panel, ktory pamieta, co kiedys wyslal.
	obserwowane := map[string]modul.Plik{}
	fragment, err := s.inventory.Fragment(r.Context(), hostID, "files")
	if err == nil && fragment != nil && len(fragment.Payload) > 0 {
		var snapshot modul.Snapshot
		if err := json.Unmarshal(fragment.Payload, &snapshot); err == nil {
			for _, plik := range snapshot.Files {
				obserwowane[plik.Path] = plik
			}
		}
	}

	widoki := make([]plikWidok, 0, len(stany))
	for _, stan := range stany {
		widok := plikWidok{StanDocelowy: stan}
		if plik, znany := obserwowane[stan.Path]; znany {
			widok.ObservedSHA256 = plik.SHA256
			widok.Exists = plik.Exists
			widok.Mode = plik.Mode
			widok.Owner = plik.Owner
			widok.UnavailableReason = plik.UnavailableReason
			// Drift oznacza wylacznie rozjazd stwierdzony: plik, ktorego
			// host nie odczytal, nie jest ani zgodny, ani rozjechany.
			//
			// Pliku z sekretu panel nie porownuje wcale: nie ma jego odcisku
			// i mieć go nie moze. Zamiast falszywej zgodnosci mowi wprost,
			// ze tresci nie sprawdza.
			widok.Drift = stan.SecretName == "" && plik.Exists &&
				plik.SHA256 != "" && plik.SHA256 != stan.SHA256
			if stan.SecretName != "" && plik.Exists {
				widok.DriftUnknownReason = "tresc pochodzi z magazynu sekretow; panel nie trzyma jej odcisku"
			}
		}
		widoki = append(widoki, widok)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": widoki, "count": len(widoki)})
}

// handleFileHistory zwraca kolejne wersje pliku.
func (s *Server) handleFileHistory(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	_, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	if _, ok := s.authorize(w, r, authz.PermFilePlan, scope, "host", hostID); !ok {
		return
	}
	sciezka := r.URL.Query().Get("path")
	if sciezka == "" {
		problem(w, http.StatusBadRequest, "path_required", "path query parameter is required")
		return
	}
	wersje, err := s.files.Historia(r.Context(), hostID, sciezka, 0)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": wersje, "count": len(wersje)})
}

// handleFileVersion zwraca tresc wersji pliku.
//
// Tresc jest osobnym uprawnieniem niz lista: plik konfiguracyjny bywa
// wrazliwy nawet wtedy, gdy nie jest sekretem - niesie adresy, nazwy kont
// i topologie.
func (s *Server) handleFileVersion(w http.ResponseWriter, r *http.Request) {
	odcisk := r.PathValue("sha256")
	if !odciskHex.MatchString(odcisk) {
		problem(w, http.StatusBadRequest, "invalid_sha256", "sha256 must be 64 hex characters")
		return
	}
	if _, ok := s.authorizeCollection(w, r, authz.PermFileRead, "file"); !ok {
		return
	}
	tresc, err := s.files.Tresc(r.Context(), odcisk)
	if errors.Is(err, managedfiles.ErrNieZnaleziono) {
		problem(w, http.StatusNotFound, "version_not_found", "no such file version")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sha256": odcisk, "content": string(tresc), "size_bytes": len(tresc),
	})
}
