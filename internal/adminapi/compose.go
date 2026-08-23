package adminapi

import (
	"net/http"
	"time"

	"github.com/ultherego/flotestro/internal/authz"
)

// wersjaProjektu opisuje jedno wdrozenie manifestu.
type wersjaProjektu struct {
	JobID     string    `json:"job_id"`
	State     string    `json:"state"`
	Digest    string    `json:"plan_digest,omitempty"`
	Manifest  string    `json:"manifest"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
	Reason    string    `json:"reason,omitempty"`
	Applied   bool      `json:"applied"`
}

// handleComposeVersions zwraca historie manifestow projektu na hoscie.
//
// Historia nie ma wlasnej tabeli. Kazde wdrozenie jest operacja, a operacja
// niesie juz manifest, autora, czas i wynik - osobny zapis bylby drugim
// zrodlem prawdy o tym samym i predzej czy pozniej rozjechalby sie z pierwszym.
// Wycofanie zmiany to wdrozenie wczesniejszej wersji, wiec nie potrzebuje
// wlasnej operacji.
func (s *Server) handleComposeVersions(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	_, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	if _, ok := s.authorize(w, r, authz.PermJobRead, scope, "host", hostID); !ok {
		return
	}
	project := r.PathValue("project")

	const query = `
		select j.id, j.state, j.created_by, j.created_at,
		       coalesce(j.payload->'compose'->>'manifest', ''),
		       coalesce(j.payload->'compose'->>'plan_digest', '')
		  from jobs j
		 where j.host_id = $1
		   and j.action_type = 'docker.compose.deploy'
		   and j.payload->'compose'->>'project' = $2
		 order by j.created_at desc
		 limit 50`
	rows, err := s.pool.Query(r.Context(), query, hostID, project)
	if err != nil {
		s.fail(w, err)
		return
	}
	defer rows.Close()

	wersje := []wersjaProjektu{}
	for rows.Next() {
		var wersja wersjaProjektu
		if err := rows.Scan(&wersja.JobID, &wersja.State, &wersja.CreatedBy,
			&wersja.CreatedAt, &wersja.Manifest, &wersja.Digest); err != nil {
			s.fail(w, err)
			return
		}
		// Wdrozona jest ta wersja, ktora sie powiodla. Wersja zlecona
		// i wersja dzialajaca to dwie rozne rzeczy.
		wersja.Applied = wersja.State == "succeeded"
		wersje = append(wersje, wersja)
	}
	if err := rows.Err(); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": wersje, "count": len(wersje)})
}
