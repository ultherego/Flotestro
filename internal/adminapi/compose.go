package adminapi

import (
	"net/http"
	"time"

	"github.com/ultherego/flotestro/internal/authz"
)

// projectVersion describes one manifest deployment.
type projectVersion struct {
	JobID     string    `json:"job_id"`
	State     string    `json:"state"`
	Digest    string    `json:"plan_digest,omitempty"`
	Manifest  string    `json:"manifest"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
	Reason    string    `json:"reason,omitempty"`
	Applied   bool      `json:"applied"`
}

// handleComposeVersions returns the manifest history of a project on a
// host.
//
// The history has no table of its own. Every deployment is an operation,
// and an operation already carries the manifest, the author, the time and
// the result - a separate record would be a second source of truth about
// the same thing and would sooner or later drift from the first. Reverting
// a change is deploying an earlier version, so it needs no operation of its
// own.
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

	versions := []projectVersion{}
	for rows.Next() {
		var version projectVersion
		if err := rows.Scan(&version.JobID, &version.State, &version.CreatedBy,
			&version.CreatedAt, &version.Manifest, &version.Digest); err != nil {
			s.fail(w, err)
			return
		}
		// The deployed version is the one that succeeded. The ordered
		// version and the running version are two different things.
		version.Applied = version.State == "succeeded"
		versions = append(versions, version)
	}
	if err := rows.Err(); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": versions, "count": len(versions)})
}
