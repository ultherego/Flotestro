package adminapi

import (
	"net/http"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
)

// handleProvisionPreserveRights gives the connector's service account the
// one right a preserve needs and reports what it created, what was already
// there and what a directory administrator has to do.
//
// It is deliberate and idempotent, which is the whole design: no user
// operation reaches it - a change of the directory's own configuration
// must not happen as a side effect of preserving somebody's account - and
// a second run sends no create at all, reads everything back and says that
// nothing changed.
func (s *Server) handleProvisionPreserveRights(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorize(w, r, authz.PermIdentityPolicyWrite, authz.GlobalScope,
		"directory_provisioning", "preserve")
	if !ok {
		return
	}
	if s.directory == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"configured": false, "detail": "no directory connector is configured"})
		return
	}
	report, err := s.directory.ProvisionPreserveRights(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	// The directory's configuration changed, or was confirmed unchanged:
	// either way it belongs in the trail next to the other changes of who
	// may do what.
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "identity.directory.provision", TargetType: "directory_provisioning",
		TargetID: "preserve", RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{"summary": report.Summary(), "changed": report.Changed},
	})
	writeJSON(w, http.StatusOK, report)
}
