package adminapi

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
)

// Granting a role to somebody the panel has not met yet.
//
// The screen of who may sign in lists the directory's people, and most of
// them have no record here: the panel makes one at the first sign-in. An
// administrator who wants to give one of them a role of their own - beside
// what their group grants, or because no group grants anything - had nowhere
// to do it.
//
// The record is written down in advance and says which issuer it waits for,
// so the first sign-in adopts it instead of making a second one under the
// same name. That trap is the reason this is an endpoint of its own rather
// than a call to POST /api/v1/principals: the identity it creates is not an
// ordinary local identity and must not be made by a path that does not know
// the difference.

type grantToHolderRequest struct {
	Subject     string `json:"subject"`
	DisplayName string `json:"display_name"`
	Role        string `json:"role"`
	Site        string `json:"site"`
	Environment string `json:"environment"`
	Reason      string `json:"reason"`
}

func (s *Server) handleGrantToHolder(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authorize(w, r, authz.PermPrincipalManage, authz.GlobalScope, "principal", "")
	if !ok {
		return
	}
	var request grantToHolderRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&request); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return
	}
	subject := strings.TrimSpace(request.Subject)
	if subject == "" {
		problem(w, http.StatusBadRequest, "invalid_binding", "a grant names the person it is for")
		return
	}
	// Which provider this person will arrive from. Without one configured
	// there is nothing to wait for, and a record made here would never be
	// adopted - so the panel refuses rather than leaving one behind.
	issuer := ""
	if s.oidc != nil {
		issuer = s.oidc.Issuer()
	}
	if issuer == "" {
		problem(w, http.StatusConflict, "no_provider",
			"no identity provider is configured, so there is no sign-in for this record to wait for; "+
				"create a local identity instead")
		return
	}

	role := authz.Role(strings.TrimSpace(request.Role))
	carried, ok := s.resolveRole(w, r, role)
	if !ok {
		return
	}
	scope := authz.PlacementWithin(strings.TrimSpace(request.Site), strings.TrimSpace(request.Environment), nil, nil)
	if err := mayGrant(actor, role, carried, scope); err != nil {
		s.refuseEscalation(w, r, actor, "principal.role.grant", subject, err)
		return
	}
	evidence, ok := s.requireStepUp(w, r, actor, request.Reason, "principal.role.grant", "principal", subject)
	if !ok {
		return
	}

	tx, err := s.authz.Pool().Begin(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	id, written, err := s.authz.EnsureAwaitingPrincipal(r.Context(), tx, subject, strings.TrimSpace(request.DisplayName), issuer)
	if err != nil {
		problem(w, http.StatusBadRequest, "invalid_binding", err.Error())
		return
	}
	if err := s.authz.GrantRole(r.Context(), tx, id, role, scope, nil, actor.Subject); err != nil {
		problem(w, http.StatusBadRequest, "invalid_binding", err.Error())
		return
	}
	if err := s.audit.RecordTx(r.Context(), tx, audit.Event{
		ActorType: audit.ActorUser, ActorID: actor.Subject,
		Action: "principal.role.grant", TargetType: "principal", TargetID: id,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: withStepUp(map[string]any{
			"subject": subject, "role": string(role), "scope": scope.String(),
			// Whether this is the moment the panel first heard of them.
			"identity_written_in_advance": written, "awaiting_issuer": issuer,
		}, evidence),
		After: map[string]any{"principal_id": id, "subject": subject, "role": string(role)},
	}); err != nil {
		s.fail(w, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"principal_id": id, "subject": subject, "role": string(role), "scope": scope,
		"identity_written_in_advance": written, "awaiting_issuer": issuer,
	})
}
