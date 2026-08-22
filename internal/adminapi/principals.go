package adminapi

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
)

// handleWhoami zwraca tozsamosc zadania i jej role. Endpoint nie wymaga
// uprawnien: kazdy moze sprawdzic, kim jest.
func (s *Server) handleWhoami(w http.ResponseWriter, r *http.Request) {
	principal := authz.FromContext(r.Context())
	if !principal.Authenticated() {
		w.Header().Set("WWW-Authenticate", `Bearer realm="flotestro"`)
		problem(w, http.StatusUnauthorized, "unauthenticated", "brak waznego tokenu")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"subject":      principal.Subject,
		"display_name": principal.DisplayName,
		"kind":         principal.Kind,
		"roles":        principal.Roles(),
		"bindings":     principal.Bindings,
		"permissions":  principal.Permissions(),
	})
}

// handleListRoles opisuje katalog rol i ich uprawnienia.
func (s *Server) handleListRoles(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, authz.PermHostRead, authz.GlobalScope, "role", ""); !ok {
		return
	}
	type roleInfo struct {
		Role        string   `json:"role"`
		Permissions []string `json:"permissions"`
	}
	items := make([]roleInfo, 0)
	for _, role := range authz.AllRoles() {
		permissions := make([]string, 0)
		for _, permission := range role.Permissions() {
			permissions = append(permissions, string(permission))
		}
		items = append(items, roleInfo{Role: string(role), Permissions: permissions})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "count": len(items)})
}

func (s *Server) handleListPrincipals(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, authz.PermPrincipalManage, authz.GlobalScope, "principal", ""); !ok {
		return
	}
	principals, err := s.authz.ListPrincipals(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	if principals == nil {
		principals = []authz.Principal{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": principals, "count": len(principals)})
}

type createPrincipalRequest struct {
	Subject     string `json:"subject"`
	DisplayName string `json:"display_name"`
	Kind        string `json:"kind"`
	Roles       []struct {
		Role        string `json:"role"`
		Site        string `json:"site"`
		Environment string `json:"environment"`
	} `json:"roles"`
	// IssueToken wystawia token API razem z tozsamoscia. Wartosc jest widoczna
	// wylacznie w tej odpowiedzi.
	IssueToken    bool `json:"issue_token"`
	TokenTTLHours int  `json:"token_ttl_hours"`
	// Reason opisuje, po co nadawany jest dostep. Operacja przestawia reguly
	// dostepu do calej floty, wiec powod jest czescia sladu audytowego.
	Reason string `json:"reason"`
}

// handleCreatePrincipal tworzy tozsamosc wraz z przypisaniami rol.
func (s *Server) handleCreatePrincipal(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authorize(w, r, authz.PermPrincipalManage, authz.GlobalScope, "principal", "")
	if !ok {
		return
	}

	var request createPrincipalRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&request); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "cialo zadania nie jest poprawnym JSON")
		return
	}
	if request.Subject == "" {
		problem(w, http.StatusBadRequest, "invalid_subject", "brak identyfikatora tozsamosci")
		return
	}
	for _, binding := range request.Roles {
		if !authz.KnownRole(authz.Role(binding.Role)) {
			problem(w, http.StatusBadRequest, "unknown_role", "nieznana rola "+binding.Role)
			return
		}
	}

	// Nadanie uprawnien jest operacja o najwiekszym wplywie: przestawia to,
	// kto moze cokolwiek zrobic na flocie.
	dowod, ok := s.requireStepUp(w, r, actor, request.Reason,
		"principal.create", "principal", request.Subject)
	if !ok {
		return
	}

	tx, err := s.authz.Pool().Begin(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	principalID, err := s.authz.EnsurePrincipal(r.Context(), tx,
		request.Subject, request.DisplayName, request.Kind)
	if err != nil {
		s.fail(w, err)
		return
	}
	granted := make([]map[string]string, 0, len(request.Roles))
	for _, binding := range request.Roles {
		scope := authz.Scope{Site: binding.Site, Environment: binding.Environment}
		if err := s.authz.GrantRole(r.Context(), tx, principalID,
			authz.Role(binding.Role), scope, actor.Subject); err != nil {
			s.fail(w, err)
			return
		}
		granted = append(granted, map[string]string{
			"role": binding.Role, "scope": scope.String(),
		})
	}

	response := map[string]any{
		"id": principalID, "subject": request.Subject, "roles": granted,
	}
	if request.IssueToken {
		ttl := time.Duration(request.TokenTTLHours) * time.Hour
		if ttl <= 0 {
			ttl = 30 * 24 * time.Hour
		}
		token, err := s.authz.IssueToken(r.Context(), tx, principalID,
			"token dla "+request.Subject, ttl, actor.Subject)
		if err != nil {
			s.fail(w, err)
			return
		}
		response["token"] = token.Value
		response["token_expires_at"] = token.ExpiresAt
	}

	if err := s.audit.RecordTx(r.Context(), tx, audit.Event{
		ActorType: audit.ActorUser, ActorID: actor.Subject,
		Action: "principal.create", TargetType: "principal", TargetID: principalID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: withStepUp(map[string]any{
			"subject": request.Subject, "roles": granted,
			"token_issued": request.IssueToken,
		}, dowod),
	}); err != nil {
		s.fail(w, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, response)
}

type createGroupMappingRequest struct {
	Issuer      string `json:"issuer"`
	GroupName   string `json:"group_name"`
	Role        string `json:"role"`
	Site        string `json:"site"`
	Environment string `json:"environment"`
	Reason      string `json:"reason"`
}

// handleListGroupMappings zwraca mapowania grup zewnetrznych na role.
func (s *Server) handleListGroupMappings(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, authz.PermPrincipalManage, authz.GlobalScope, "group_mapping", ""); !ok {
		return
	}
	mappings, err := s.authz.ListGroupMappings(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	if mappings == nil {
		mappings = []authz.GroupMapping{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": mappings, "count": len(mappings)})
}

// handleCreateGroupMapping dodaje mapowanie grupy na role w zakresie.
// Grupa nadaje wylacznie kandydacka role; zakres pozostaje polityka panelu.
func (s *Server) handleCreateGroupMapping(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authorize(w, r, authz.PermPrincipalManage, authz.GlobalScope, "group_mapping", "")
	if !ok {
		return
	}

	var request createGroupMappingRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&request); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "cialo zadania nie jest poprawnym JSON")
		return
	}
	if request.Issuer == "" && s.oidc != nil {
		request.Issuer = s.oidc.Issuer()
	}
	if !authz.KnownRole(authz.Role(request.Role)) {
		problem(w, http.StatusBadRequest, "unknown_role", "nieznana rola "+request.Role)
		return
	}

	// Mapowanie grupy na role decyduje, kogo dostawca tozsamosci wpuszcza
	// i z jakimi uprawnieniami; to zmiana samej reguly dostepu.
	dowod, ok := s.requireStepUp(w, r, actor, request.Reason,
		"group_mapping.create", "group_mapping", request.GroupName)
	if !ok {
		return
	}

	tx, err := s.authz.Pool().Begin(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	mapping, err := s.authz.CreateGroupMapping(r.Context(), tx, request.Issuer, request.GroupName,
		authz.Role(request.Role), authz.Scope{Site: request.Site, Environment: request.Environment},
		actor.Subject)
	if err != nil {
		problem(w, http.StatusBadRequest, "invalid_mapping", err.Error())
		return
	}
	if err := s.audit.RecordTx(r.Context(), tx, audit.Event{
		ActorType: audit.ActorUser, ActorID: actor.Subject,
		Action: "group_mapping.create", TargetType: "group_mapping", TargetID: mapping.ID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: withStepUp(map[string]any{
			"issuer": mapping.Issuer, "group": mapping.GroupName, "role": string(mapping.Role),
			"site": mapping.Site, "environment": mapping.Environment,
		}, dowod),
	}); err != nil {
		s.fail(w, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, mapping)
}

// handleDeleteGroupMapping usuwa mapowanie.
func (s *Server) handleDeleteGroupMapping(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authorize(w, r, authz.PermPrincipalManage, authz.GlobalScope, "group_mapping", "")
	if !ok {
		return
	}
	mappingID := r.PathValue("id")
	// Powod przy usuwaniu przekazuje sie parametrem: zadanie DELETE nie ma
	// ciala, a warunek jest ten sam co przy tworzeniu mapowania.
	dowod, ok := s.requireStepUp(w, r, actor, r.URL.Query().Get("reason"),
		"group_mapping.delete", "group_mapping", mappingID)
	if !ok {
		return
	}
	removed, err := s.authz.DeleteGroupMapping(r.Context(), mappingID)
	if err != nil {
		s.fail(w, err)
		return
	}
	if !removed {
		problem(w, http.StatusNotFound, "mapping_not_found", "mapowanie nie istnieje")
		return
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: actor.Subject,
		Action: "group_mapping.delete", TargetType: "group_mapping", TargetID: mappingID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: withStepUp(map[string]any{}, dowod),
	})
	w.WriteHeader(http.StatusNoContent)
}
