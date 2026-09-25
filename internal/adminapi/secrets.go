package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/secrets"
)

// The secret store has one property that must not be lost: a value goes in and
// does not come out.

type secretRequest struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	// Value is the only place where the value appears in the API - and only
	// in the direction towards the panel.
	Value string `json:"value"`
	// Reason says what the change is for.
	Reason string `json:"reason"`
}

// secretsReady says whether the installation has a secret store. The
// answer has been written when the result is false.
func (s *Server) secretsReady(w http.ResponseWriter) bool {
	if s.secrets == nil {
		problem(w, http.StatusServiceUnavailable, "secrets_disabled",
			"this installation has no secret store")
		return false
	}
	return true
}

// handleListSecrets returns the secret metadata.
func (s *Server) handleListSecrets(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorizeCollection(w, r, authz.PermSecretRead, "secrets"); !ok {
		return
	}
	if s.secrets == nil {
		problem(w, http.StatusServiceUnavailable, "secrets_disabled",
			"this installation has no secret store")
		return
	}
	list, err := s.secrets.List(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	if list == nil {
		list = []secrets.Secret{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": list, "count": len(list)})
}

// handleGetSecret returns the metadata of one secret together with the
// version history.
func (s *Server) handleGetSecret(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorizeCollection(w, r, authz.PermSecretRead, "secrets"); !ok {
		return
	}
	secret, ok := s.secret(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, secret)
}

// handleCreateSecret creates a secret together with its first version.
func (s *Server) handleCreateSecret(w http.ResponseWriter, r *http.Request) {
	// A secret has no site: it can be named by a task on any host, so the
	// permission is the global one.
	principal, ok := s.authorize(w, r, authz.PermSecretWrite, authz.GlobalScope, "secret", "")
	if !ok {
		return
	}
	if !s.secretsReady(w) {
		return
	}

	var request secretRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return
	}
	evidence, ok := s.requireStepUp(w, r, principal, request.Reason, "secret.create", "secret", request.Name)
	if !ok {
		return
	}
	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	if _, err := s.secrets.CreateTx(r.Context(), tx, request.Name, request.Description,
		[]byte(request.Value), principal.Subject); err != nil {
		problem(w, http.StatusBadRequest, "invalid_secret", err.Error())
		return
	}
	// The entry records the creation and the size - never the value. It is also
	// the only record that this value ever entered the store, because the value
	// is never readable again, so it commits with the secret or not at all.
	if err := s.audit.RecordTx(r.Context(), tx, audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "secret.create", TargetType: "secret", TargetID: request.Name,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: withStepUp(map[string]any{
			"version": 1, "size_bytes": len(request.Value),
		}, evidence),
	}); err != nil {
		s.fail(w, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		s.fail(w, err)
		return
	}
	secret, err := s.secrets.Secret(r.Context(), request.Name)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, secret)
}

// handleRotateSecret adds a new version and makes it current.
func (s *Server) handleRotateSecret(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorize(w, r, authz.PermSecretWrite, authz.GlobalScope, "secret", r.PathValue("name"))
	if !ok {
		return
	}
	if !s.secretsReady(w) {
		return
	}

	var request secretRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return
	}
	evidence, ok := s.requireStepUp(w, r, principal, request.Reason, "secret.rotate", "secret", r.PathValue("name"))
	if !ok {
		return
	}
	name := r.PathValue("name")
	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	version, err := s.secrets.RotateTx(r.Context(), tx, name, []byte(request.Value), principal.Subject)
	switch {
	case errors.Is(err, secrets.ErrNotFound):
		problem(w, http.StatusNotFound, "secret_not_found", "no such secret")
		return
	case errors.Is(err, secrets.ErrRetired):
		problem(w, http.StatusConflict, "secret_retired", "this secret has been retired")
		return
	case err != nil:
		problem(w, http.StatusBadRequest, "invalid_secret", err.Error())
		return
	}
	// The previous versions stay: a host with a lease on an earlier version
	// is meant to get it also after the rotation.
	if err := s.audit.RecordTx(r.Context(), tx, audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "secret.rotate", TargetType: "secret", TargetID: name,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: withStepUp(map[string]any{
			"version": version, "size_bytes": len(request.Value),
		}, evidence),
	}); err != nil {
		s.fail(w, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		s.fail(w, err)
		return
	}
	secret, err := s.secrets.Secret(r.Context(), name)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, secret)
}

// handleRetireSecret closes a secret: the metadata stays, issuing ends.
func (s *Server) handleRetireSecret(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	principal, ok := s.authorize(w, r, authz.PermSecretDestroy, authz.GlobalScope, "secret", name)
	if !ok {
		return
	}
	if !s.secretsReady(w) {
		return
	}
	reason, ok := requestReason(w, r, nil)
	if !ok {
		return
	}
	evidence, ok := s.requireStepUp(w, r, principal, reason, "secret.retire", "secret", name)
	if !ok {
		return
	}
	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	if err := s.secrets.RetireTx(r.Context(), tx, name); err != nil {
		if errors.Is(err, secrets.ErrNotFound) {
			problem(w, http.StatusNotFound, "secret_not_found", "no such secret")
			return
		}
		s.fail(w, err)
		return
	}
	if err := s.audit.RecordTx(r.Context(), tx, audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "secret.retire", TargetType: "secret", TargetID: name,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: withStepUp(map[string]any{}, evidence),
	}); err != nil {
		s.fail(w, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		s.fail(w, err)
		return
	}
	secret, err := s.secrets.Secret(r.Context(), name)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, secret)
}

// handleDestroySecretVersion deletes the content of one version.
func (s *Server) handleDestroySecretVersion(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	principal, ok := s.authorize(w, r, authz.PermSecretDestroy, authz.GlobalScope, "secret", name)
	if !ok {
		return
	}
	if !s.secretsReady(w) {
		return
	}
	version, err := versionFromPath(r.PathValue("version"))
	if err != nil {
		problem(w, http.StatusBadRequest, "invalid_version", err.Error())
		return
	}
	reason, ok := requestReason(w, r, nil)
	if !ok {
		return
	}
	evidence, ok := s.requireStepUp(w, r, principal, reason, "secret.destroy", "secret", name)
	if !ok {
		return
	}
	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	if err := s.secrets.DestroyTx(r.Context(), tx, name, version); err != nil {
		if errors.Is(err, secrets.ErrNotFound) {
			problem(w, http.StatusNotFound, "version_not_found", "no such secret version")
			return
		}
		s.fail(w, err)
		return
	}
	// The overwrite cannot be undone, so the entry naming who ordered it is the
	// last evidence there is: it commits with the overwrite.
	if err := s.audit.RecordTx(r.Context(), tx, audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "secret.destroy", TargetType: "secret", TargetID: name,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: withStepUp(map[string]any{"version": version}, evidence),
	}); err != nil {
		s.fail(w, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		s.fail(w, err)
		return
	}
	secret, err := s.secrets.Secret(r.Context(), name)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, secret)
}

func (s *Server) secret(w http.ResponseWriter, r *http.Request) (*secrets.Secret, bool) {
	if s.secrets == nil {
		problem(w, http.StatusServiceUnavailable, "secrets_disabled",
			"this installation has no secret store")
		return nil, false
	}
	secret, err := s.secrets.Secret(r.Context(), r.PathValue("name"))
	if errors.Is(err, secrets.ErrNotFound) {
		problem(w, http.StatusNotFound, "secret_not_found", "no such secret")
		return nil, false
	}
	if err != nil {
		s.fail(w, err)
		return nil, false
	}
	return secret, true
}

func versionFromPath(value string) (int, error) {
	version := 0
	for _, r := range value {
		if r < '0' || r > '9' {
			return 0, errors.New("the version must be a number")
		}
		version = version*10 + int(r-'0')
		if version > 1<<20 {
			return 0, errors.New("the version is out of range")
		}
	}
	if version == 0 {
		return 0, errors.New("the version must be a positive number")
	}
	return version, nil
}
