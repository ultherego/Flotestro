package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/secrets"
)

// The secret store has one property that must not be lost: a value goes
// in and does not come out. The API allows creating, rotating and retiring
// a secret and destroying a version - but there is no way to read the
// content through it. The only way out for a value leads through a lease
// issued to a host for the duration of one task.

type secretRequest struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	// Value is the only place where the value appears in the API - and only
	// in the direction towards the panel.
	Value string `json:"value"`
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
	principal, ok := s.authorizeCollection(w, r, authz.PermSecretWrite, "secrets")
	if !ok {
		return
	}
	if s.secrets == nil {
		problem(w, http.StatusServiceUnavailable, "secrets_disabled",
			"this installation has no secret store")
		return
	}

	var request secretRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return
	}
	secret, err := s.secrets.Create(r.Context(), request.Name, request.Description,
		[]byte(request.Value), principal.Subject)
	if err != nil {
		problem(w, http.StatusBadRequest, "invalid_secret", err.Error())
		return
	}
	// The audit log records the creation and the size - never the value.
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "secret.create", TargetType: "secret", TargetID: secret.Name,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{"version": secret.CurrentVersion, "size_bytes": len(request.Value)},
	})
	writeJSON(w, http.StatusCreated, secret)
}

// handleRotateSecret adds a new version and makes it current.
func (s *Server) handleRotateSecret(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermSecretWrite, "secrets")
	if !ok {
		return
	}
	if s.secrets == nil {
		problem(w, http.StatusServiceUnavailable, "secrets_disabled",
			"this installation has no secret store")
		return
	}

	var request secretRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return
	}
	secret, err := s.secrets.Rotate(r.Context(), r.PathValue("name"), []byte(request.Value), principal.Subject)
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
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "secret.rotate", TargetType: "secret", TargetID: secret.Name,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{"version": secret.CurrentVersion, "size_bytes": len(request.Value)},
	})
	writeJSON(w, http.StatusOK, secret)
}

// handleRetireSecret closes a secret: the metadata stays, issuing ends.
func (s *Server) handleRetireSecret(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermSecretDestroy, "secrets")
	if !ok {
		return
	}
	if s.secrets == nil {
		problem(w, http.StatusServiceUnavailable, "secrets_disabled",
			"this installation has no secret store")
		return
	}
	name := r.PathValue("name")
	if err := s.secrets.Retire(r.Context(), name); err != nil {
		if errors.Is(err, secrets.ErrNotFound) {
			problem(w, http.StatusNotFound, "secret_not_found", "no such secret")
			return
		}
		s.fail(w, err)
		return
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "secret.retire", TargetType: "secret", TargetID: name,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
	})
	secret, err := s.secrets.Secret(r.Context(), name)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, secret)
}

// handleDestroySecretVersion deletes the content of one version.
//
// The row stays: the history is meant to show that the version existed and
// when it stopped. Destroyed content cannot be recovered from a database
// backup either.
func (s *Server) handleDestroySecretVersion(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermSecretDestroy, "secrets")
	if !ok {
		return
	}
	if s.secrets == nil {
		problem(w, http.StatusServiceUnavailable, "secrets_disabled",
			"this installation has no secret store")
		return
	}
	name := r.PathValue("name")
	version, err := versionFromPath(r.PathValue("version"))
	if err != nil {
		problem(w, http.StatusBadRequest, "invalid_version", err.Error())
		return
	}
	if err := s.secrets.Destroy(r.Context(), name, version); err != nil {
		if errors.Is(err, secrets.ErrNotFound) {
			problem(w, http.StatusNotFound, "version_not_found", "no such secret version")
			return
		}
		s.fail(w, err)
		return
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "secret.destroy", TargetType: "secret", TargetID: name,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{"version": version},
	})
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
