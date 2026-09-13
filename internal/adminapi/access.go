package adminapi

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/identity"
)

// The effective access: who may enter a host and with what privileges. The
// panel reads the directory's rules and projects them onto one host; the
// verdict for a concrete user comes from the directory's own simulation, so
// the answer is the one the host will apply rather than a reconstruction.

// handleSimulateAccess asks the directory whether a user may use a service
// on a host. It reads and changes nothing, so it needs the policy read
// permission and no plan.
func (s *Server) handleSimulateAccess(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, authz.PermIdentityPolicyRead, authz.GlobalScope, "identity", "access-simulate"); !ok {
		return
	}
	if s.directory == nil {
		problem(w, http.StatusNotImplemented, "directory_disabled",
			"no directory connector is configured")
		return
	}

	var request struct {
		User    string `json:"user"`
		Host    string `json:"host"`
		Service string `json:"service"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14)).Decode(&request); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return
	}
	request.User = strings.TrimSpace(request.User)
	request.Host = strings.TrimSpace(request.Host)
	request.Service = strings.TrimSpace(request.Service)
	if request.User == "" || request.Host == "" {
		problem(w, http.StatusBadRequest, "invalid_body", "the simulation requires a user and a host")
		return
	}
	if request.Service == "" {
		// Signing in over SSH is what the question is about nearly always.
		request.Service = "sshd"
	}

	result, err := s.directory.HBACTest(r.Context(), request.User, request.Host, request.Service)
	if err != nil {
		if strings.Contains(err.Error(), "invalid") {
			problem(w, http.StatusBadRequest, "invalid_body", err.Error())
			return
		}
		// A directory failure is a state, not an internal panel error.
		problem(w, http.StatusBadGateway, "directory_unavailable", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// handleHostAccess returns the effective access of one host: its host
// groups and the access and sudo rules that reach it. The projection is
// computed from the same short-lived directory reads as the other directory
// views, so it is as fresh as they are and no fresher.
func (s *Server) handleHostAccess(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	host, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	if _, ok := s.authorize(w, r, authz.PermIdentityRead, scope, "host", hostID); !ok {
		return
	}
	if s.directory == nil {
		problem(w, http.StatusNotImplemented, "directory_disabled",
			"no directory connector is configured")
		return
	}

	access, err := identity.EffectiveAccess(r.Context(), s.directory, host.Hostname, host.Identity.Domain)
	if err != nil {
		problem(w, http.StatusBadGateway, "directory_unavailable", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, access)
}
