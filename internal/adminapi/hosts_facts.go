package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/hosts"
)

// The facts an operator records about a host by hand: who answers for it,
// how it is reached and what it goes down with. Like the tags, they are the panel's knowledge
// about the machine rather than the machine's about itself - nothing runs
// on the host and it is not asked - so they share the tag permission and
// go straight to the row, not through the task queue.
//
// Two operators may correct the same host at once, so the reads and the
// writes carry an entity tag over these facts: a write with a stale
// If-Match is refused with the current tag rather than silently undoing
// the other correction.

// hostFactsTag is the version of the hand-recorded facts of a host. It
// covers only them, not the whole row: the row changes at every heartbeat,
// and a tag that changed under an operator's hands every ten seconds would
// refuse every honest write.
func hostFactsTag(host *hosts.Host) string {
	return etagOf("facts", host.Owner, host.ManagementAddress, host.ManagementAddressSource,
		host.FailureDomain, host.Site, host.Environment)
}

type hostOwnerRequest struct {
	// Owner is who answers for the host; empty hands it back to nobody.
	Owner string `json:"owner"`
	// Reason is the note for the trail; it is kept when given.
	Reason string `json:"reason"`
}

// handleSetHostOwner records the owner of a host.
func (s *Server) handleSetHostOwner(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	host, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	principal, ok := s.authorize(w, r, authz.PermHostTagWrite, scope, "host", hostID)
	if !ok {
		return
	}
	if !requireMatch(w, r, hostFactsTag(host)) {
		return
	}

	var request hostOwnerRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&request); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return
	}
	owner, err := hosts.NormalizeOwner(request.Owner)
	if errors.Is(err, hosts.ErrInvalidOwner) {
		problem(w, http.StatusBadRequest, "invalid_owner", err.Error())
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}

	updated, err := s.hosts.SetOwner(r.Context(), hostID, owner)
	if errors.Is(err, hosts.ErrNotFound) {
		problem(w, http.StatusNotFound, "host_not_found", "no such host")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}

	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "host.owner", TargetType: "host", TargetID: host.ID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{"before": host.Owner, "after": owner, "reason": strings.TrimSpace(request.Reason)},
		Before: map[string]any{"owner": host.Owner},
		After:  map[string]any{"owner": owner},
	})
	setETag(w, hostFactsTag(updated))
	writeJSON(w, http.StatusOK, updated)
}

type hostManagementAddressRequest struct {
	// Address is an IP address or a host name; empty forgets the manual
	// address and lets the observed one show again.
	Address string `json:"address"`
	Reason  string `json:"reason"`
}

// handleSetHostManagementAddress records the address an operator chose
// for reaching the host, or takes it away.
func (s *Server) handleSetHostManagementAddress(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	host, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	principal, ok := s.authorize(w, r, authz.PermHostTagWrite, scope, "host", hostID)
	if !ok {
		return
	}
	if !requireMatch(w, r, hostFactsTag(host)) {
		return
	}

	var request hostManagementAddressRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&request); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return
	}
	address, err := hosts.NormalizeManagementAddress(request.Address)
	if errors.Is(err, hosts.ErrInvalidAddress) {
		problem(w, http.StatusBadRequest, "invalid_address", err.Error())
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}

	updated, err := s.hosts.SetManualManagementAddress(r.Context(), hostID, address)
	if errors.Is(err, hosts.ErrNotFound) {
		problem(w, http.StatusNotFound, "host_not_found", "no such host")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}

	// The trail keeps the source with the address on both sides: an
	// address that went from 'manual' back to 'session' is a different
	// event from one that changed its digits.
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "host.management_address", TargetType: "host", TargetID: host.ID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"before": host.ManagementAddress, "after": updated.ManagementAddress,
			"reason": strings.TrimSpace(request.Reason),
		},
		Before: map[string]any{
			"management_address": host.ManagementAddress, "management_address_source": host.ManagementAddressSource,
		},
		After: map[string]any{
			"management_address": updated.ManagementAddress, "management_address_source": updated.ManagementAddressSource,
		},
	})
	setETag(w, hostFactsTag(updated))
	writeJSON(w, http.StatusOK, updated)
}

type hostFailureDomainRequest struct {
	// FailureDomain is what the host goes down with - a rack, a zone, a
	// cluster; empty takes the host out from under the domain budgets.
	FailureDomain string `json:"failure_domain"`
	// Reason is the note for the trail; it is kept when given.
	Reason string `json:"reason"`
}

// handleSetHostFailureDomain records the failure domain of a host.
//
// The domain is a budget key from the moment it is written: the next change
// on the host asks for a token of domain:<domain>:<family>, next to the
// site's. That is why it is a fact recorded by hand and not a tag - a tag
// says something about the host, the domain limits what may happen to it.
func (s *Server) handleSetHostFailureDomain(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	host, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	principal, ok := s.authorize(w, r, authz.PermHostTagWrite, scope, "host", hostID)
	if !ok {
		return
	}
	if !requireMatch(w, r, hostFactsTag(host)) {
		return
	}

	var request hostFailureDomainRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&request); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return
	}
	domain, err := hosts.NormalizeFailureDomain(request.FailureDomain)
	if errors.Is(err, hosts.ErrInvalidFailureDomain) {
		problem(w, http.StatusBadRequest, "invalid_failure_domain", err.Error())
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}

	updated, err := s.hosts.SetFailureDomain(r.Context(), hostID, domain)
	if errors.Is(err, hosts.ErrNotFound) {
		problem(w, http.StatusNotFound, "host_not_found", "no such host")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}

	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "host.failure_domain", TargetType: "host", TargetID: host.ID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{"before": host.FailureDomain, "after": domain, "reason": strings.TrimSpace(request.Reason)},
		Before: map[string]any{"failure_domain": host.FailureDomain},
		After:  map[string]any{"failure_domain": domain},
	})
	setETag(w, hostFactsTag(updated))
	writeJSON(w, http.StatusOK, updated)
}
