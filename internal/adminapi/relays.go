package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/relays"
)

// relayView is a relay as the panel shows it: the registry row together
// with what follows from it - the state, the hosts it attests and what it
// last reported about itself.
type relayView struct {
	relays.Relay
	// State is one of active, silent, never_seen and revoked: the same four
	// the metrics count.
	State string `json:"state"`
	// HostsAttested counts the hosts whose open session came through the
	// relay.
	HostsAttested int `json:"hosts_attested"`
	// Buffer is what the relay reported at its last heartbeat; missing when
	// it has not reported since the panel started.
	Buffer *relays.Heartbeat `json:"buffer,omitempty"`
	// CertificateNotAfter is the end of the current certificate; the same
	// value as not_after, under the name the list is read by.
	CertificateNotAfter *time.Time `json:"certificate_not_after,omitempty"`
	AdvertisedNames     []string   `json:"advertised_names,omitempty"`
}

func (s *Server) relayView(relay relays.Relay, attested int, now time.Time) relayView {
	view := relayView{
		Relay: relay, State: relay.StateAt(now), HostsAttested: attested,
		CertificateNotAfter: relay.NotAfter,
	}
	if heartbeat, ok := s.relays.LastHeartbeat(relay.ID); ok {
		view.Buffer = &heartbeat
	}
	return view
}

// handleListRelays lists the relays with their state.
//
// The list serves two readers: the installation of a host, which needs a
// route, and the relay page, which needs to know which site is about to be
// cut off. Both read it with the right to prepare an installation, narrowed
// to the sites the reader may prepare installations in. A relay without an
// environment serves its whole site, so a binding to any environment of the
// site sees it.
func (s *Server) handleListRelays(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermHostEnrollRead, "relay")
	if !ok {
		return
	}
	items := []relayView{}
	if s.relays != nil {
		list, err := s.relays.List(r.Context())
		if err != nil {
			s.fail(w, err)
			return
		}
		attested, err := s.relays.AttestedCounts(r.Context())
		if err != nil {
			s.fail(w, err)
			return
		}
		now := time.Now()
		site := r.URL.Query().Get("site")
		for _, relay := range list {
			if site != "" && relay.Site != site {
				continue
			}
			if relayVisible(principal, relay) {
				items = append(items, s.relayView(relay, attested[relay.ID], now))
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "count": len(items)})
}

func relayVisible(principal authz.Principal, relay relays.Relay) bool {
	for _, binding := range principal.Bindings {
		if !binding.Role.Has(authz.PermHostEnrollRead) {
			continue
		}
		granted := binding.Scope
		siteMatches := granted.Site == authz.Wildcard || (granted.Site != "" && granted.Site == relay.Site)
		environmentMatches := relay.Environment == "" || granted.Environment == authz.Wildcard ||
			granted.Environment == relay.Environment
		if siteMatches && environmentMatches {
			return true
		}
	}
	return false
}

// loadRelay reads a relay for a handler and answers the request itself
// when there is none to read.
func (s *Server) loadRelay(w http.ResponseWriter, r *http.Request) (*relays.Relay, bool) {
	if s.relays == nil {
		problem(w, http.StatusNotFound, "relay_not_found", "this installation has no relays")
		return nil, false
	}
	relayID := r.PathValue("id")
	if _, err := uuid.Parse(relayID); err != nil {
		problem(w, http.StatusNotFound, "relay_not_found", "no such relay")
		return nil, false
	}
	relay, err := s.relays.Get(r.Context(), relayID)
	if errors.Is(err, relays.ErrNotFound) {
		problem(w, http.StatusNotFound, "relay_not_found", "no such relay")
		return nil, false
	}
	if err != nil {
		s.fail(w, err)
		return nil, false
	}
	return relay, true
}

// handleGetRelay shows one relay together with the hosts it attests.
func (s *Server) handleGetRelay(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermHostEnrollRead, "relay")
	if !ok {
		return
	}
	relay, ok := s.loadRelay(w, r)
	if !ok {
		return
	}
	if !relayVisible(principal, *relay) {
		// The same answer as for a relay that does not exist: a narrowed
		// scope is not to learn which sites have relays.
		problem(w, http.StatusNotFound, "relay_not_found", "no such relay")
		return
	}
	hosts, err := s.relays.AttestedHosts(r.Context(), relay.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	names, err := s.relays.Names(r.Context(), relay.ID)
	if err != nil && !errors.Is(err, relays.ErrNotFound) {
		s.fail(w, err)
		return
	}
	view := s.relayView(*relay, len(hosts), time.Now())
	view.AdvertisedNames = names
	writeJSON(w, http.StatusOK, map[string]any{"relay": view, "hosts": hosts})
}

// relayRevocation is the body of a revocation order.
type relayRevocation struct {
	Reason string `json:"reason"`
}

// handleRevokeRelay takes the right to mediate away from a relay.
//
// The relay stops being recognised at once: its heartbeat, its renewal and
// every new session through it are refused from this moment, and the
// sessions it attested are ended - the agents reconnect on their own, over
// their remaining gateways or another relay, or not at all. That is a
// deliberate decision about a whole site, so it is taken with fresh
// authentication and a reason, and it leaves one entry on the trail.
func (s *Server) handleRevokeRelay(w http.ResponseWriter, r *http.Request) {
	relay, ok := s.loadRelay(w, r)
	if !ok {
		return
	}
	// A relay without an environment serves its whole site, so cutting it
	// off needs a right over the whole site: an empty environment is
	// matched only by a wildcard binding.
	scope := authz.Scope{Site: relay.Site, Environment: relay.Environment}
	principal, ok := s.authorize(w, r, authz.PermRelayManage, scope, "relay", relay.ID)
	if !ok {
		return
	}

	var req relayRevocation
	if r.ContentLength > 0 {
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
			problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
			return
		}
	}
	req.Reason = strings.TrimSpace(req.Reason)
	if req.Reason == "" {
		problem(w, http.StatusBadRequest, "reason_required", "revoking a relay must state its reason")
		return
	}
	if relay.RevokedAt != nil {
		problem(w, http.StatusConflict, "relay_revoked", "the relay is already revoked")
		return
	}
	evidence, ok := s.requireStepUp(w, r, principal, req.Reason, "relay.revoke", "relay", relay.ID)
	if !ok {
		return
	}

	// The hosts are read before the revocation: afterwards their sessions
	// are what is to be ended, and the list is what the trail says was cut.
	attested, err := s.relays.AttestedHosts(r.Context(), relay.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	if err := s.relays.Revoke(r.Context(), relay.ID, req.Reason); err != nil {
		if errors.Is(err, relays.ErrNotFound) {
			problem(w, http.StatusConflict, "relay_revoked", "the relay is already revoked")
			return
		}
		s.fail(w, err)
		return
	}

	// The sessions end only after the write: had the revocation failed, the
	// hosts would be disconnected from a relay the panel still trusts, and
	// they would come straight back through it.
	closed := 0
	hostIDs := make([]string, 0, len(attested))
	for _, host := range attested {
		hostIDs = append(hostIDs, host.HostID)
		if s.registry != nil && s.registry.EndSession(host.HostID, "relay.revoke") {
			closed++
		}
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "relay.revoke", TargetType: "relay", TargetID: relay.ID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: withStepUp(map[string]any{
			"reason": req.Reason, "name": relay.Name, "site": relay.Site,
			"cert_serial": relay.Serial, "hosts_attested": hostIDs, "sessions_closed": closed,
		}, evidence),
	})
	s.log.Info("the relay was revoked", "relay_id", relay.ID, "name", relay.Name,
		"site", relay.Site, "sessions_closed", closed, "actor", principal.Subject)

	revoked, err := s.relays.Get(r.Context(), relay.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"relay":           s.relayView(*revoked, 0, time.Now()),
		"hosts_attested":  len(attested),
		"sessions_closed": closed,
	})
}
