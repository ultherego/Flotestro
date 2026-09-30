package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/ultherego/flotestro/internal/advertise"
	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
)

// The address the agents reach this panel at.
//
// It is read here and confirmed here, and the two are not symmetric on
// purpose: the panel reads the addresses of its own interfaces and offers them,
// but it adopts none of them. It cannot tell which of its interfaces the hosts
// route to, and putting the wrong one into the certificate produces a fleet
// that enrols and drops out again with nothing saying why. So detection
// proposes and an administrator decides.

// SetAdvertised attaches the address the installation is seen under.
func (s *Server) SetAdvertised(store *advertise.Store) { s.advertised = store }

// advertisedAddressAnswer is what the Setup screen reads: what is in force,
// where that came from, and the proposals.
type advertisedAddressAnswer struct {
	advertise.State
	// Candidates are the addresses of this machine and the name it answers to.
	// They are proposals: none of them is in force until it comes back through
	// the confirmation.
	Candidates []advertise.Candidate `json:"candidates"`
	// Note explains the precedence in one sentence, so the screen does not have
	// to carry the rule as well.
	Note string `json:"note"`
}

// advertisedAddressWrite is the confirmation. The names are written out in
// full rather than named by an index into the candidates: a list read a second
// later may be a different list, and confirming "the second one" would then
// confirm something nobody looked at.
type advertisedAddressWrite struct {
	Names []string `json:"names"`
	// Reason goes on the audit trail beside the names.
	Reason string `json:"reason"`
}

// advertisedAddressNote is the precedence, stated where it is acted on.
const advertisedAddressNote = "A confirmed address takes effect on every replica within half a " +
	"minute and survives a restart and a recreated container. An installation that sets " +
	"FLOTESTRO_ADVERTISE to a reachable address declares it in the deployment, and that " +
	"declaration decides: the confirmation is refused rather than stored where it would not take " +
	"effect. A detected address is a proposal until it is confirmed here."

// handleAdvertisedAddress reports the address in force and the proposals.
// The permission is settings.read.
func (s *Server) handleAdvertisedAddress(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, authz.PermSettingsRead, authz.GlobalScope,
		"advertised_address", ""); !ok {
		return
	}
	if s.advertised == nil {
		problem(w, http.StatusNotFound, "advertised_address_unavailable",
			"this panel was started without the advertised-address setting")
		return
	}
	writeJSON(w, http.StatusOK, advertisedAddressAnswer{
		State:      s.advertised.State(),
		Candidates: advertise.Detect(),
		Note:       advertisedAddressNote,
	})
}

// handleConfirmAdvertisedAddress stores an administrator's choice. This is the
// only way a network address enters the panel's certificate.
//
// The permission is settings.advertise.write and not settings.read: what this
// changes is where the whole fleet connects. There is no step-up on it, and
// that is deliberate - the flow this serves has the administrator arriving
// through the bootstrap token on a panel that has no identity provider yet, and
// an installation whose step-up policy refuses token sessions would then have
// no way to become reachable at all. The audit entry carries who confirmed
// what, before and after.
func (s *Server) handleConfirmAdvertisedAddress(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorize(w, r, authz.PermSettingsAdvertiseWrite, authz.GlobalScope,
		"advertised_address", "")
	if !ok {
		return
	}
	if s.advertised == nil {
		problem(w, http.StatusNotFound, "advertised_address_unavailable",
			"this panel was started without the advertised-address setting")
		return
	}
	var body advertisedAddressWrite
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		problem(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	before := s.advertised.State()
	state, err := s.advertised.Confirm(r.Context(), advertise.Of(body.Names), principal.Subject)
	switch {
	case errors.Is(err, advertise.ErrNoName):
		problem(w, http.StatusBadRequest, advertise.ErrNoName.Error(),
			"names: a confirmation names at least one address or DNS name the agents can reach")
		return
	case errors.Is(err, advertise.ErrInvalidName):
		problem(w, http.StatusBadRequest, advertise.ErrInvalidName.Error(), err.Error())
		return
	case errors.Is(err, advertise.ErrEnvironmentInForce):
		// A refusal and not a silent store: an address kept where it does not
		// take effect is a screen that lies about where the fleet connects.
		s.audit.Record(r.Context(), audit.Event{
			ActorType: audit.ActorUser, ActorID: principal.Subject,
			Action: string(authz.PermSettingsAdvertiseWrite), TargetType: "advertised_address",
			RequestID: requestIDOf(r), Outcome: audit.OutcomeFailure,
			Detail: map[string]any{"names": body.Names, "reason": body.Reason,
				"refusal": advertise.ErrEnvironmentInForce.Error()},
		})
		problem(w, http.StatusConflict, advertise.ErrEnvironmentInForce.Error(), err.Error())
		return
	case err != nil:
		s.fail(w, err)
		return
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: string(authz.PermSettingsAdvertiseWrite), TargetType: "advertised_address",
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{"reason": body.Reason, "revision": state.Revision},
		Before: map[string]any{"advertised": before.InForce, "reserved": before.Reserved},
		After:  map[string]any{"advertised": state.InForce, "reserved": state.Reserved},
	})
	writeJSON(w, http.StatusOK, advertisedAddressAnswer{
		State:      state,
		Candidates: advertise.Detect(),
		Note:       advertisedAddressNote,
	})
}
