package helpercap

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
)

// Verifier checks a capability against the host, the request and the keyring.
// The order of the checks is part of the contract (chapter 3.
type Verifier struct {
	// hostID reads the root-owned host identity.
	hostID func() (string, error)
	// keyring loads the root-owned keys, for the same reason.
	keyring func() (*Keyring, error)
	replay  *ReplayStore
	now     func() time.Time
}

// NewVerifier builds a verifier over a trust store and a replay store.
func NewVerifier(trust TrustStore, replay *ReplayStore, log *slog.Logger) *Verifier {
	return &Verifier{
		hostID: trust.HostID,
		keyring: func() (*Keyring, error) {
			ring, skipped, err := trust.Keyring()
			for _, problem := range skipped {
				log.Warn("a key file of the helper keyring was not honoured", "problem", problem)
			}
			return ring, err
		},
		replay: replay,
		now:    time.Now,
	}
}

// NewVerifierWith builds a verifier from parts held in memory; the tests
// use it.
func NewVerifierWith(hostID string, keyring *Keyring, replay *ReplayStore, now func() time.Time) *Verifier {
	if now == nil {
		now = time.Now
	}
	return &Verifier{
		hostID:  func() (string, error) { return hostID, nil },
		keyring: func() (*Keyring, error) { return keyring, nil },
		replay:  replay,
		now:     now,
	}
}

// Verify checks the capability the request carries against the request.
func (v *Verifier) Verify(request *helperv1.HelperRequest, expectation Expectation) error {
	capability := request.GetCapability()
	if capability == nil {
		return refusal(ErrorCapabilityRequired, "the request carries no capability")
	}
	if capability.GetSchemaVersion() != SchemaVersion {
		return refusal(ErrorCapabilityVersion,
			fmt.Sprintf("the capability has layout %d, this helper reads %d", capability.GetSchemaVersion(), SchemaVersion))
	}
	localHost, err := v.hostID()
	if err != nil {
		return fmt.Errorf("reading the host identity: %w", err)
	}
	if localHost == "" {
		return refusal(ErrorWrongHost, "the helper has no host identity yet; the trust bundle of the panel has not reached it")
	}
	if capability.GetHostId() != localHost {
		return refusal(ErrorWrongHost, "the capability names another host")
	}
	if !expectation.Allows(capability.GetActionType()) {
		return refusal(ErrorWrongAction,
			fmt.Sprintf("the capability authorizes %s, the request asks for %s", capability.GetActionType(), expectation.Kind))
	}
	if request.GetTaskId() != capability.GetTaskId() {
		return refusal(ErrorWrongAction, "the capability is for another task than the request names")
	}
	now := v.now().Unix()
	skew := int64(ClockSkew.Seconds())
	// The start of the window forgives a clock behind the panel's; the end
	// forgives nothing, so a stale capability is stale on the second.
	if now < capability.GetNotBeforeUnix()-skew || now > capability.GetExpiresUnix() {
		return refusal(ErrorCapabilityExpired,
			fmt.Sprintf("the capability is valid from %s to %s",
				time.Unix(capability.GetNotBeforeUnix(), 0).UTC().Format(time.RFC3339),
				time.Unix(capability.GetExpiresUnix(), 0).UTC().Format(time.RFC3339)))
	}
	// The window the panel issues starts ClockSkew before the moment of
	// issue, so the longest honest window is the class window plus that.
	longest := int64(MaxTTL[ClassOf(capability.GetActionType())].Seconds()) + skew
	if capability.GetExpiresUnix()-capability.GetNotBeforeUnix() > longest {
		return refusal(ErrorTTLTooLong,
			fmt.Sprintf("the window of the capability is longer than %s", MaxTTL[ClassOf(capability.GetActionType())]))
	}
	digest := sha256.Sum256(request.GetCanonicalPayload())
	if len(capability.GetPayloadSha256()) != len(digest) ||
		subtle.ConstantTimeCompare(digest[:], capability.GetPayloadSha256()) != 1 {
		return refusal(ErrorPayloadMismatch, "the payload handed over is not the one the capability binds")
	}
	bound, err := DecodeCanonicalPayload(request.GetCanonicalPayload())
	if err != nil {
		return refusal(ErrorPayloadMismatch, err.Error())
	}
	if string(bound.Action) != capability.GetActionType() {
		return refusal(ErrorPayloadBinding,
			fmt.Sprintf("the bound payload is of %s, the capability of %s", bound.Action, capability.GetActionType()))
	}
	if err := CheckBinding(request, bound); err != nil {
		return err
	}
	ring, err := v.keyring()
	if err != nil {
		return fmt.Errorf("reading the keyring: %w", err)
	}
	public, ok := ring.Lookup(capability.GetKeyId())
	if !ok {
		return refusal(ErrorUnknownKey,
			fmt.Sprintf("the keyring holds no key %s", capability.GetKeyId()))
	}
	if !VerifySignature(public, capability, request.GetCapabilitySignature()) {
		return refusal(ErrorBadSignature, "the signature of the capability does not verify")
	}
	if v.replay == nil {
		return fmt.Errorf("the helper has no replay store")
	}
	return v.replay.Consume(capability.GetNonce(), capability.GetExpiresUnix(), capability.GetTaskId())
}

// Decision is what the policy says about one request.
type Decision struct {
	// Allowed says the request may run.
	Allowed bool
	// Code and Message describe a refusal, or under observe the failure
	// that was recorded and let through.
	Code    string
	Message string
	// Outcome names the path for the log and the counters: read, verified,
	// legacy, observed, refused.
	Outcome string
	// Legacy says the request carried no capability and was let through.
	Legacy bool
	// CapabilityID names the verified capability, for the audit line.
	CapabilityID string
}

// The outcomes of a decision.
const (
	OutcomeRead     = "read"
	OutcomeVerified = "verified"
	OutcomeLegacy   = "legacy"
	OutcomeObserved = "observed"
	OutcomeRefused  = "refused"
)

// Policy joins the mode with the verifier.
type Policy struct {
	Mode     Mode
	Verifier *Verifier
	// The counters are the helper's own telemetry, printed to the log at
	// every legacy request; the helper exports nothing else.
	legacy   atomic.Uint64
	verified atomic.Uint64
	refused  atomic.Uint64
	observed atomic.Uint64
}

// NewPolicy builds a policy.
func NewPolicy(mode Mode, verifier *Verifier) *Policy {
	return &Policy{Mode: mode, Verifier: verifier}
}

// Counters returns how many requests took each path since the start.
func (p *Policy) Counters() (legacy, verified, refused, observed uint64) {
	return p.legacy.Load(), p.verified.Load(), p.refused.Load(), p.observed.Load()
}

// Decide applies the mode to a request.
func (p *Policy) Decide(request *helperv1.HelperRequest) Decision {
	expectation := Expect(request)
	if !expectation.Mutating {
		return Decision{Allowed: true, Outcome: OutcomeRead}
	}
	if request.GetCapability() == nil {
		if p.Mode == ModeEnforce {
			p.refused.Add(1)
			return Decision{Outcome: OutcomeRefused, Code: ErrorCapabilityRequired,
				Message: "the helper runs in enforce mode and this request carries no capability of the panel"}
		}
		p.legacy.Add(1)
		return Decision{Allowed: true, Outcome: OutcomeLegacy, Legacy: true}
	}
	if p.Verifier == nil {
		p.refused.Add(1)
		return Decision{Outcome: OutcomeRefused, Code: ErrorUnknownKey,
			Message: "the helper has no keyring to verify the capability against"}
	}
	err := p.Verifier.Verify(request, expectation)
	if err == nil {
		p.verified.Add(1)
		return Decision{Allowed: true, Outcome: OutcomeVerified,
			CapabilityID: request.GetCapability().GetCapabilityId()}
	}
	code := CodeOf(err)
	if code == "" {
		// Not a refusal but a failure of the helper's own machinery - a keyring or a
		// replay directory that cannot be read.
		code = ErrorBadSignature
	}
	if p.Mode == ModeObserve {
		p.observed.Add(1)
		return Decision{Allowed: true, Outcome: OutcomeObserved, Code: code, Message: err.Error(),
			CapabilityID: request.GetCapability().GetCapabilityId()}
	}
	p.refused.Add(1)
	return Decision{Outcome: OutcomeRefused, Code: code, Message: err.Error(),
		CapabilityID: request.GetCapability().GetCapabilityId()}
}
