package scheduler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ultherego/flotestro/internal/gateway"
	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/helpercap"
	"github.com/ultherego/flotestro/internal/jobs"
	"github.com/ultherego/flotestro/internal/metrics"
	"github.com/ultherego/flotestro/internal/opspec"
)

// The capability is minted at dispatch, not when the job is created: a
// host that is offline for hours must not hold a valid authorization for
// hours. The window starts now and is as long as the class of the
// operation needs to start, and the nonce is fresh for this attempt.

// helperCapabilityDispatch counts what the dispatch did about the
// capability: minted, legacy_agent for a host whose agent does not forward
// one, no_signer for a panel without a key, refused for a host held back
// under enforce. The share of legacy hosts is what decides when the mode
// can move on.
var helperCapabilityDispatch = metrics.Default.NewCounter("flotestro_helper_capability_total",
	"Capabilities minted at dispatch, by outcome.", "outcome", "gateway")

// PrincipalPermissions reads the permissions of the creator of a task, by
// the subject the task records. An interface rather than the authz store:
// the scheduler is to derive the grants, not to know how identities are
// kept.
type PrincipalPermissions interface {
	PermissionsOfSubject(ctx context.Context, subject string) ([]string, error)
}

// HelperCapabilities configures the minting.
type HelperCapabilities struct {
	// Signer holds the panel's key. Nil mints nothing.
	Signer *helpercap.Signer
	// Mode is the panel's stage of the rollout. Under observe and prefer a
	// host whose agent does not forward a capability gets the envelope it
	// knows; prefer says so on the log. Under enforce such a host gets no
	// mutating task at all.
	Mode helpercap.Mode
	// Permissions reads the creator's permissions for the grants. Nil means
	// the grants are the permission of the action alone.
	Permissions PrincipalPermissions
}

// SetHelperCapabilities connects the capability key and the rollout mode.
func (s *Scheduler) SetHelperCapabilities(capabilities HelperCapabilities) {
	s.capabilities = capabilities
}

// errCapabilityUnsupported marks a host held back under enforce.
var errCapabilityUnsupported = errors.New("the agent of the host does not forward a helper capability")

// ErrorHelperCapabilityUnsupported is the code such a task ends with.
const ErrorHelperCapabilityUnsupported = "helper_capability_unsupported"

// attachCapability mints and signs the capability of a mutating task and
// puts it on the envelope. It returns the identifier for the audit trail,
// or "" when no capability went out, and an error only under enforce for
// a host that cannot carry one.
func (s *Scheduler) attachCapability(ctx context.Context, item jobs.LeasedJob,
	envelope *agentv1.TaskEnvelope) (string, error) {
	action := opspec.ActionType(item.Job.ActionType)
	if !action.Mutating() {
		return "", nil
	}
	if s.capabilities.Signer == nil {
		helperCapabilityDispatch.Inc("no_signer", s.options.GatewayID)
		return "", nil
	}
	session, ok := s.registry.Get(item.Job.HostID)
	if !ok || !session.HelperCapabilitySupported {
		switch s.capabilities.Mode {
		case helpercap.ModeEnforce:
			helperCapabilityDispatch.Inc("refused", s.options.GatewayID)
			return "", errCapabilityUnsupported
		case helpercap.ModePrefer:
			s.log.Info("legacy dispatch: the agent of the host does not forward a helper capability",
				"job_id", item.Job.ID, "host_id", item.Job.HostID, "action", item.Job.ActionType,
				"agent_version", agentVersionOf(session))
		}
		helperCapabilityDispatch.Inc("legacy_agent", s.options.GatewayID)
		return "", nil
	}

	var payload opspec.Payload
	if err := json.Unmarshal(item.Job.Payload, &payload); err != nil {
		return "", err
	}
	canonical, err := helpercap.CanonicalPayload(action, item.Job.ActionVersion, payload)
	if err != nil {
		return "", fmt.Errorf("the canonical payload: %w", err)
	}
	// The grants come from the creator's permissions; a creator the store
	// does not know - a system task, a subject removed since - gets the
	// permission of the action alone, which is the narrow side.
	var permissions []string
	if s.capabilities.Permissions != nil && item.Job.CreatedBy != "" {
		permissions, err = s.capabilities.Permissions.PermissionsOfSubject(ctx, item.Job.CreatedBy)
		if err != nil {
			s.log.Warn("the permissions of the creator of the task were not read; the capability carries the action's own grant only",
				"job_id", item.Job.ID, "created_by", item.Job.CreatedBy, "err", err)
			permissions = nil
		}
	}
	approved := item.Job.ApprovedBy != "" || len(item.Job.Approvals) > 0
	capability, signature, err := s.capabilities.Signer.Issue(helpercap.Mint{
		HostID:        item.Job.HostID,
		TaskID:        item.AttemptID,
		ActionType:    item.Job.ActionType,
		PayloadSHA256: helpercap.PayloadDigest(canonical),
		Grants:        helpercap.GrantsFor(action, payload, permissions, approved),
		Now:           time.Now(),
	})
	if err != nil {
		return "", fmt.Errorf("minting the capability: %w", err)
	}
	envelope.HelperCapability = capability
	envelope.HelperCapabilitySignature = signature
	envelope.CanonicalPayload = canonical
	helperCapabilityDispatch.Inc("minted", s.options.GatewayID)
	return capability.GetCapabilityId(), nil
}

func agentVersionOf(session *gateway.Session) string {
	if session == nil {
		return ""
	}
	return session.AgentVersion
}
