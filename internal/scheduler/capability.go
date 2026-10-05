package scheduler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/ultherego/flotestro/internal/gateway"
	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/helpercap"
	"github.com/ultherego/flotestro/internal/jobs"
	"github.com/ultherego/flotestro/internal/metrics"
	"github.com/ultherego/flotestro/internal/opspec"
)

// The capability is minted at dispatch, not when the job is created: a host
// that is offline for hours must not hold a valid authorization for hours.

// helperCapabilityDispatch counts what the dispatch did about the capability:
// minted, legacy_agent for a host whose agent does not forward one, no_signer
// for a panel without a key, refused for a host held back under enforce.
var helperCapabilityDispatch = metrics.Default.NewCounter("flotestro_helper_capability_total",
	"Capabilities minted at dispatch, by outcome.", "outcome", "gateway")

// PrincipalPermissions reads the permissions of the creator of a task, by the
// subject the task records.
type PrincipalPermissions interface {
	PermissionsOfSubject(ctx context.Context, subject string) ([]string, error)
}

// HelperCapabilities configures the minting.
type HelperCapabilities struct {
	// Signer holds the panel's key. Nil mints nothing.
	Signer *helpercap.Signer
	// Mode is the panel's stage of the rollout.
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

// errCreatorRightsUnconfirmed marks a task whose creator's rights nobody could
// read. The capability's grants follow from those rights, so the task waits
// with the reason instead of going out under an authorization nobody checked.
var errCreatorRightsUnconfirmed = errors.New("the rights of the task's creator are not confirmed")

// errCreatorRightsGone marks a task whose creator was read and does not hold
// the permission of its action any more. Unlike the unconfirmed case this does
// not come back by waiting.
var errCreatorRightsGone = errors.New("the creator of the task no longer holds the permission of its action")

// ErrorCreatorRightsUnconfirmed is the reason such a task is put back with.
const ErrorCreatorRightsUnconfirmed = "creator_rights_unconfirmed"

// ErrorCreatorRightsGone is the reason a task is settled with when its creator
// was read and no longer holds the permission of its action.
const ErrorCreatorRightsGone = "creator_rights_gone"

// ErrorHelperCapabilityUnsupported is the code such a task ends with.
const ErrorHelperCapabilityUnsupported = "helper_capability_unsupported"

// attachCapability mints and signs the capability of a mutating task and puts
// it on the envelope.
func (s *Scheduler) attachCapability(ctx context.Context, item jobs.LeasedJob,
	envelope *agentv1.TaskEnvelope) (string, error) {
	action := opspec.ActionType(item.Job.ActionType)
	// Every change goes under a capability, and so does a read that runs a tool
	// with what the order carried: the helper refuses those without one.
	if !action.UnderCapability() {
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
	// The grants come from the creator's permissions; a creator the store does
	// not know - a system task, a subject removed since - gets the permission of
	// the action alone, which is the narrow side.
	//
	// A question that was asked and not answered is a different matter: the
	// rights may be narrower than the action, and nobody can tell. The task
	// waits with the reason rather than leaving on a guess.
	var permissions []string
	if s.capabilities.Permissions != nil && item.Job.CreatedBy != "" {
		permissions, err = s.capabilities.Permissions.PermissionsOfSubject(ctx, item.Job.CreatedBy)
		if err != nil {
			s.log.Warn("the task waits: the rights of its creator were not read",
				"job_id", item.Job.ID, "created_by", item.Job.CreatedBy, "err", err)
			return "", fmt.Errorf("%w: %v", errCreatorRightsUnconfirmed, err)
		}
	}
	approved := item.Job.ApprovedBy != "" || len(item.Job.Approvals) > 0
	// A right the creator no longer holds is a different answer from one nobody
	// could read. The order waits for the second and stops for the first: the
	// task was queued when the creator could order it, the host came back after
	// they could not, and a capability minted now would carry a permission that
	// no longer exists.
	//
	// An approved job goes out on the approval instead: somebody who holds the
	// right said so, which is what an approval is for.
	if permission := action.Permission(); permissions != nil && permission != "" && !approved &&
		!slices.Contains(permissions, permission) {
		s.log.Warn("the task stops: its creator no longer holds the permission of the action",
			"job_id", item.Job.ID, "created_by", item.Job.CreatedBy, "permission", permission)
		return "", fmt.Errorf("%w: %s", errCreatorRightsGone, permission)
	}
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
