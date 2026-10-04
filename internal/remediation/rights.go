package remediation

import (
	"context"
	"errors"

	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/opspec"
)

// A plan is approved once and runs for hours. The rights behind it are
// therefore confirmed before each step, and the three possible answers are
// kept apart: the right is held, the right is gone, or nobody can say.

// StepRightsUnconfirmed is written on a step that waits because nobody could
// confirm the rights behind its plan.
const StepRightsUnconfirmed = "rights_unconfirmed"

// stepVerdict is what one check came to. Unknown is not a refusal: it is the
// absence of an answer, and a step waits on it with the reason written down.
type stepVerdict struct {
	held    bool
	unknown bool
	reason  string
}

func stepHeld() stepVerdict { return stepVerdict{held: true} }

func stepGone(reason string) stepVerdict { return stepVerdict{reason: reason} }

func stepUnconfirmed(reason string) stepVerdict {
	return stepVerdict{unknown: true, reason: reason}
}

// judgeRights reads the answer about a subject's rights for one step. A
// missing or disabled identity is an answer; a failed lookup, and a group
// membership no directory confirmed, are not.
func judgeRights(subject string, principal *authz.Principal, lookupErr error,
	permission authz.Permission, scope authz.Scope, place string) stepVerdict {
	switch {
	case errors.Is(lookupErr, authz.ErrUnauthenticated), errors.Is(lookupErr, authz.ErrNotFound):
		return stepGone("the identity behind the plan (" + subject + ") is disabled or gone")
	case errors.Is(lookupErr, authz.ErrGroupsUnavailable):
		// A group adds rights and never takes one away, so where a binding
		// granted by hand already carries this step, the question about the
		// groups cannot change the answer.
		if principal != nil && principal.Can(permission, scope) {
			return stepHeld()
		}
		return stepUnconfirmed("the group membership of " + subject +
			" is not confirmed: " + lookupErr.Error())
	case lookupErr != nil:
		return stepUnconfirmed("the rights of " + subject +
			" could not be checked: " + lookupErr.Error())
	case principal == nil:
		return stepUnconfirmed("the rights of " + subject +
			" could not be checked: the identity store answered with nothing")
	case !principal.Can(permission, scope):
		return stepGone(subject + " no longer holds " + string(permission) + " on " + place)
	}
	return stepHeld()
}

// mayRunStep says whether the identity behind the plan may still run this step
// on this host.
func (r *Runner) mayRunStep(ctx context.Context, plan Plan, step *Step, host *hosts.Host) stepVerdict {
	if r.authorizer == nil {
		return stepHeld()
	}
	subject, verdict := r.subjectOf(ctx, plan)
	if !verdict.held {
		return verdict
	}
	principal, err := r.authorizer.PrincipalBySubject(ctx, subject)
	permission := authz.Permission(opspec.ActionType(step.ActionType).Permission())
	return judgeRights(subject, principal, err, permission, hosts.ScopeOf(host),
		host.Site+"/"+host.Environment)
}

// subjectOf names the identity whose rights decide this plan: its own creator,
// or the person who ordered the campaign the plan belongs to.
func (r *Runner) subjectOf(ctx context.Context, plan Plan) (string, stepVerdict) {
	campaign := plan.Campaign()
	if campaign == "" {
		return plan.CreatedBy, stepHeld()
	}
	if r.creators == nil {
		return "", stepUnconfirmed("the identity that ordered the campaign " + campaign +
			" cannot be named: no source of campaign creators is configured")
	}
	subject, err := r.creators.CreatorOfCampaign(ctx, campaign)
	if err != nil {
		return "", stepUnconfirmed("the identity that ordered the campaign " + campaign +
			" could not be read: " + err.Error())
	}
	if subject == "" {
		return "", stepUnconfirmed("the campaign " + campaign + " names no creator")
	}
	return subject, stepHeld()
}

// holdStep leaves a step pending with the reason nobody could answer, so the
// wait is visible in the panel rather than silent. The next tick asks again.
func (r *Runner) holdStep(ctx context.Context, plan Plan, step *Step, reason string) error {
	held := StepRightsUnconfirmed + ": " + reason
	if step.Reason != held {
		r.log.Warn("a remediation step waits: the rights behind the plan are not confirmed",
			"plan_id", plan.ID, "host_id", plan.HostID, "check_id", step.CheckID, "reason", reason)
	}
	return r.store.HoldStep(ctx, step.ID, held)
}

// stopPlan ends a plan whose identity lost the right to it. The remaining
// steps are skipped with the reason and the plan is stopped rather than
// failed: nothing went wrong on the host, the order lost its authority.
func (r *Runner) stopPlan(ctx context.Context, plan Plan, reason string) error {
	if err := r.store.SkipRemaining(ctx, plan.ID, reason); err != nil {
		return err
	}
	r.log.Warn("the remediation plan was stopped: the rights behind it are gone",
		"plan_id", plan.ID, "host_id", plan.HostID, "reason", reason)
	return r.finish(ctx, plan, StateStopped, reason)
}
