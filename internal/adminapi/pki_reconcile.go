package adminapi

import (
	"context"
	"errors"
	"log/slog"

	"github.com/ultherego/flotestro/internal/audit"
)

// trustIntentFamily is the family of actions the reconciler closes: the three
// changes to what the fleet trusts.
const trustIntentFamily = "pki.ca.%"

// ReconcileTrustIntents closes the beginnings of trust changes that no outcome
// answers. It happens when the change was made and the panel stopped before it
// could write the second entry - the only case the write-ahead order leaves
// open. Rather than guess, the reconciler reads the trust store and appends what
// is actually there, so the trail ends with a fact instead of a beginning.
//
// The entries are never removed, so this is safe to run at every start: a
// beginning that already has an outcome is not listed.
func (s *Server) ReconcileTrustIntents(ctx context.Context, log *slog.Logger) {
	if s.audit == nil || s.trust == nil {
		return
	}
	intents, err := s.audit.UnfinishedIntents(ctx, trustIntentFamily)
	if err != nil {
		log.Error("the beginnings of the trust changes could not be read", "err", err)
		return
	}
	for _, intent := range intents {
		outcome, found := s.trustState(intent)
		detail := map[string]any{
			audit.IntentKey: intent.Key, "reconciled": true,
			"began_at": intent.OccurredAt, "began_by": intent.ActorID,
			"found": found,
		}
		err := s.audit.RecordOutcome(ctx, audit.Event{
			ActorType: audit.ActorSystem, ActorID: "reconciler",
			Action: intent.Action, TargetType: "pki", TargetID: intent.TargetID,
			Outcome: outcome, Detail: detail,
		})
		if errors.Is(err, audit.ErrOutcomeRecorded) {
			// Another replica reconciled first. One answer per beginning is the
			// point, so this one is dropped rather than written beside it.
			continue
		}
		if err != nil {
			log.Error("a trust change that began could not be closed on the trail",
				"action", intent.Action, "began_at", intent.OccurredAt, "err", err)
			continue
		}
		log.Warn("a trust change that began without an outcome was closed by reading the state",
			"action", intent.Action, "began_at", intent.OccurredAt,
			"began_by", intent.ActorID, "found", found, "outcome", string(outcome))
	}
}

// trustState reads the trust store and says what it shows about the authority an
// intent names.
func (s *Server) trustState(intent audit.Intent) (audit.Outcome, string) {
	active, pending, known := "", "", false
	if ca := s.trust.Active(); ca != nil {
		active = ca.FingerprintHex()
	}
	if ca, _ := s.trust.Pending(); ca != nil {
		pending = ca.FingerprintHex()
	}
	for _, authority := range s.trust.Authorities() {
		if authority.Fingerprint == intent.TargetID {
			known = true
			break
		}
	}
	return trustOutcome(intent.Action, intent.TargetID, active, pending, known)
}

// trustOutcome maps what the trust store shows to what the trail should say. A
// state reads as a success only when it is the state the change was meant to
// reach; anything else, including an action this panel does not reconcile, is
// written down as a failure rather than assumed.
func trustOutcome(action, target, active, pending string, known bool) (audit.Outcome, string) {
	switch action {
	case "pki.ca.prepare":
		// A prepared CA stands beside the active one and signs nothing yet.
		if pending != "" {
			return audit.OutcomeSuccess, "a CA is prepared: " + pending
		}
		return audit.OutcomeFailure, "no CA is prepared"
	case "pki.ca.activate":
		switch {
		case active != "" && active == target:
			return audit.OutcomeSuccess, "the CA it names signs: " + target
		case active != "":
			return audit.OutcomeFailure, "another CA signs: " + active
		}
		return audit.OutcomeFailure, "no CA signs"
	case "pki.ca.retire":
		if known {
			return audit.OutcomeFailure, "the CA is still in the trust set"
		}
		return audit.OutcomeSuccess, "the CA is no longer in the trust set"
	}
	return audit.OutcomeFailure, "the action is not one this panel reconciles"
}
