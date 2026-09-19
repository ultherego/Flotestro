package identity

import (
	"context"
	"log/slog"
	"slices"
	"time"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/oidc"
)

// A session carries the groups of the moment of login and the roles are
// recomputed from them on every request.

// GroupRefresher is the provider side of the check.
type GroupRefresher interface {
	Refresh(ctx context.Context, refreshToken string) (*oidc.TokenSet, *oidc.Claims, error)
}

// SessionGroupStore is the part of the session store the refresher uses.
type SessionGroupStore interface {
	StaleGroupSnapshots(ctx context.Context, before time.Time, limit int) ([]authz.RefreshableSession, error)
	RecordGroupRefresh(ctx context.Context, sessionID string, groups []string, tokens authz.SessionTokens) error
	RevokeSession(ctx context.Context, sessionID, reason string) error
}

// auditor is the part of the audit recorder the refresher writes through.
type auditor interface {
	Record(ctx context.Context, event audit.Event)
}

// RefreshOutcome is what one check of a session came to.
type RefreshOutcome string

const (
	// RefreshUnchanged means the provider confirmed the snapshot.
	RefreshUnchanged RefreshOutcome = "unchanged"
	// RefreshChanged means the session now carries a different group set.
	RefreshChanged RefreshOutcome = "changed"
	// RefreshRevoked means the provider no longer honours the refresh token
	// and the session was ended.
	RefreshRevoked RefreshOutcome = "revoked"
	// RefreshDeferred means a failure that says nothing about the user; the
	// session keeps its snapshot and is checked again at the next tick.
	RefreshDeferred RefreshOutcome = "deferred"
)

// revokedGroupsReason is written on a session the provider gave up on. It
// reads next to the reasons the executor writes when locking an account.
const revokedGroupsReason = "the identity provider no longer honours the session"

// sessionsPerTick bounds one pass of the loop.
const sessionsPerTick = 200

// SessionGroupRefresher renews the group snapshot of live sessions.
type SessionGroupRefresher struct {
	sessions SessionGroupStore
	provider GroupRefresher
	audit    auditor
	log      *slog.Logger
	interval time.Duration
}

// NewSessionGroupRefresher builds the loop.
func NewSessionGroupRefresher(sessions SessionGroupStore, provider GroupRefresher,
	recorder auditor, log *slog.Logger, interval time.Duration) *SessionGroupRefresher {
	return &SessionGroupRefresher{sessions: sessions, provider: provider,
		audit: recorder, log: log, interval: interval}
}

// Run checks the due sessions every interval until the context is closed.
func (r *SessionGroupRefresher) Run(ctx context.Context) {
	if r.interval <= 0 || r.provider == nil {
		return
	}
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.tick(ctx)
		}
	}
}

// tick refreshes the sessions whose snapshot is older than the interval.
func (r *SessionGroupRefresher) tick(ctx context.Context) {
	due, err := r.sessions.StaleGroupSnapshots(ctx, time.Now().Add(-r.interval), sessionsPerTick)
	if err != nil {
		r.log.Error("the sessions due for a group refresh were not read", "err", err)
		return
	}
	for _, session := range due {
		if ctx.Err() != nil {
			return
		}
		r.refreshOne(ctx, session)
	}
}

// refreshOne asks the provider about one session and applies the answer.
func (r *SessionGroupRefresher) refreshOne(ctx context.Context, session authz.RefreshableSession) RefreshOutcome {
	tokens, claims, err := r.provider.Refresh(ctx, session.RefreshToken)
	if err != nil {
		if !oidc.IsInvalidGrant(err) {
			// The provider may be down or slow; the user has done nothing to
			// lose the session over it. The next tick asks again.
			r.log.Warn("the group snapshot of a session was not refreshed",
				"session_id", session.ID, "subject", session.Subject, "err", err)
			return RefreshDeferred
		}
		if err := r.sessions.RevokeSession(ctx, session.ID, revokedGroupsReason); err != nil {
			r.log.Error("the session refused by the provider was not revoked",
				"session_id", session.ID, "subject", session.Subject, "err", err)
			return RefreshDeferred
		}
		r.audit.Record(ctx, audit.Event{
			ActorType: audit.ActorSystem, ActorID: "session-group-refresh",
			Action: "auth.session_revoked", TargetType: "principal", TargetID: session.PrincipalID,
			Outcome: audit.OutcomeSuccess,
			Detail: map[string]any{
				"session_id": session.ID, "subject": session.Subject,
				"reason": "invalid_grant", "error": err.Error(),
			},
		})
		r.log.Info("a session ended because the provider refused its refresh token",
			"session_id", session.ID, "subject", session.Subject)
		return RefreshRevoked
	}

	// A renewal without an identity token carries no groups.
	groups := session.Groups
	outcome := RefreshUnchanged
	if claims != nil && !sameGroupSet(session.Groups, claims.Groups) {
		groups = claims.Groups
		outcome = RefreshChanged
	}
	if err := r.sessions.RecordGroupRefresh(ctx, session.ID, orEmpty(groups), authz.SessionTokens{
		RefreshToken:    tokens.RefreshToken,
		IDToken:         tokens.IDToken,
		AccessExpiresAt: tokens.ExpiresAt,
	}); err != nil {
		r.log.Error("the refreshed group snapshot was not recorded",
			"session_id", session.ID, "subject", session.Subject, "err", err)
		return RefreshDeferred
	}
	if outcome == RefreshChanged {
		added, removed := groupDiff(session.Groups, claims.Groups)
		r.audit.Record(ctx, audit.Event{
			ActorType: audit.ActorSystem, ActorID: "session-group-refresh",
			Action: "auth.groups_changed", TargetType: "principal", TargetID: session.PrincipalID,
			Outcome: audit.OutcomeSuccess,
			Detail: map[string]any{
				"session_id": session.ID, "subject": session.Subject,
				"added": added, "removed": removed,
			},
			Before: map[string]any{"groups": orEmpty(session.Groups)},
			After:  map[string]any{"groups": orEmpty(claims.Groups)},
		})
		r.log.Info("the groups of a session changed at the provider",
			"session_id", session.ID, "subject", session.Subject,
			"added", len(added), "removed", len(removed))
	}
	return outcome
}

// sameGroupSet compares two group lists as sets.
func sameGroupSet(current, fresh []string) bool {
	a := slices.Clone(current)
	b := slices.Clone(fresh)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(slices.Compact(a), slices.Compact(b))
}

// groupDiff names what came and what went, for the trail.
func groupDiff(current, fresh []string) (added, removed []string) {
	added, removed = []string{}, []string{}
	for _, group := range fresh {
		if !slices.Contains(current, group) && !slices.Contains(added, group) {
			added = append(added, group)
		}
	}
	for _, group := range current {
		if !slices.Contains(fresh, group) && !slices.Contains(removed, group) {
			removed = append(removed, group)
		}
	}
	slices.Sort(added)
	slices.Sort(removed)
	return added, removed
}

// orEmpty keeps "no groups" from rendering as null in the trail.
func orEmpty(groups []string) []string {
	if groups == nil {
		return []string{}
	}
	return groups
}
