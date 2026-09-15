package adminapi

import (
	"context"

	"github.com/ultherego/flotestro/internal/authz"
)

// PendingDecisions is the part of the fleet summary that counts what waits
// for a person: an order nobody has approved, a campaign standing at a gate,
// a directory change with a plan and no signature, a host the declared
// state disagrees with. The dashboard's "waiting for approval" tile and the
// sidebar's badges read these, so an operator sees the queue of decisions
// without opening each list in turn.
//
// Every counter is missing, not zero, for a reader without the right to
// see the list it counts: a badge of zero on a list they may not open would
// say "nothing waits" about a queue they cannot check.
type PendingDecisions struct {
	// JobsAwaitingApproval counts the jobs on the visible hosts that wait
	// for an operator's approval.
	JobsAwaitingApproval *int `json:"jobs_awaiting_approval,omitempty"`
	// CampaignsAwaitingApproval counts the campaigns with a visible target
	// that wait for their approval, and CampaignsManualGate those that
	// have stopped at a manual gate between waves.
	CampaignsAwaitingApproval *int `json:"campaigns_awaiting_approval,omitempty"`
	CampaignsManualGate       *int `json:"campaigns_manual_gate,omitempty"`
	// DirectoryChangesPending counts the directory changes that wait for
	// approval. The directory has no site or environment, so the counter
	// exists only for a reader with the fleet-wide identity right.
	DirectoryChangesPending *int `json:"directory_changes_pending,omitempty"`
	// HostsDrifted counts the visible hosts on which at least one rule of
	// a published policy found drift at its last evaluation.
	HostsDrifted *int `json:"hosts_drifted,omitempty"`
}

// countPendingDecisions fills the decision counters of the summary, each
// with one aggregated query over the rows the principal may see - the
// narrowing is the same one the lists apply, so a badge never counts a row
// the list behind it would not show.
func (s *Server) countPendingDecisions(ctx context.Context, principal authz.Principal, decisions *PendingDecisions) error {
	// The visibility of a row that belongs to a host - a job, a policy
	// verdict - is the visibility of the host, under the permission that
	// reads the row.
	hostCondition := func(permission authz.Permission) (string, []any, bool) {
		scopes := principal.ScopesFor(permission)
		if len(scopes) == 0 {
			return "", nil, false
		}
		condition, args := authz.ScopeSQL(scopes, "h.site", "h.environment", 0)
		if condition == "" {
			condition = "true"
		}
		return condition, args, true
	}

	if visible, args, ok := hostCondition(authz.PermJobRead); ok {
		var waiting int
		err := s.pool.QueryRow(ctx, `
			select count(*) from jobs j
			where j.state = 'awaiting_approval'
			  and exists (select 1 from hosts h where h.id = j.host_id and `+visible+`)`,
			args...).Scan(&waiting)
		if err != nil {
			return err
		}
		decisions.JobsAwaitingApproval = &waiting
	}

	// A campaign is visible when one of its targets is, the way the
	// campaign list decides it.
	if visible, args, ok := hostCondition(authz.PermCampaignRead); ok {
		var approval, gate int
		err := s.pool.QueryRow(ctx, `
			select count(*) filter (where c.state = 'awaiting_approval'),
			       count(*) filter (where c.state = 'manual_gate')
			from campaigns c
			where c.state in ('awaiting_approval', 'manual_gate')
			  and exists (select 1 from campaign_targets t join hosts h on h.id = t.host_id
			              where t.campaign_id = c.id and `+visible+`)`,
			args...).Scan(&approval, &gate)
		if err != nil {
			return err
		}
		decisions.CampaignsAwaitingApproval = &approval
		decisions.CampaignsManualGate = &gate
	}

	if s.changes != nil && principal.Can(authz.PermIdentityRead, authz.GlobalScope) {
		var pending int
		err := s.pool.QueryRow(ctx,
			`select count(*) from directory_changes where state = 'awaiting_approval'`).Scan(&pending)
		if err != nil {
			return err
		}
		decisions.DirectoryChangesPending = &pending
	}

	// A host is drifted once, however many rules disagree with it: the
	// badge counts hosts to fix, not findings to read.
	if visible, args, ok := hostCondition(authz.PermPolicyRead); ok {
		var drifted int
		err := s.pool.QueryRow(ctx, `
			select count(distinct r.host_id)
			from policy_results r join hosts h on h.id = r.host_id
			where r.verdict = 'drift' and h.lifecycle_state <> 'retired'
			  and `+visible, args...).Scan(&drifted)
		if err != nil {
			return err
		}
		decisions.HostsDrifted = &drifted
	}
	return nil
}
