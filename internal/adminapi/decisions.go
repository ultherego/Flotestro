package adminapi

import (
	"context"

	"github.com/ultherego/flotestro/internal/authz"
)

// PendingDecisions is the part of the fleet summary that counts what waits for
// a person: an unapproved order, a campaign at a gate, a drifted host.
type PendingDecisions struct {
	// JobsAwaitingApproval counts the jobs on the visible hosts that wait
	// for an operator's approval.
	JobsAwaitingApproval *int `json:"jobs_awaiting_approval,omitempty"`
	// CampaignsAwaitingApproval counts the campaigns that wait for their
	// approval, and CampaignsManualGate those that have stopped at a manual gate
	// between waves. A campaign is narrowed by its targets only when the
	// principal's scopes narrow anything: one awaiting its approval has no
	// target yet, and a badge that leaves those out hides the decisions nobody
	// has made.
	CampaignsAwaitingApproval *int `json:"campaigns_awaiting_approval,omitempty"`
	CampaignsManualGate       *int `json:"campaigns_manual_gate,omitempty"`
	// DirectoryChangesPending counts the directory changes that wait for
	// approval.
	DirectoryChangesPending *int `json:"directory_changes_pending,omitempty"`
	// HostsDrifted counts the visible hosts on which at least one rule of
	// a published policy found drift at its last evaluation.
	HostsDrifted *int `json:"hosts_drifted,omitempty"`
}

// countPendingDecisions fills the decision counters with one aggregated query
// each, narrowed as the lists are, so a badge never counts a hidden row.
func (s *Server) countPendingDecisions(ctx context.Context, principal authz.Principal, decisions *PendingDecisions) error {
	// The visibility of a row that belongs to a host - a job, a policy verdict -
	// is the visibility of the host, under the permission that reads the row.
	// An empty condition is not "true": it is "no restriction", and the lists
	// add no clause at all for it. The counter used to turn it into
	//
	//     exists (select 1 from campaign_targets t join hosts h ... and true)
	//
	// which is a restriction of its own - a campaign with no target row yet is
	// not counted. A campaign waits for its approval before it is planned, so
	// those are exactly the decisions a person has not made. Measured on the
	// laboratory: 30 campaigns awaiting approval, 28 of them without a target,
	// and the badge said 2. The operator would have had 28 decisions the panel
	// did not mention, and the comment here claimed the badge counted "the way
	// the campaign list decides it".
	//
	// So the clause is returned separately from the permission, and a principal
	// nothing narrows gets no clause - the rule the job list and the campaign
	// list already follow.
	hostCondition := func(permission authz.Permission) (string, []any, bool) {
		scopes := principal.ScopesFor(permission)
		if len(scopes) == 0 {
			return "", nil, false
		}
		condition, args := authz.ScopeSQL(scopes, authz.HostColumns("h"), 0)
		return condition, args, true
	}

	if visible, args, ok := hostCondition(authz.PermJobRead); ok {
		var waiting int
		err := s.pool.QueryRow(ctx, `
			select count(*) from jobs j
			where j.state = 'awaiting_approval'`+
			narrowByHost(visible, "select 1 from hosts h where h.id = j.host_id"),
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
			where c.state in ('awaiting_approval', 'manual_gate')`+
			narrowByHost(visible, "select 1 from campaign_targets t join hosts h on h.id = t.host_id"+
				" where t.campaign_id = c.id"),
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
		// The drift count joins the host itself, so there is no existence test
		// to wrap: an unrestricted principal simply gets no further condition.
		condition := ""
		if visible != "" {
			condition = " and " + visible
		}
		err := s.pool.QueryRow(ctx, `
			select count(distinct r.host_id)
			from policy_results r join hosts h on h.id = r.host_id
			where r.verdict = 'drift' and h.lifecycle_state <> 'retired'`+condition,
			args...).Scan(&drifted)
		if err != nil {
			return err
		}
		decisions.HostsDrifted = &drifted
	}
	return nil
}

// narrowByHost wraps a visibility clause in the existence test the row needs,
// and answers the empty string when there is nothing to narrow. A badge must
// count what the list it leads to shows, and the lists add no clause for a
// principal nothing narrows - so neither does this.
func narrowByHost(condition, test string) string {
	if condition == "" {
		return ""
	}
	return " and exists (" + test + " and " + condition + ")"
}
