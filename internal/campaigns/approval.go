package campaigns

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ApprovedPlan is the plan of one host as it was when the consent was
// given: the digest of its envelope, the planner that computed it, who
// consented and against which revision of the campaign, and the body.
type ApprovedPlan struct {
	ApprovalID     string          `json:"approval_id"`
	HostID         string          `json:"host_id"`
	PlanHash       string          `json:"plan_hash"`
	PlannerVersion string          `json:"planner_version,omitempty"`
	Principal      string          `json:"principal"`
	PolicyRevision int64           `json:"policy_revision"`
	Plan           json.RawMessage `json:"plan,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
}

// ApproveWithPlans approves a campaign and records, with the approval,
// the plan of every host as it stands now: the consent has to keep what
// it covered, because campaign_plans is overwritten by the next planning
// and the fingerprint alone does not say what the approver read. The
// policy revision is the revision of the campaign record the consent was
// given against - its rollout policy included - as read before the
// approval raised it. Everything is written in the caller's transaction:
// there is no approval without its plans and no plans without the
// approval.
func (s *Store) ApproveWithPlans(ctx context.Context, tx pgx.Tx, campaign Campaign,
	approval Approval) (*Campaign, error) {
	approved, err := s.Approve(ctx, tx, campaign.ID, approval)
	if err != nil {
		return nil, err
	}
	// The record Approve wrote is the newest of this campaign in the
	// transaction; its identifier is what the plans are attached to.
	var approvalID string
	if err := tx.QueryRow(ctx, `
		select id from campaign_approvals
		 where campaign_id = $1
		 order by created_at desc, id desc
		 limit 1`, campaign.ID).Scan(&approvalID); err != nil {
		return nil, fmt.Errorf("find the approval record: %w", err)
	}
	const record = `
		insert into campaign_approval_plans
		    (approval_id, campaign_id, host_id, plan_hash, planner_version, principal, policy_revision, plan)
		select $2, p.campaign_id, p.host_id, p.plan_hash,
		       coalesce(p.plan->>'planner_version', ''), $3, $4, p.plan
		  from campaign_plans p
		 where p.campaign_id = $1`
	if _, err := tx.Exec(ctx, record, campaign.ID, approvalID, approval.ApprovedBy, campaign.Revision); err != nil {
		return nil, fmt.Errorf("record the approved plans: %w", err)
	}
	return approved, nil
}

// ApprovedPlans lists the plans an approval covered, by host.
func (s *Store) ApprovedPlans(ctx context.Context, campaignID string) ([]ApprovedPlan, error) {
	const query = `
		select approval_id, host_id, plan_hash, planner_version, principal, policy_revision, plan, created_at
		  from campaign_approval_plans
		 where campaign_id = $1
		 order by created_at, host_id`
	rows, err := s.pool.Query(ctx, query, campaignID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	plans := []ApprovedPlan{}
	for rows.Next() {
		var entry ApprovedPlan
		if err := rows.Scan(&entry.ApprovalID, &entry.HostID, &entry.PlanHash, &entry.PlannerVersion,
			&entry.Principal, &entry.PolicyRevision, &entry.Plan, &entry.CreatedAt); err != nil {
			return nil, err
		}
		plans = append(plans, entry)
	}
	return plans, rows.Err()
}
