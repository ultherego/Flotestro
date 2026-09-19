package campaigns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// BuildReport summarises the targets of a campaign: the state totals, the
// split into waves and the lists of hosts that need attention.
func BuildReport(campaign Campaign, targets []Target) Report {
	report := Report{
		CampaignID: campaign.ID,
		State:      campaign.State,
		Totals:     map[string]int{},
		Waves:      []WaveSummary{},
		Failures:   []Target{},
	}
	waveTotals := map[int]map[string]int{}
	waveOpen := map[int]bool{}
	for _, target := range targets {
		report.Totals[string(target.State)]++
		if waveTotals[target.Wave] == nil {
			waveTotals[target.Wave] = map[string]int{}
		}
		waveTotals[target.Wave][string(target.State)]++
		if !target.State.Finished() {
			waveOpen[target.Wave] = true
		}
		// The failures are the hosts the operator has to look at.
		if target.State == TargetFailed || target.State == TargetUnknown {
			report.Failures = append(report.Failures, target)
		}
		// A host verifying its units without a reboot behind it is not waiting for
		// one; only a reboot that was ordered keeps the host on this list until the
		// verification settles it.
		if target.State == TargetRebooting || (target.State == TargetVerifying && target.RebootJobID != nil) {
			report.RebootPending = append(report.RebootPending, target.HostID)
		}
		// A host that came back with a different plan ran nothing, and the report
		// says so by name: the consent covered the old plan, and a campaign that
		// quietly counted it among the skipped would hide the one host the operator
		if target.State == TargetSkipped && target.ErrorCode == "plan_changed_offline" {
			report.PlanChanged = append(report.PlanChanged, target)
		}
		if target.State == TargetQueuedOffline {
			report.OfflineQueued = append(report.OfflineQueued, target.HostID)
		}
	}
	for wave := 0; wave < len(waveTotals); wave++ {
		totals, exists := waveTotals[wave]
		if !exists {
			continue
		}
		report.Waves = append(report.Waves, WaveSummary{
			Wave:      wave,
			IsCanary:  wave == 0,
			Totals:    totals,
			Completed: !waveOpen[wave],
		})
	}
	return report
}

// ReportView is the report as the API serves it: the summary together with
// where it came from.
type ReportView struct {
	Report
	Stored      bool       `json:"stored"`
	GeneratedAt *time.Time `json:"generated_at,omitempty"`
	// The consent the report belongs to: the approver, the fingerprint and
	// the plan set digest as they stood when the campaign ended.
	ApprovalFingerprint string `json:"approval_fingerprint,omitempty"`
	PlanSetHash         string `json:"plan_set_hash,omitempty"`
	ApprovedBy          string `json:"approved_by,omitempty"`
	CreatedBy           string `json:"created_by"`
}

// LiveReport computes the report of a campaign from its targets now.
func (s *Store) LiveReport(ctx context.Context, campaign Campaign) (ReportView, error) {
	targets, err := s.Targets(ctx, campaign.ID)
	if err != nil {
		return ReportView{}, err
	}
	return ReportView{
		Report:              BuildReport(campaign, targets),
		ApprovalFingerprint: campaign.ApprovalFingerprint,
		PlanSetHash:         campaign.PlanSetHash,
		ApprovedBy:          campaign.ApprovedBy,
		CreatedBy:           campaign.CreatedBy,
	}, nil
}

// ErrNoReport means the campaign has no stored report: it has not ended,
// or it ended before the panel kept reports.
var ErrNoReport = errors.New("the campaign has no stored report")

// StoredReport reads the report written when the campaign ended.
func (s *Store) StoredReport(ctx context.Context, campaignID string) (ReportView, error) {
	const query = `
		select campaign_id, state, totals, waves, failures, plan_changed, generated_at,
		       approval_fingerprint, plan_set_hash, approved_by, created_by
		from campaign_reports where campaign_id = $1`
	var view ReportView
	var generatedAt time.Time
	var totals, waves, failures, planChanged []byte
	err := s.pool.QueryRow(ctx, query, campaignID).Scan(&view.CampaignID, &view.State,
		&totals, &waves, &failures, &planChanged, &generatedAt,
		&view.ApprovalFingerprint, &view.PlanSetHash, &view.ApprovedBy, &view.CreatedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return ReportView{}, ErrNoReport
	}
	if err != nil {
		return ReportView{}, err
	}
	view.Totals = map[string]int{}
	view.Waves = []WaveSummary{}
	view.Failures = []Target{}
	read := func(name string, raw []byte, into any) error {
		if err := json.Unmarshal(raw, into); err != nil {
			return fmt.Errorf("the stored report of %s has an unreadable %s: %w", campaignID, name, err)
		}
		return nil
	}
	if err := errors.Join(
		read("totals", totals, &view.Totals),
		read("waves", waves, &view.Waves),
		read("failures", failures, &view.Failures),
		read("plan_changed", planChanged, &view.PlanChanged),
	); err != nil {
		return ReportView{}, err
	}
	view.Stored = true
	view.GeneratedAt = &generatedAt
	return view, nil
}

// recordReport writes the final report of a campaign that just reached a
// terminal state, inside the transaction of the transition: there is no
// finished campaign without its report and no report of a campaign that did
func (s *Store) recordReport(ctx context.Context, tx pgx.Tx, campaignID string) error {
	campaign, err := s.getTx(ctx, tx, campaignID)
	if err != nil {
		return err
	}
	if !campaign.State.Terminal() {
		return fmt.Errorf("the campaign %s is %s, not finished", campaignID, campaign.State)
	}
	targets, err := s.targetsTx(ctx, tx, campaignID)
	if err != nil {
		return err
	}
	report := BuildReport(*campaign, targets)
	if report.PlanChanged == nil {
		report.PlanChanged = []Target{}
	}
	// The lists go in as JSON documents: the report is read back as a whole,
	// never queried by host, and a column per list would have to grow with every
	// kind of attention the report learns to draw.
	encoded := map[string][]byte{}
	for name, value := range map[string]any{
		"totals": report.Totals, "waves": report.Waves,
		"failures": report.Failures, "plan_changed": report.PlanChanged,
	} {
		document, err := json.Marshal(value)
		if err != nil {
			return fmt.Errorf("serialising the %s of the report: %w", name, err)
		}
		encoded[name] = document
	}
	const query = `
		insert into campaign_reports
		    (campaign_id, state, totals, waves, failures, plan_changed,
		     approval_fingerprint, plan_set_hash, approved_by, created_by)
		values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		on conflict (campaign_id) do nothing`
	if _, err := tx.Exec(ctx, query, campaignID, string(campaign.State),
		encoded["totals"], encoded["waves"], encoded["failures"], encoded["plan_changed"],
		campaign.ApprovalFingerprint, campaign.PlanSetHash, campaign.ApprovedBy,
		campaign.CreatedBy); err != nil {
		return fmt.Errorf("record the report: %w", err)
	}
	return nil
}

// targetsTx reads the whole target list inside a transaction, in the order of
// the rollout.
func (s *Store) targetsTx(ctx context.Context, tx pgx.Tx, campaignID string) ([]Target, error) {
	const query = `
		select t.id, t.campaign_id, t.host_id, coalesce(h.hostname, ''), t.wave, t.position,
		       t.state, t.job_id, t.plan_job_id, t.reboot_job_id, t.health_job_id,
		       coalesce(t.boot_id_before, ''),
		       coalesce(t.error_code, ''), coalesce(t.message, ''), t.started_at, t.finished_at
		from campaign_targets t
		left join hosts h on h.id = t.host_id
		where t.campaign_id = $1
		order by t.wave, t.position`
	rows, err := tx.Query(ctx, query, campaignID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	targets := []Target{}
	for rows.Next() {
		var t Target
		if err := rows.Scan(&t.ID, &t.CampaignID, &t.HostID, &t.Hostname, &t.Wave, &t.Position,
			&t.State, &t.JobID, &t.PlanJobID, &t.RebootJobID, &t.HealthJobID, &t.BootIDBefore,
			&t.ErrorCode, &t.Message, &t.StartedAt, &t.FinishedAt); err != nil {
			return nil, err
		}
		targets = append(targets, t)
	}
	return targets, rows.Err()
}
