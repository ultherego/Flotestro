package reports

import (
	"context"
	"fmt"
	"time"
)

// The campaign report: every campaign that closed in the period, with how
// it ended and what became of its hosts.
//
// A campaign is in the report when its finished_at falls in the period,
// whatever its terminal state - a canceled campaign is a decision of the
// period and belongs in its report as much as a completed one. A campaign
// with no host in the reader's scope is not in it, like on the list.

// OutcomeCounts tallies the targets of one or more campaigns by how they
// ended. The tally is in the terms of the campaign report: succeeded takes
// in the hosts that changed nothing because they already stood in the
// desired state, and skipped takes in the hosts left out on purpose - by
// a policy, a window, the operator or a missing adapter.
type OutcomeCounts struct {
	Targets   int `json:"targets"`
	Succeeded int `json:"succeeded"`
	// NoChange is the part of Succeeded that changed nothing.
	NoChange int `json:"no_change"`
	Failed   int `json:"failed"`
	// Unknown counts the hosts whose task ended without a result. Not a
	// success and not a failure of the change: a question to read off the
	// host.
	Unknown  int `json:"unknown"`
	Skipped  int `json:"skipped"`
	Canceled int `json:"canceled"`
}

// Rate is the success rate: the share of the attempted hosts that
// succeeded, that is the successes over the successes, failures and
// unknowns. A host skipped or canceled was not attempted and counts in
// neither side. Nil when nothing was attempted - a rate over nothing is
// not a hundred per cent.
func (c OutcomeCounts) Rate() *float64 {
	attempted := c.Succeeded + c.Failed + c.Unknown
	if attempted == 0 {
		return nil
	}
	rate := float64(c.Succeeded) / float64(attempted)
	return &rate
}

// outcomeSQL tallies the targets of the rows in scope of the query it is
// pasted into; the alias t is the campaign_targets row.
const outcomeSQL = `
	count(t.id),
	count(t.id) filter (where t.state in ('succeeded', 'no_change')),
	count(t.id) filter (where t.state = 'no_change'),
	count(t.id) filter (where t.state = 'failed'),
	count(t.id) filter (where t.state = 'unknown'),
	count(t.id) filter (where t.state in ('skipped', 'ineligible', 'excluded')),
	count(t.id) filter (where t.state = 'canceled')`

// fields are the destinations of the columns of outcomeSQL, in order.
func (c *OutcomeCounts) fields() []any {
	return []any{&c.Targets, &c.Succeeded, &c.NoChange, &c.Failed, &c.Unknown, &c.Skipped, &c.Canceled}
}

// CampaignGroup is the outcome over the targets of one site.
type CampaignGroup struct {
	Key string `json:"key"`
	OutcomeCounts
}

// CampaignRow is one campaign of the report.
type CampaignRow struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Operation string `json:"operation"`
	State     string `json:"state"`
	// Requester ordered the campaign; Approver approved it, empty for a
	// campaign that ended before anyone did.
	Requester  string     `json:"requester"`
	Approver   string     `json:"approver,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt time.Time  `json:"finished_at"`
	// DurationSeconds is how long the campaign ran, from its start to its
	// end; nil for a campaign that never started.
	DurationSeconds *int `json:"duration_seconds"`
	OutcomeCounts
	SuccessRate *float64        `json:"success_rate"`
	BySite      []CampaignGroup `json:"by_site"`
}

// CampaignsReport is the campaign report of a period.
type CampaignsReport struct {
	Campaigns []CampaignRow `json:"campaigns"`
	Totals    struct {
		Campaigns int            `json:"campaigns"`
		ByState   map[string]int `json:"by_state"`
		OutcomeCounts
		SuccessRate *float64 `json:"success_rate"`
	} `json:"totals"`
	BySite []CampaignGroup `json:"by_site"`
}

// campaignRowLimit bounds the report: a period with more closed
// campaigns than this is a period to narrow. The campaigns are ordered
// by people, a few a day, so a month stays far under it.
const campaignRowLimit = 5000

// Campaigns computes the campaign report of the period: the campaigns
// that closed in it and touch a host the reader may see under the filter,
// newest first, each with its per-site split, and the totals over them.
func (s *Store) Campaigns(ctx context.Context, period Period, filter Filter) (*CampaignsReport, error) {
	report := &CampaignsReport{Campaigns: []CampaignRow{}, BySite: []CampaignGroup{}}
	report.Totals.ByState = map[string]int{}

	clause, args := hostClause(filter, 2)
	args = append([]any{period.From, period.To}, args...)
	args = append(args, campaignRowLimit)
	// The campaigns of the period, with the tally over all of their
	// targets: the outcome of a campaign is the outcome of the whole
	// campaign, as its own report states it, and the scope decides only
	// whether the reader sees the campaign at all.
	rows, err := s.pool.Query(ctx, fmt.Sprintf(`
		select c.id::text, c.name, c.action_type, c.state, c.created_by, coalesce(c.approved_by, ''),
		       c.created_at, c.started_at, c.finished_at, `+outcomeSQL+`
		  from campaigns c
		  left join campaign_targets t on t.campaign_id = c.id
		 where c.finished_at >= $1 and c.finished_at < $2
		   and exists (select 1 from campaign_targets v join hosts h on h.id = v.host_id
		                where v.campaign_id = c.id and %s)
		 group by c.id
		 order by c.finished_at desc, c.id
		 limit $%d`, clause, len(args)), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	index := map[string]int{}
	for rows.Next() {
		var row CampaignRow
		fields := append([]any{&row.ID, &row.Name, &row.Operation, &row.State, &row.Requester, &row.Approver,
			&row.CreatedAt, &row.StartedAt, &row.FinishedAt}, row.OutcomeCounts.fields()...)
		if err := rows.Scan(fields...); err != nil {
			return nil, err
		}
		if row.StartedAt != nil {
			seconds := int(row.FinishedAt.Sub(*row.StartedAt) / time.Second)
			row.DurationSeconds = &seconds
		}
		row.SuccessRate = row.Rate()
		row.BySite = []CampaignGroup{}
		index[row.ID] = len(report.Campaigns)
		report.Campaigns = append(report.Campaigns, row)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(report.Campaigns) == 0 {
		return report, nil
	}

	// The split by site of every campaign of the report, in one read; the
	// fleet-wide split is the same rows summed.
	ids := make([]string, 0, len(report.Campaigns))
	for _, row := range report.Campaigns {
		ids = append(ids, row.ID)
	}
	split, err := s.pool.Query(ctx, `
		select t.campaign_id::text, h.site, `+outcomeSQL+`
		  from campaign_targets t join hosts h on h.id = t.host_id
		 where t.campaign_id = any($1::uuid[])
		 group by t.campaign_id, h.site
		 order by t.campaign_id, h.site`, ids)
	if err != nil {
		return nil, err
	}
	defer split.Close()
	bySite := map[string]*CampaignGroup{}
	for split.Next() {
		var campaignID string
		var group CampaignGroup
		if err := split.Scan(append([]any{&campaignID, &group.Key}, group.OutcomeCounts.fields()...)...); err != nil {
			return nil, err
		}
		if i, ok := index[campaignID]; ok {
			report.Campaigns[i].BySite = append(report.Campaigns[i].BySite, group)
		}
		total, ok := bySite[group.Key]
		if !ok {
			total = &CampaignGroup{Key: group.Key}
			bySite[group.Key] = total
		}
		total.OutcomeCounts.add(group.OutcomeCounts)
	}
	if err := split.Err(); err != nil {
		return nil, err
	}
	for _, row := range report.Campaigns {
		report.Totals.Campaigns++
		report.Totals.ByState[row.State]++
		report.Totals.OutcomeCounts.add(row.OutcomeCounts)
	}
	report.Totals.SuccessRate = report.Totals.OutcomeCounts.Rate()
	for _, key := range sortedKeys(bySite) {
		report.BySite = append(report.BySite, *bySite[key])
	}
	return report, nil
}

// add sums another tally into this one.
func (c *OutcomeCounts) add(other OutcomeCounts) {
	c.Targets += other.Targets
	c.Succeeded += other.Succeeded
	c.NoChange += other.NoChange
	c.Failed += other.Failed
	c.Unknown += other.Unknown
	c.Skipped += other.Skipped
	c.Canceled += other.Canceled
}
