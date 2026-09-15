package reports

import (
	"context"
	"fmt"
	"time"
)

// The patch status report: where the fleet stands with its updates at the
// moment of reading, and what was done about them in the period.
//
// The standing facts - pending updates, the reboot flag, the agent version
// - are the host's latest report, not a value at the end of the period:
// the panel keeps the current facts, and a report on an old period says
// what the fleet looks like now and what happened then. The period
// applies to the work: the last successful upgrade of each host and the
// campaigns that ran on it.

// PatchHost is one host of the patch status report.
type PatchHost struct {
	HostID          string     `json:"host_id"`
	Hostname        string     `json:"hostname"`
	Site            string     `json:"site"`
	Environment     string     `json:"environment"`
	LifecycleState  string     `json:"lifecycle_state"`
	ConnectionState string     `json:"connection_state"`
	AgentVersion    string     `json:"agent_version,omitempty"`
	LastSeenAt      *time.Time `json:"last_seen_at,omitempty"`
	// The standing facts; nil when the host has not reported them.
	PendingUpdates         *int  `json:"pending_updates"`
	PendingSecurityUpdates *int  `json:"pending_security_updates"`
	RebootRequired         *bool `json:"reboot_required"`
	// LastUpgradeAt is when the host's last successful packages.upgrade
	// task of the period finished; nil when none did.
	LastUpgradeAt *time.Time `json:"last_upgrade_at,omitempty"`
	// Campaigns counts the campaigns that started work on the host in the
	// period. Nil when the reader may not read campaigns: the column is
	// left out rather than shown as zero.
	Campaigns *int `json:"campaigns,omitempty"`
}

// PatchCounts are the totals of the patch status over a set of hosts.
// Every fact has its unknown count next to it: a host that never said
// whether it needs a reboot is in neither the backlog nor the clear.
type PatchCounts struct {
	Hosts int `json:"hosts"`
	// FullyPatched counts the hosts that reported zero pending security
	// updates; SecurityUnknown the hosts that reported nothing.
	FullyPatched    int `json:"fully_patched"`
	SecurityUnknown int `json:"security_unknown"`
	// PatchedInPeriod counts the hosts with a successful upgrade task in
	// the period.
	PatchedInPeriod int `json:"patched_in_period"`
	// RebootBacklog counts the hosts that reported a pending reboot;
	// RebootUnknown the hosts that reported nothing.
	RebootBacklog int `json:"reboot_backlog"`
	RebootUnknown int `json:"reboot_unknown"`
	// The sums of the reported pending updates; a host that reported
	// nothing adds nothing, and is counted under SecurityUnknown.
	PendingUpdates         int `json:"pending_updates"`
	PendingSecurityUpdates int `json:"pending_security_updates"`
}

// PatchGroup is the totals over one site or one environment.
type PatchGroup struct {
	Key string `json:"key"`
	PatchCounts
}

// PatchStatus is the patch status report without its host rows; the rows
// are read separately, because a fleet of ten thousand hosts is streamed
// into a file rather than held in one answer.
type PatchStatus struct {
	Totals        PatchCounts  `json:"totals"`
	BySite        []PatchGroup `json:"by_site"`
	ByEnvironment []PatchGroup `json:"by_environment"`
}

// patchSetsSQL prepares the sets every query of the report reads: the
// visible hosts under the filter, each host's last successful upgrade of
// the period, and the campaigns that started work on it in the period.
// The period comes first in the parameters; the clause is numbered from
// $3.
const patchSetsSQL = `
	with visible as (
		select h.* from hosts h where %s
	),
	upgrades as (
		select j.host_id, max(j.finished_at) as last_upgrade_at
		  from jobs j join visible h on h.id = j.host_id
		 where j.action_type = 'packages.upgrade' and j.state = 'succeeded'
		   and j.finished_at >= $1 and j.finished_at < $2
		 group by j.host_id
	),
	touched as (
		select t.host_id, count(distinct t.campaign_id) as campaigns
		  from campaign_targets t join visible h on h.id = t.host_id
		 where t.started_at >= $1 and t.started_at < $2
		 group by t.host_id
	)`

// patchHostsSQL reads the host rows off the sets, in the order of the
// host list.
const patchHostsSQL = `
	select h.id::text, h.hostname, h.site, h.environment, h.lifecycle_state, h.connection_state,
	       coalesce(h.agent_version, ''), h.last_seen_at,
	       h.pending_updates, h.pending_security_updates, h.reboot_required,
	       u.last_upgrade_at, coalesce(c.campaigns, 0)
	  from visible h
	  left join upgrades u on u.host_id = h.id
	  left join touched c on c.host_id = h.id
	 order by h.hostname, h.id`

// PatchStatus computes the totals and the breakdowns by site and by
// environment over the visible hosts.
func (s *Store) PatchStatus(ctx context.Context, period Period, filter Filter) (*PatchStatus, error) {
	report := &PatchStatus{BySite: []PatchGroup{}, ByEnvironment: []PatchGroup{}}
	totals, err := s.patchGroups(ctx, period, filter, "")
	if err != nil {
		return nil, err
	}
	if len(totals) > 0 {
		report.Totals = totals[0].PatchCounts
	}
	if report.BySite, err = s.patchGroups(ctx, period, filter, "site"); err != nil {
		return nil, err
	}
	if report.ByEnvironment, err = s.patchGroups(ctx, period, filter, "environment"); err != nil {
		return nil, err
	}
	return report, nil
}

// patchGroups counts the report by the given key; an empty key gives one
// row of totals. A fleet with no visible host gives no row at all, and
// the caller reads that as zeros - the honest zeros of an empty set.
func (s *Store) patchGroups(ctx context.Context, period Period, filter Filter, key string) ([]PatchGroup, error) {
	column := "''::text"
	if key != "" {
		column = groupKeys[key]
	}
	clause, args := hostClause(filter, 2)
	args = append([]any{period.From, period.To}, args...)
	rows, err := s.pool.Query(ctx, fmt.Sprintf(patchSetsSQL, clause)+`
		select `+column+` as key, count(*),
		       count(*) filter (where h.pending_security_updates = 0),
		       count(*) filter (where h.pending_security_updates is null),
		       count(*) filter (where u.last_upgrade_at is not null),
		       count(*) filter (where h.reboot_required),
		       count(*) filter (where h.reboot_required is null),
		       coalesce(sum(h.pending_updates), 0), coalesce(sum(h.pending_security_updates), 0)
		  from visible h
		  left join upgrades u on u.host_id = h.id
		 group by 1 order by 1`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	groups := []PatchGroup{}
	for rows.Next() {
		var group PatchGroup
		if err := rows.Scan(&group.Key, &group.Hosts, &group.FullyPatched, &group.SecurityUnknown,
			&group.PatchedInPeriod, &group.RebootBacklog, &group.RebootUnknown,
			&group.PendingUpdates, &group.PendingSecurityUpdates); err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}
	return groups, rows.Err()
}

// PatchHosts reads the host rows of the report in the order of the host
// list and hands each to yield, until yield says false or the rows end.
// The rows come straight from the query: a file of the whole fleet costs
// the memory of one row.
func (s *Store) PatchHosts(ctx context.Context, period Period, filter Filter, yield func(PatchHost) bool) error {
	clause, args := hostClause(filter, 2)
	args = append([]any{period.From, period.To}, args...)
	rows, err := s.pool.Query(ctx, fmt.Sprintf(patchSetsSQL, clause)+patchHostsSQL, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var host PatchHost
		var campaigns int
		if err := rows.Scan(&host.HostID, &host.Hostname, &host.Site, &host.Environment, &host.LifecycleState,
			&host.ConnectionState, &host.AgentVersion, &host.LastSeenAt,
			&host.PendingUpdates, &host.PendingSecurityUpdates, &host.RebootRequired,
			&host.LastUpgradeAt, &campaigns); err != nil {
			return err
		}
		host.Campaigns = &campaigns
		if !yield(host) {
			return nil
		}
	}
	return rows.Err()
}
