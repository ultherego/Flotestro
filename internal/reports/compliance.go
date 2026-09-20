package reports

import (
	"context"
	"fmt"
	"time"
)

// The compliance report: where the visible hosts stand against the declared
// policies at the end of the period.

// The verdicts a policy rule gives, and the one the report adds.
const (
	VerdictCompliant     = "compliant"
	VerdictDrift         = "drift"
	VerdictError         = "error"
	VerdictNotApplicable = "not_applicable"
	// VerdictUnknown is the report's own: the verdict that stood at the
	// end of the period has been overwritten since.
	VerdictUnknown = "unknown"
)

// HostRef names a host of a report.
type HostRef struct {
	HostID   string `json:"host_id"`
	Hostname string `json:"hostname"`
	Site     string `json:"site"`
}

// PolicyRow is one policy of the report with its hosts by verdict.
type PolicyRow struct {
	ID              string     `json:"id"`
	Name            string     `json:"name"`
	Version         int        `json:"version"`
	Enabled         bool       `json:"enabled"`
	RemediationMode string     `json:"remediation_mode"`
	LastEvaluatedAt *time.Time `json:"last_evaluated_at,omitempty"`
	// Hosts counts the visible hosts with a verdict; the verdicts split
	// them.
	Hosts         int `json:"hosts"`
	Compliant     int `json:"compliant"`
	Drift         int `json:"drift"`
	Error         int `json:"error"`
	NotApplicable int `json:"not_applicable"`
	Unknown       int `json:"unknown"`
	// Rules tallies the rule results by verdict: what the results list of
	// the policy counts.
	Rules map[string]int `json:"rules"`
	// DriftHosts names the hosts in drift, the first driftHostLimit of
	// them by name; Drift is the exact count.
	DriftHosts []HostRef `json:"drift_hosts"`
}

// DriftHost is one host in drift and how much of it.
type DriftHost struct {
	HostRef
	Environment string `json:"environment"`
	// Policies counts the policies the host drifts from; Rules the rules.
	Policies int `json:"policies"`
	Rules    int `json:"rules"`
}

// PolicyTotals are the totals over the policies of the report.
type PolicyTotals struct {
	Policies int `json:"policies"`
	// The host verdicts summed over the policies: a host under three
	// policies counts three times, once per policy.
	Compliant     int `json:"compliant"`
	Drift         int `json:"drift"`
	Error         int `json:"error"`
	NotApplicable int `json:"not_applicable"`
	Unknown       int `json:"unknown"`
	// HostsInDrift counts the distinct hosts in drift from any policy.
	HostsInDrift int `json:"hosts_in_drift"`
}

// PolicyCompliance is the policy part of the compliance report.
type PolicyCompliance struct {
	Policies []PolicyRow `json:"policies"`
	// DriftHosts names the hosts in drift, the first driftHostSample of them
	// by name; Totals.HostsInDrift is the exact count.
	DriftHosts []DriftHost `json:"drift_hosts"`
	// DriftHostsTruncated says hosts are left out of the sample; the file of
	// the hosts section carries them all.
	DriftHostsTruncated bool         `json:"drift_hosts_truncated"`
	Totals              PolicyTotals `json:"totals"`
}

// driftHostLimit bounds the host names a policy row carries. The count is
// exact; the names are a sample, and the drift host table lists the rest.
const driftHostLimit = 50

// driftHostSample bounds the hosts in drift the report itself carries, so a
// fleet where everything drifts has a ceiling rather than a body per host.
const driftHostSample = 200

// hostVerdictsSQL judges every visible host under every policy: the worst
// verdict of its rules, with the verdicts recorded after the end of the period
// read as unknown.
const hostVerdictsSQL = `
	with verdicts as (
		select r.policy_id, r.host_id, h.hostname, h.site, h.environment,
		       case when r.evaluated_at >= $1 then 'unknown' else r.verdict end as verdict
		  from policy_results r join hosts h on h.id = r.host_id
		 where %s
	),
	judged as (
		select policy_id, host_id, min(hostname) as hostname, min(site) as site, min(environment) as environment,
		       case when bool_or(verdict = 'drift') then 'drift'
		            when bool_or(verdict = 'error') then 'error'
		            when bool_or(verdict = 'unknown') then 'unknown'
		            when bool_or(verdict = 'compliant') then 'compliant'
		            else 'not_applicable' end as verdict,
		       count(*) filter (where verdict = 'drift') as drift_rules
		  from verdicts group by policy_id, host_id
	)`

// Policies computes the policy part of the report over the visible hosts.
func (s *Store) Policies(ctx context.Context, period Period, filter Filter) (*PolicyCompliance, error) {
	report := &PolicyCompliance{Policies: []PolicyRow{}, DriftHosts: []DriftHost{}}
	clause, args := hostClause(filter, 1)
	args = append([]any{period.To}, args...)

	// Every policy, evaluated or not, with its hosts by verdict; a policy
	// nobody has judged yet is a row of zeros, not a missing row.
	rows, err := s.pool.Query(ctx, `
		select p.id::text, p.name, p.version, p.enabled, p.remediation_mode, p.last_evaluated_at,
		       count(j.host_id),
		       count(j.host_id) filter (where j.verdict = 'compliant'),
		       count(j.host_id) filter (where j.verdict = 'drift'),
		       count(j.host_id) filter (where j.verdict = 'error'),
		       count(j.host_id) filter (where j.verdict = 'not_applicable'),
		       count(j.host_id) filter (where j.verdict = 'unknown')
		  from policies p
		  left join (`+fmt.Sprintf(hostVerdictsSQL, clause)+` select * from judged) j on j.policy_id = p.id
		 group by p.id
		 order by p.name, p.id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	index := map[string]int{}
	for rows.Next() {
		row := PolicyRow{Rules: map[string]int{}, DriftHosts: []HostRef{}}
		if err := rows.Scan(&row.ID, &row.Name, &row.Version, &row.Enabled, &row.RemediationMode, &row.LastEvaluatedAt,
			&row.Hosts, &row.Compliant, &row.Drift, &row.Error, &row.NotApplicable, &row.Unknown); err != nil {
			return nil, err
		}
		for _, verdict := range []string{VerdictCompliant, VerdictDrift, VerdictError, VerdictNotApplicable, VerdictUnknown} {
			row.Rules[verdict] = 0
		}
		index[row.ID] = len(report.Policies)
		report.Policies = append(report.Policies, row)
		report.Totals.Policies++
		report.Totals.Compliant += row.Compliant
		report.Totals.Drift += row.Drift
		report.Totals.Error += row.Error
		report.Totals.NotApplicable += row.NotApplicable
		report.Totals.Unknown += row.Unknown
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// The rule results by verdict, as the results list of a policy counts
	// them.
	rules, err := s.pool.Query(ctx, `
		select r.policy_id::text, case when r.evaluated_at >= $1 then 'unknown' else r.verdict end, count(*)
		  from policy_results r join hosts h on h.id = r.host_id
		 where `+clause+`
		 group by 1, 2`, args...)
	if err != nil {
		return nil, err
	}
	defer rules.Close()
	for rules.Next() {
		var policyID, verdict string
		var count int
		if err := rules.Scan(&policyID, &verdict, &count); err != nil {
			return nil, err
		}
		if i, ok := index[policyID]; ok {
			report.Policies[i].Rules[verdict] = count
		}
	}
	if err := rules.Err(); err != nil {
		return nil, err
	}

	// The hosts in drift: named under their policies, a sample per policy, and
	// listed once each with how many policies they drift from - a sample too,
	// with the exact count in the totals.
	if err := s.scanDrift(ctx, period, filter,
		func(policyID string, host HostRef) {
			if i, ok := index[policyID]; ok && len(report.Policies[i].DriftHosts) < driftHostLimit {
				report.Policies[i].DriftHosts = append(report.Policies[i].DriftHosts, host)
			}
		},
		func(host DriftHost) bool {
			report.Totals.HostsInDrift++
			if len(report.DriftHosts) < driftHostSample {
				report.DriftHosts = append(report.DriftHosts, host)
			} else {
				report.DriftHostsTruncated = true
			}
			return true
		}); err != nil {
		return nil, err
	}
	return report, nil
}

// DriftHosts hands every host in drift to yield, once each, in the order of
// the host list: what the report samples, the file carries in full.
func (s *Store) DriftHosts(ctx context.Context, period Period, filter Filter, yield func(DriftHost) bool) error {
	return s.scanDrift(ctx, period, filter, nil, yield)
}

// scanDrift walks the hosts in drift, a row per host and policy. perPolicy
// sees every row; perHost sees each host once with its totals and ends the
// walk by returning false. The rows arrive grouped by host, so one host at a
// time is held.
func (s *Store) scanDrift(ctx context.Context, period Period, filter Filter,
	perPolicy func(policyID string, host HostRef), perHost func(DriftHost) bool) error {
	clause, args := hostClause(filter, 1)
	args = append([]any{period.To}, args...)
	rows, err := s.pool.Query(ctx, fmt.Sprintf(hostVerdictsSQL, clause)+`
		select policy_id::text, host_id::text, hostname, site, environment, drift_rules
		  from judged where verdict = 'drift'
		 order by hostname, host_id, policy_id`, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	var current DriftHost
	open := false
	for rows.Next() {
		var policyID string
		var host DriftHost
		var driftRules int
		if err := rows.Scan(&policyID, &host.HostID, &host.Hostname, &host.Site, &host.Environment, &driftRules); err != nil {
			return err
		}
		if perPolicy != nil {
			perPolicy(policyID, host.HostRef)
		}
		if open && current.HostID != host.HostID {
			if !perHost(current) {
				return nil
			}
			open = false
		}
		if !open {
			current, open = host, true
		}
		current.Policies++
		current.Rules += driftRules
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if open {
		perHost(current)
	}
	return nil
}
