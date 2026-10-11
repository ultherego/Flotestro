package jobs

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ultherego/flotestro/internal/authz"
)

// What the fleet left in a state nobody could confirm, and what an operator
// has said about it.
//
// Two outcomes belong here and they ask different questions, so they are
// never summed:
//
//	outcome_unknown      did the change happen? The agent came back from a
//	                     restart to find an operation it had started and did
//	                     not live to see the end of.
//	applied_unverified   did the change hold? It was made, and the verifier
//	                     could not confirm it afterwards.
//
// The dashboard's counter of failed tasks covers the last 24 hours, so until
// now one of these left the screen because time passed. Nothing here ages
// out: an item is on the list until somebody rules on it, and the ruling is
// a row of its own that leaves the attempt as the fleet reported it.
const (
	// UncertaintyOutcomeUnknown is "did it happen?".
	UncertaintyOutcomeUnknown = "outcome_unknown"
	// UncertaintyAppliedUnverified is "did it hold?".
	UncertaintyAppliedUnverified = "applied_unverified"
)

// Unresolved is one attempt whose outcome nobody could confirm.
type Unresolved struct {
	AttemptID string `json:"attempt_id"`
	JobID     string `json:"job_id"`
	HostID    string `json:"host_id"`
	Hostname  string `json:"hostname"`
	Action    string `json:"action"`
	// Kind is which question is open; the two are never added together.
	Kind string `json:"kind"`
	// Reason is what the host said, in its own words.
	Reason string `json:"reason,omitempty"`
	// Verification is what the verifier looked for and what it found, for an
	// applied_unverified. Null for an outcome_unknown, which has no reading.
	Verification []byte `json:"verification,omitempty"`
	// FirstSeen is when the uncertainty arose, not when it was last looked at.
	FirstSeen time.Time `json:"first_seen"`
	// LastCheckedAt is the most recent attempt of the same job to settle it,
	// so the operator can tell "nobody has looked since" from "it was tried
	// again an hour ago".
	LastCheckedAt *time.Time `json:"last_checked_at,omitempty"`
}

// UnresolvedCounts answers "how much is open" without the list. Operations
// and hosts are counted apart because one host with forty uncertain
// operations and forty hosts with one each are different situations, and a
// single number reads the same for both.
type UnresolvedCounts struct {
	OutcomeUnknownOperations    int `json:"outcome_unknown_operations"`
	OutcomeUnknownHosts         int `json:"outcome_unknown_hosts"`
	AppliedUnverifiedOperations int `json:"applied_unverified_operations"`
	AppliedUnverifiedHosts      int `json:"applied_unverified_hosts"`
}

// UnresolvedFilter narrows the list the way the screen does.
type UnresolvedFilter struct {
	// Scopes narrow it to the hosts the caller may see, the same way the job
	// list is narrowed: an uncertain operation is an operation, and an
	// operator of one environment must not read the whole fleet's.
	Scopes []authz.Scope
	// Kind selects one of the two questions, or both when empty.
	Kind   string
	HostID string
	Limit  int
}

// unresolvedWhere builds the condition both the list and the counts use, so
// a narrowing added to one cannot go missing from the other - the counter
// and the list disagreeing is how an operator learns to trust neither.
func unresolvedWhere(f UnresolvedFilter) (string, []any) {
	conditions := []string{
		// No ruling yet. The ruling is a separate row and removing it from
		// the list is all it does: the attempt keeps what the fleet reported.
		"not exists (select 1 from unresolved_operation_rulings r where r.attempt_id = a.id)",
		// One of the two uncertainties, read off what the host answered.
		fmt.Sprintf(
			"(a.error_code = '%s' or a.error_code = '%s' or "+
				"(a.verification is not null and (a.verification ->> 'verified') = 'false'))",
			UncertaintyOutcomeUnknown, UncertaintyAppliedUnverified),
	}
	var args []any
	if len(f.Scopes) > 0 {
		if condition, extra := authz.ScopeSQL(f.Scopes, authz.HostColumns("h"), len(args)); condition != "" {
			conditions = append(conditions,
				"exists (select 1 from hosts h where h.id = j.host_id and "+condition+")")
			args = append(args, extra...)
		}
	}
	if f.HostID != "" {
		args = append(args, f.HostID)
		conditions = append(conditions, fmt.Sprintf("j.host_id = $%d", len(args)))
	}
	switch f.Kind {
	case UncertaintyOutcomeUnknown:
		args = append(args, UncertaintyOutcomeUnknown)
		conditions = append(conditions, fmt.Sprintf("a.error_code = $%d", len(args)))
	case UncertaintyAppliedUnverified:
		conditions = append(conditions,
			"(a.error_code = '"+UncertaintyAppliedUnverified+"' or "+
				"(a.verification is not null and (a.verification ->> 'verified') = 'false'))")
	}
	where := "where " + conditions[0]
	for _, condition := range conditions[1:] {
		where += " and " + condition
	}
	return where, args
}

// unresolvedKind says which question an attempt leaves open. An attempt can
// carry both marks - the agent answered applied_unverified and the verifier
// recorded why - and the error code is the one that names what happened.
func unresolvedKind(errorCode string, hasFailedVerification bool) string {
	if errorCode == UncertaintyOutcomeUnknown {
		return UncertaintyOutcomeUnknown
	}
	if errorCode == UncertaintyAppliedUnverified || hasFailedVerification {
		return UncertaintyAppliedUnverified
	}
	return ""
}

// UnresolvedList returns the attempts nobody has ruled on, newest first.
func (s *Store) UnresolvedList(ctx context.Context, f UnresolvedFilter) ([]Unresolved, error) {
	where, args := unresolvedWhere(f)
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	args = append(args, limit)
	rows, err := s.pool.Query(ctx, `
		select a.id, a.job_id, j.host_id, coalesce(h.hostname, ''), j.action,
		       coalesce(a.error_code, ''), coalesce(a.message, ''),
		       a.verification,
		       -- Carrying a verification is not the same as having failed one:
		       -- a row selected by its error code may hold a reading that
		       -- succeeded, and calling that applied_unverified would put the
		       -- wrong question on the screen.
		       (a.verification is not null and (a.verification ->> 'verified') = 'false'),
		       a.started_at,
		       (select max(later.started_at) from job_attempts later
		         where later.job_id = a.job_id and later.started_at > a.started_at)
		  from job_attempts a
		  join jobs j on j.id = a.job_id
		  left join hosts h on h.id = j.host_id
		`+where+`
		 order by a.started_at desc
		 limit $`+fmt.Sprint(len(args)), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []Unresolved
	for rows.Next() {
		var one Unresolved
		var errorCode string
		var verificationFailed bool
		if err := rows.Scan(&one.AttemptID, &one.JobID, &one.HostID, &one.Hostname,
			&one.Action, &errorCode, &one.Reason, &one.Verification,
			&verificationFailed, &one.FirstSeen, &one.LastCheckedAt); err != nil {
			return nil, err
		}
		one.Kind = unresolvedKind(errorCode, verificationFailed)
		if one.Reason == "" {
			one.Reason = errorCode
		}
		list = append(list, one)
	}
	return list, rows.Err()
}

// UnresolvedCount answers how much is open, in four numbers rather than one.
//
// Operations and hosts are counted apart, and the two uncertainties are
// counted apart from each other. A single total would read the same for one
// host with forty uncertain operations and for forty hosts with one each,
// and those call for different work.
//
// The condition is the one the list uses, from the same function: a counter
// that disagrees with the list it heads is how an operator learns to trust
// neither.
func (s *Store) UnresolvedCount(ctx context.Context, f UnresolvedFilter) (UnresolvedCounts, error) {
	// The kind filter belongs to the list, not here: this answers both.
	f.Kind = ""
	where, args := unresolvedWhere(f)
	var counts UnresolvedCounts
	err := s.pool.QueryRow(ctx, `
		with open as (
		  select j.host_id,
		         case when a.error_code = '`+UncertaintyOutcomeUnknown+`'
		              then '`+UncertaintyOutcomeUnknown+`'
		              else '`+UncertaintyAppliedUnverified+`' end as kind
		    from job_attempts a
		    join jobs j on j.id = a.job_id
		  `+where+`
		)
		select
		  count(*) filter (where kind = '`+UncertaintyOutcomeUnknown+`'),
		  count(distinct host_id) filter (where kind = '`+UncertaintyOutcomeUnknown+`'),
		  count(*) filter (where kind = '`+UncertaintyAppliedUnverified+`'),
		  count(distinct host_id) filter (where kind = '`+UncertaintyAppliedUnverified+`')
		  from open`, args...).
		Scan(&counts.OutcomeUnknownOperations, &counts.OutcomeUnknownHosts,
			&counts.AppliedUnverifiedOperations, &counts.AppliedUnverifiedHosts)
	return counts, err
}

// Ruling is what an operator concluded about one uncertain attempt.
type Ruling struct {
	AttemptID string    `json:"attempt_id"`
	Kind      string    `json:"kind"`
	Ruling    string    `json:"ruling"`
	Basis     string    `json:"basis"`
	RuledBy   string    `json:"ruled_by"`
	RuledAt   time.Time `json:"ruled_at"`
}

// The rulings an operator may give. accepted_unknown is a decision to stop
// asking, which is still a decision somebody made and put their name to -
// unlike the old behaviour, where the item left the screen because a day
// had passed.
const (
	RulingConfirmedApplied    = "confirmed_applied"
	RulingConfirmedNotApplied = "confirmed_not_applied"
	RulingAcceptedUnknown     = "accepted_unknown"
)

// Rule records what an operator concluded. It writes a row beside the
// attempt and changes nothing about the attempt itself: the job keeps the
// outcome the fleet reported, because an operator's reading is a second
// fact about it and not a correction of the first. A screen that rewrote
// the outcome would make the record unreliable for everything else that
// reads it - the audit trail, the campaign report, the pilot's evidence.
func (s *Store) Rule(ctx context.Context, one Ruling) error {
	switch one.Ruling {
	case RulingConfirmedApplied, RulingConfirmedNotApplied, RulingAcceptedUnknown:
	default:
		return fmt.Errorf("%q is not a ruling", one.Ruling)
	}
	if one.Kind != UncertaintyOutcomeUnknown && one.Kind != UncertaintyAppliedUnverified {
		return fmt.Errorf("%q is not one of the two uncertainties", one.Kind)
	}
	_, err := s.pool.Exec(ctx, `
		insert into unresolved_operation_rulings
		       (attempt_id, kind, ruling, basis, ruled_by)
		values ($1, $2, $3, $4, $5)
		on conflict (attempt_id) do nothing`,
		one.AttemptID, one.Kind, one.Ruling, one.Basis, one.RuledBy)
	return err
}

// AttemptOwner is the job an attempt belongs to: who may rule on an attempt
// is decided by the job, the same way who may read it is.
type AttemptOwner struct {
	ID     string
	HostID string
}

// JobOfAttempt answers which job an attempt belongs to, or an empty owner
// when there is no such attempt.
func (s *Store) JobOfAttempt(ctx context.Context, attemptID string) (AttemptOwner, error) {
	var owner AttemptOwner
	err := s.pool.QueryRow(ctx, `
		select j.id, j.host_id from job_attempts a
		  join jobs j on j.id = a.job_id
		 where a.id = $1`, attemptID).Scan(&owner.ID, &owner.HostID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return AttemptOwner{}, nil
		}
		return AttemptOwner{}, err
	}
	return owner, nil
}
