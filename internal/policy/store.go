package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ultherego/flotestro/internal/paging"
)

var (
	// ErrNotFound means there is no such policy.
	ErrNotFound = errors.New("the policy does not exist")
	// ErrNameTaken means another policy carries the name.
	ErrNameTaken = errors.New("a policy with this name exists")
	// ErrNotPublished means a request that needs a published version of
	// a policy that has none.
	ErrNotPublished = errors.New("the policy has not been published")
)

// Store provides access to the policy tables.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore opens the store on the pool.
func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// Pool returns the pool, for the callers that write in one transaction
// with the campaigns.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

const policyColumns = `
	select p.id, p.name, p.description, p.version, p.selector, p.rules, p.remediation_mode,
	       p.enabled, p.check_interval_seconds, p.created_by, p.created_at, p.updated_at,
	       p.published_at, p.published_by, p.last_evaluated_at,
	       coalesce((select v.document from policy_versions v
	                  where v.policy_id = p.id and v.version = p.version), 'null'::jsonb)
	from policies p `

type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

func (s *Store) query(ctx context.Context, q querier, clause string, args ...any) ([]Policy, error) {
	rows, err := q.Query(ctx, policyColumns+clause, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var policies []Policy
	for rows.Next() {
		var p Policy
		var rules, published json.RawMessage
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.Version, &p.Selector, &rules, &p.RemediationMode,
			&p.Enabled, &p.CheckInterval, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt,
			&p.PublishedAt, &p.PublishedBy, &p.LastEvaluatedAt, &published); err != nil {
			return nil, err
		}
		if len(p.Selector) == 0 {
			p.Selector = json.RawMessage("{}")
		}
		if err := json.Unmarshal(rules, &p.Rules); err != nil {
			return nil, fmt.Errorf("the rules of policy %s do not decode: %w", p.ID, err)
		}
		if p.Rules == nil {
			p.Rules = []Rule{}
		}
		// The draft flag compares the row with the frozen document: a policy edited
		// after its publication is judged by the published text, and the screen has
		// to say so.
		if p.Version > 0 && string(published) != "null" {
			var frozen Document
			if err := json.Unmarshal(published, &frozen); err == nil {
				p.Draft = !frozen.Equal(DocumentOf(p))
			}
		}
		p.Counts = EmptyCounts()
		policies = append(policies, p)
	}
	return policies, rows.Err()
}

// List returns every policy, by name, with the verdict counts of the
// latest evaluation.
func (s *Store) List(ctx context.Context) ([]Policy, error) {
	policies, err := s.query(ctx, s.pool, "order by p.name")
	if err != nil {
		return nil, err
	}
	if policies == nil {
		policies = []Policy{}
	}
	if err := s.fillCounts(ctx, policies); err != nil {
		return nil, err
	}
	return policies, nil
}

// Get returns one policy with its counts.
func (s *Store) Get(ctx context.Context, id string) (*Policy, error) {
	policies, err := s.query(ctx, s.pool, "where p.id = $1", id)
	if err != nil {
		return nil, err
	}
	if len(policies) == 0 {
		return nil, ErrNotFound
	}
	if err := s.fillCounts(ctx, policies); err != nil {
		return nil, err
	}
	return &policies[0], nil
}

// fillCounts reads the verdict counts of the latest evaluation of every
// policy. Missing verdicts stay at zero; the four keys are always there.
func (s *Store) fillCounts(ctx context.Context, policies []Policy) error {
	if len(policies) == 0 {
		return nil
	}
	ids := make([]string, 0, len(policies))
	index := map[string]int{}
	for i, p := range policies {
		ids = append(ids, p.ID)
		index[p.ID] = i
	}
	rows, err := s.pool.Query(ctx, `
		select policy_id::text, verdict, count(*) from policy_results
		 where policy_id = any($1::uuid[]) group by policy_id, verdict`, ids)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, verdict string
		var count int
		if err := rows.Scan(&id, &verdict, &count); err != nil {
			return err
		}
		if i, ok := index[id]; ok {
			policies[i].Counts[verdict] = count
		}
	}
	return rows.Err()
}

// Create records a draft.
func (s *Store) Create(ctx context.Context, spec Spec, createdBy string) (*Policy, error) {
	selector, rules, interval, enabled, err := encodeSpec(spec)
	if err != nil {
		return nil, err
	}
	id := uuid.NewString()
	_, err = s.pool.Exec(ctx, `
		insert into policies (id, name, description, selector, rules, remediation_mode, enabled,
		                      check_interval_seconds, created_by)
		values ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		id, strings.TrimSpace(spec.Name), strings.TrimSpace(spec.Description), selector, rules,
		spec.RemediationMode, enabled, interval, createdBy)
	if isUniqueViolation(err) {
		return nil, ErrNameTaken
	}
	if err != nil {
		return nil, fmt.Errorf("creating the policy: %w", err)
	}
	return s.Get(ctx, id)
}

// Update rewrites the draft. The version does not move: what the loop
// judges is the published document until the next publication.
func (s *Store) Update(ctx context.Context, id string, spec Spec) (*Policy, error) {
	selector, rules, interval, enabled, err := encodeSpec(spec)
	if err != nil {
		return nil, err
	}
	tag, err := s.pool.Exec(ctx, `
		update policies
		   set name = $2, description = $3, selector = $4, rules = $5, remediation_mode = $6,
		       enabled = $7, check_interval_seconds = $8, updated_at = now()
		 where id = $1`,
		id, strings.TrimSpace(spec.Name), strings.TrimSpace(spec.Description), selector, rules,
		spec.RemediationMode, enabled, interval)
	if isUniqueViolation(err) {
		return nil, ErrNameTaken
	}
	if err != nil {
		return nil, fmt.Errorf("updating the policy: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrNotFound
	}
	return s.Get(ctx, id)
}

func encodeSpec(spec Spec) (selector, rules []byte, interval int, enabled bool, err error) {
	selector, err = json.Marshal(spec.Selector)
	if err != nil {
		return nil, nil, 0, false, err
	}
	list := spec.Rules
	if list == nil {
		list = []Rule{}
	}
	rules, err = json.Marshal(list)
	if err != nil {
		return nil, nil, 0, false, err
	}
	interval = spec.CheckInterval
	if interval == 0 {
		interval = int(DefaultCheckInterval / time.Second)
	}
	enabled = spec.Enabled == nil || *spec.Enabled
	return selector, rules, interval, enabled, nil
}

// Delete removes a policy with its versions, results and remediation
// links; the campaigns it ordered stay, with the link set to null.
func (s *Store) Delete(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `delete from policies where id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Publication is the evidence of a publication, recorded with the frozen
// document.
type Publication struct {
	PublishedBy     string
	Reason          string
	Authentication  string
	ACR             string
	AMR             []string
	AuthenticatedAt *time.Time
}

// Publish freezes the draft as the next version.
func (s *Store) Publish(ctx context.Context, id string, publication Publication) (*Policy, *Version, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	policies, err := s.query(ctx, tx, "where p.id = $1 for update of p", id)
	if err != nil {
		return nil, nil, err
	}
	if len(policies) == 0 {
		return nil, nil, ErrNotFound
	}
	policy := policies[0]
	if err := ValidateRules(policy.Rules, policy.RemediationMode); err != nil {
		return nil, nil, err
	}
	document := DocumentOf(policy)
	encoded, err := json.Marshal(document)
	if err != nil {
		return nil, nil, err
	}
	next := policy.Version + 1
	amr := publication.AMR
	if amr == nil {
		amr = []string{}
	}
	if _, err := tx.Exec(ctx, `
		insert into policy_versions (policy_id, version, document, published_by, reason,
		                             authentication, acr, amr, authenticated_at)
		values ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		id, next, encoded, publication.PublishedBy, publication.Reason,
		publication.Authentication, publication.ACR, amr, publication.AuthenticatedAt); err != nil {
		return nil, nil, fmt.Errorf("freezing the version: %w", err)
	}
	// A new version judges anew: the results of the old one would mix
	// two documents in one table.
	if _, err := tx.Exec(ctx, `delete from policy_results where policy_id = $1`, id); err != nil {
		return nil, nil, err
	}
	if _, err := tx.Exec(ctx, `
		update policies set version = $2, published_at = now(), published_by = $3,
		                    last_evaluated_at = null, updated_at = now()
		 where id = $1`, id, next, publication.PublishedBy); err != nil {
		return nil, nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, nil, err
	}
	version, err := s.VersionOf(ctx, id, next)
	if err != nil {
		return nil, nil, err
	}
	updated, err := s.Get(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	return updated, version, nil
}

// Versions lists the publications of a policy, newest first.
func (s *Store) Versions(ctx context.Context, id string) ([]Version, error) {
	rows, err := s.pool.Query(ctx, `
		select policy_id, version, document, published_by, published_at, reason,
		       authentication, acr, amr, authenticated_at
		  from policy_versions where policy_id = $1 order by version desc`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	versions := []Version{}
	for rows.Next() {
		version, err := scanVersion(rows)
		if err != nil {
			return nil, err
		}
		versions = append(versions, version)
	}
	return versions, rows.Err()
}

// VersionOf returns one publication.
func (s *Store) VersionOf(ctx context.Context, id string, number int) (*Version, error) {
	rows, err := s.pool.Query(ctx, `
		select policy_id, version, document, published_by, published_at, reason,
		       authentication, acr, amr, authenticated_at
		  from policy_versions where policy_id = $1 and version = $2`, id, number)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, ErrNotPublished
	}
	version, err := scanVersion(rows)
	if err != nil {
		return nil, err
	}
	return &version, nil
}

func scanVersion(rows pgx.Rows) (Version, error) {
	var version Version
	if err := rows.Scan(&version.PolicyID, &version.Version, &version.Document, &version.PublishedBy,
		&version.PublishedAt, &version.Reason, &version.Authentication, &version.ACR, &version.AMR,
		&version.AuthenticatedAt); err != nil {
		return Version{}, err
	}
	if _, err := version.Decode(); err != nil {
		return Version{}, err
	}
	return version, nil
}

// Due lists the enabled, published policies whose last evaluation is
// older than their interval, or that were never evaluated.
func (s *Store) Due(ctx context.Context, now time.Time) ([]Policy, error) {
	policies, err := s.query(ctx, s.pool, `
		where p.enabled and p.version > 0
		  and (p.last_evaluated_at is null
		       or p.last_evaluated_at + make_interval(secs => p.check_interval_seconds) <= $1)
		order by p.last_evaluated_at nulls first, p.name`, now)
	if err != nil {
		return nil, err
	}
	return policies, nil
}

// ReplaceResults writes the verdicts of one evaluation of a policy and marks
// the evaluation.
func (s *Store) ReplaceResults(ctx context.Context, policyID string, version int, results []Result, now time.Time) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `delete from policy_results where policy_id = $1`, policyID); err != nil {
		return err
	}
	batch := &pgx.Batch{}
	for _, result := range results {
		batch.Queue(`
			insert into policy_results (policy_id, host_id, rule_index, version, verdict, reason,
			                            observed_revision, evaluated_at)
			values ($1, $2, $3, $4, $5, $6, $7, $8)`,
			policyID, result.HostID, result.RuleIndex, version, result.Verdict, result.Reason,
			result.ObservedRevision, now)
	}
	if batch.Len() > 0 {
		if err := tx.SendBatch(ctx, batch).Close(); err != nil {
			return fmt.Errorf("recording the verdicts: %w", err)
		}
	}
	if _, err := tx.Exec(ctx, `update policies set last_evaluated_at = $2 where id = $1`, policyID, now); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ResultFilter narrows a page of results.
type ResultFilter struct {
	HostID  string
	Verdict string
}

// Results pages through the verdicts of a policy, host by host and rule
// by rule, with the rule of the judged version beside every row.
func (s *Store) Results(ctx context.Context, policyID string, filter ResultFilter, cursor string, limit int) ([]Result, string, int, error) {
	parts, err := paging.Decode(cursor, 2)
	if err != nil {
		return nil, "", 0, err
	}
	afterHost, afterRule := "", -1
	if parts != nil {
		afterHost = parts[0]
		if _, err := fmt.Sscanf(parts[1], "%d", &afterRule); err != nil {
			return nil, "", 0, paging.ErrInvalidCursor
		}
	}
	where := "where r.policy_id = $1"
	args := []any{policyID}
	if filter.HostID != "" {
		args = append(args, filter.HostID)
		where += fmt.Sprintf(" and r.host_id = $%d", len(args))
	}
	if filter.Verdict != "" {
		args = append(args, filter.Verdict)
		where += fmt.Sprintf(" and r.verdict = $%d", len(args))
	}
	var total int
	if err := s.pool.QueryRow(ctx, "select count(*) from policy_results r "+where, args...).Scan(&total); err != nil {
		return nil, "", 0, err
	}
	// The page walks the hosts by name, then by rule: the operator reads a
	// host's verdicts together.
	args = append(args, afterHost, afterRule, limit+1)
	rows, err := s.pool.Query(ctx, `
		select r.policy_id::text, p.name, r.host_id::text, coalesce(h.hostname, ''), r.rule_index,
		       r.version, r.verdict, r.reason, r.observed_revision, r.evaluated_at,
		       coalesce((select v.document -> 'rules' -> r.rule_index from policy_versions v
		                  where v.policy_id = r.policy_id and v.version = r.version), 'null'::jsonb)
		  from policy_results r
		  join policies p on p.id = r.policy_id
		  left join hosts h on h.id = r.host_id `+where+
		fmt.Sprintf(` and (coalesce(h.hostname, '') || '/' || r.host_id::text, r.rule_index) > ($%d, $%d)
		 order by coalesce(h.hostname, '') || '/' || r.host_id::text, r.rule_index
		 limit $%d`, len(args)-2, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, "", 0, err
	}
	defer rows.Close()
	results, err := scanResults(rows)
	if err != nil {
		return nil, "", 0, err
	}
	next := ""
	if len(results) > limit {
		results = results[:limit]
		last := results[len(results)-1]
		next = paging.Encode(last.Hostname+"/"+last.HostID, fmt.Sprintf("%d", last.RuleIndex))
	}
	return results, next, total, nil
}

// ForHost lists the verdicts of every policy on one host, by policy name
// and rule.
func (s *Store) ForHost(ctx context.Context, hostID string) ([]Result, error) {
	rows, err := s.pool.Query(ctx, `
		select r.policy_id::text, p.name, r.host_id::text, coalesce(h.hostname, ''), r.rule_index,
		       r.version, r.verdict, r.reason, r.observed_revision, r.evaluated_at,
		       coalesce((select v.document -> 'rules' -> r.rule_index from policy_versions v
		                  where v.policy_id = r.policy_id and v.version = r.version), 'null'::jsonb)
		  from policy_results r
		  join policies p on p.id = r.policy_id
		  left join hosts h on h.id = r.host_id
		 where r.host_id = $1
		 order by p.name, r.rule_index`, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanResults(rows)
}

func scanResults(rows pgx.Rows) ([]Result, error) {
	results := []Result{}
	for rows.Next() {
		var result Result
		var rule json.RawMessage
		if err := rows.Scan(&result.PolicyID, &result.PolicyName, &result.HostID, &result.Hostname,
			&result.RuleIndex, &result.Version, &result.Verdict, &result.Reason,
			&result.ObservedRevision, &result.EvaluatedAt, &rule); err != nil {
			return nil, err
		}
		if string(rule) != "null" {
			var decoded Rule
			if json.Unmarshal(rule, &decoded) == nil {
				result.Rule = &decoded
			}
		}
		results = append(results, result)
	}
	return results, rows.Err()
}

// RemediationCampaign returns the campaign already ordered for a drift
// set, or an empty string.
func (s *Store) RemediationCampaign(ctx context.Context, policyID, fingerprint string) (string, error) {
	var campaignID string
	err := s.pool.QueryRow(ctx, `
		select campaign_id::text from policy_remediations
		 where policy_id = $1 and fingerprint = $2`, policyID, fingerprint).Scan(&campaignID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return campaignID, err
}

// RecordRemediation links a drift set with the campaign ordered for it,
// in the caller's transaction, so the link exists only with the campaign.
func (s *Store) RecordRemediation(ctx context.Context, tx pgx.Tx, policyID string, version int, fingerprint, campaignID string) error {
	_, err := tx.Exec(ctx, `
		insert into policy_remediations (policy_id, version, fingerprint, campaign_id)
		values ($1, $2, $3, $4)`, policyID, version, fingerprint, campaignID)
	return err
}

// CampaignLink names a campaign a policy ordered.
type CampaignLink struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	State     string    `json:"state"`
	Version   int       `json:"policy_version"`
	CreatedAt time.Time `json:"created_at"`
}

// Campaigns lists the remediation campaigns of a policy, newest first.
func (s *Store) Campaigns(ctx context.Context, policyID string) ([]CampaignLink, error) {
	rows, err := s.pool.Query(ctx, `
		select id::text, name, state, coalesce(policy_version, 0), created_at
		  from campaigns where policy_id = $1 order by created_at desc limit 50`, policyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	links := []CampaignLink{}
	for rows.Next() {
		var link CampaignLink
		if err := rows.Scan(&link.ID, &link.Name, &link.State, &link.Version, &link.CreatedAt); err != nil {
			return nil, err
		}
		links = append(links, link)
	}
	return links, rows.Err()
}

// OpenRemediation says whether a remediation campaign of the policy is still
// on the table - awaiting approval, planned or under way.
func (s *Store) OpenRemediation(ctx context.Context, policyID string) (string, error) {
	var campaignID string
	err := s.pool.QueryRow(ctx, `
		select id::text from campaigns
		 where policy_id = $1
		   and state in ('planning', 'planned', 'awaiting_approval', 'canary', 'manual_gate', 'running', 'pausing', 'paused', 'canceling')
		 order by created_at desc limit 1`, policyID).Scan(&campaignID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return campaignID, err
}

// isUniqueViolation recognises the name constraint: the code is the
// database's, the error the caller's.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
