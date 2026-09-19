package hosts

import (
	"context"
	"time"

	"github.com/ultherego/flotestro/internal/authz"
)

// The fleet-wide counts the module screens rest on.

// ScopeCondition renders the visibility of a host row for the given scopes:
// the condition of this package's ScopeSQL, or "true" for a caller who sees
// the whole fleet.
func ScopeCondition(scopes []authz.Scope, siteColumn, envColumn, teamColumn string, offset int) (string, []any) {
	condition, args := ScopeSQL(scopes, siteColumn, envColumn, teamColumn, offset)
	if condition == "" {
		return "true", nil
	}
	return condition, args
}

// ModuleCoverage says, for one inventory module, how much of the visible fleet
// has reported it: a screen that judges hosts by that module needs to say how
// many hosts it judged and how many it could not.
type ModuleCoverage struct {
	// Hosts is the number of hosts in scope.
	Hosts int
	// Observed counts the hosts with a fragment of the module and no
	// unavailability reason on it.
	Observed int
	// Unavailable counts the hosts whose fragment says the module could
	// not be read: an answer, but not a fact about the thing itself.
	Unavailable int
	// Stale counts the observed hosts whose fragment is older than the
	// read policy allows; it is a part of Observed, not a further group.
	Stale int
}

// Missing counts the hosts without any fragment of the module: the hosts
// nobody has heard from about it.
func (c ModuleCoverage) Missing() int {
	missing := c.Hosts - c.Observed - c.Unavailable
	if missing < 0 {
		return 0
	}
	return missing
}

// Unknown counts the hosts a screen must not describe as anything: the ones
// without a fragment, the ones whose module could not be read and the ones
// whose fragment is too old to trust.
func (c ModuleCoverage) Unknown() int {
	return c.Missing() + c.Unavailable + c.Stale
}

// Evaluated counts the hosts a screen may describe from the module: the
// observed ones with a fresh fragment.
func (c ModuleCoverage) Evaluated() int {
	return c.Observed - c.Stale
}

// ModuleCoverage counts the hosts in scope by the state of one module's
// fragment.
func (s *Store) ModuleCoverage(ctx context.Context, scopes []authz.Scope, module string,
	staleBefore time.Time) (ModuleCoverage, error) {
	args := []any{module, staleBefore}
	condition, extra := ScopeCondition(scopes, "h.site", "h.environment", "h.team_id", len(args))
	args = append(args, extra...)
	var coverage ModuleCoverage
	err := s.pool.QueryRow(ctx, `
		select count(*),
		       count(i.host_id) filter (where coalesce(i.unavailable_reason, '') = ''),
		       count(i.host_id) filter (where coalesce(i.unavailable_reason, '') <> ''),
		       count(i.host_id) filter (where coalesce(i.unavailable_reason, '') = '' and i.observed_at < $2)
		from hosts h
		left join host_module_inventory i on i.host_id = h.id and i.module = $1
		where `+condition, args...).
		Scan(&coverage.Hosts, &coverage.Observed, &coverage.Unavailable, &coverage.Stale)
	return coverage, err
}
