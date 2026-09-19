// Package reports computes the management reports of the panel: the patch
// status of the fleet, the campaigns of a period and the compliance with the
// declared policies.
package reports

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ultherego/flotestro/internal/authz"
)

// Store computes the reports over the panel's tables.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore opens the store on the pool.
func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// Period is the window of a report: From inclusive, To exclusive, both in UTC.
type Period struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}

// Filter narrows a report to a part of the fleet.
type Filter struct {
	Site        string
	Environment string
	Scopes      []authz.Scope
}

// hostClause renders the filter as a condition over the alias h, numbered from
// the parameter after offset.
func hostClause(filter Filter, offset int) (string, []any) {
	var conditions []string
	var args []any
	add := func(column, value string) {
		if value == "" {
			return
		}
		args = append(args, value)
		conditions = append(conditions, fmt.Sprintf("%s = $%d", column, offset+len(args)))
	}
	add("h.site", filter.Site)
	add("h.environment", filter.Environment)
	condition, extra := authz.ScopeSQL(filter.Scopes, "h.site", "h.environment", offset+len(args))
	if condition != "" {
		conditions = append(conditions, condition)
		args = append(args, extra...)
	}
	if len(conditions) == 0 {
		return "true", nil
	}
	return "(" + strings.Join(conditions, " and ") + ")", args
}

// groupKeys are the columns a breakdown may group by, named by the
// reader and resolved here, so a group key never reaches the SQL as text.
var groupKeys = map[string]string{
	"site":        "h.site",
	"environment": "h.environment",
}

// sortedKeys lists the keys of a breakdown in their order, so a report
// reads the same twice.
func sortedKeys[V any](groups map[string]V) []string {
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
