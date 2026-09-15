// Package reports computes the management reports of the panel: the
// patch status of the fleet, the campaigns of a period and the compliance
// with the declared policies.
//
// A report is a read over the records the panel already keeps - the host
// facts, the tasks, the campaign targets, the policy verdicts - narrowed
// to a period and to what the reader may see. Nothing is estimated in the
// browser and nothing is stored: the same question asked twice gives the
// same answer, computed in the database each time, so a report never
// drifts from the screens it summarises.
//
// The counts follow the doctrine of the host facts: a host that has not
// reported a fact is counted as unknown, not as a zero. A fleet with ten
// hosts of which two never reported their security updates is "eight
// patched, two unknown", never "ten patched".
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

// Period is the window of a report: From inclusive, To exclusive, both in
// UTC. What "in the period" means is said by each report: a task that
// finished in it, a campaign that closed in it.
type Period struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}

// Filter narrows a report to a part of the fleet. Site and Environment
// are the operator's choice; Scopes are what the reader may see, and a
// nil list sees nothing - not knowing the scope must not widen a report.
type Filter struct {
	Site        string
	Environment string
	Scopes      []authz.Scope
}

// hostClause renders the filter as a condition over the alias h, numbered
// from the parameter after offset. It is never empty: a reader without a
// scope gets "false" and an empty report, not the whole fleet.
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
