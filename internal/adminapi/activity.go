package adminapi

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/ultherego/flotestro/internal/authz"
)

// FleetActivity feeds the widgets of the fleet screens: the operations
// finished per hour by outcome, and the composition of the fleet the viewer
// may see.
type FleetActivity struct {
	// Hours are the buckets, oldest first, each the start of the hour.
	Hours []time.Time `json:"hours"`
	// The operations that finished in each hour, by outcome.
	Succeeded []int `json:"succeeded"`
	Failed    []int `json:"failed"`
	Other     []int `json:"other"`
	// The composition of the visible fleet.
	ByOSFamily        []Facet `json:"by_os_family"`
	BySite            []Facet `json:"by_site"`
	ByEnvironment     []Facet `json:"by_environment"`
	ByAgentVersion    []Facet `json:"by_agent_version"`
	ByConnectionState []Facet `json:"by_connection_state"`
	ByLifecycleState  []Facet `json:"by_lifecycle_state"`
}

// Facet is one category and how many hosts fall into it.
type Facet struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

func (s *Server) handleFleetActivity(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermHostRead, "fleet")
	if !ok {
		return
	}
	scopes := principal.ScopesFor(authz.PermHostRead)
	condition, args := authz.ScopeSQL(scopes, "h.site", "h.environment", 0)
	visible := "true"
	if condition != "" {
		visible = condition
	}
	hours, _ := strconv.Atoi(r.URL.Query().Get("hours"))
	if hours <= 0 || hours > 24*14 {
		hours = 24
	}
	ctx := r.Context()
	activity := FleetActivity{
		Hours: make([]time.Time, 0, hours), Succeeded: make([]int, 0, hours),
		Failed: make([]int, 0, hours), Other: make([]int, 0, hours),
	}

	// One row per hour of the window, also the empty ones: a chart with a
	// hole where nothing happened would read as missing data.
	hourArgs := append(append([]any{}, args...), hours)
	rows, err := s.pool.Query(ctx, `
		with buckets as (
			select generate_series(date_trunc('hour', now()) - ($`+strconv.Itoa(len(hourArgs))+`::int - 1) * interval '1 hour',
			                       date_trunc('hour', now()), interval '1 hour') as hour)
		select b.hour,
		       count(j.id) filter (where j.result_status = 'succeeded'),
		       count(j.id) filter (where j.result_status in ('failed', 'timed_out', 'partially_applied')),
		       count(j.id) filter (where j.result_status is not null
		                             and j.result_status not in ('succeeded', 'failed', 'timed_out', 'partially_applied'))
		from buckets b
		left join jobs j on date_trunc('hour', j.finished_at) = b.hour
		left join hosts h on h.id = j.host_id
		where j.id is null or (`+visible+`)
		group by b.hour order by b.hour`, hourArgs...)
	if err != nil {
		s.fail(w, err)
		return
	}
	for rows.Next() {
		var hour time.Time
		var succeeded, failed, other int
		if err := rows.Scan(&hour, &succeeded, &failed, &other); err != nil {
			rows.Close()
			s.fail(w, err)
			return
		}
		activity.Hours = append(activity.Hours, hour.UTC())
		activity.Succeeded = append(activity.Succeeded, succeeded)
		activity.Failed = append(activity.Failed, failed)
		activity.Other = append(activity.Other, other)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		s.fail(w, err)
		return
	}

	facets := []struct {
		column string
		into   *[]Facet
	}{
		{"coalesce(nullif(h.os_family, ''), 'unknown')", &activity.ByOSFamily},
		{"h.site", &activity.BySite},
		{"h.environment", &activity.ByEnvironment},
		{"coalesce(nullif(h.agent_version, ''), 'unknown')", &activity.ByAgentVersion},
		{"h.connection_state", &activity.ByConnectionState},
		{"h.lifecycle_state", &activity.ByLifecycleState},
	}
	for _, facet := range facets {
		list, err := s.facet(ctx, facet.column, visible, args)
		if err != nil {
			s.fail(w, err)
			return
		}
		*facet.into = list
	}
	writeJSON(w, http.StatusOK, activity)
}

// facet counts the visible hosts by one column, largest first. Retired
// hosts are left out: they are history, not fleet.
func (s *Server) facet(ctx context.Context, column, visible string, args []any) ([]Facet, error) {
	rows, err := s.pool.Query(ctx, `
		select `+column+` as key, count(*) from hosts h
		where h.lifecycle_state <> 'retired' and (`+visible+`)
		group by 1 order by 2 desc, 1 limit 12`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []Facet{}
	for rows.Next() {
		var facet Facet
		if err := rows.Scan(&facet.Key, &facet.Count); err != nil {
			return nil, err
		}
		list = append(list, facet)
	}
	return list, rows.Err()
}
