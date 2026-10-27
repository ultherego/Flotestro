package adminapi

import (
	"net/http"

	"github.com/ultherego/flotestro/internal/authz"
)

// FleetCapabilities says, per technology, how the visible fleet divides: the hosts that
// have it, the hosts that reported it and cannot use it, and the hosts that never said.
type FleetCapabilities struct {
	// Total is the number of visible hosts that are not retired.
	Total int `json:"total"`
	// Items has one entry for every adapter any host reported.
	Items []FleetCapability `json:"items"`
}

// FleetCapability is one technology across the fleet.
type FleetCapability struct {
	Name      string `json:"name"`
	Available int    `json:"available"`
	Missing   int    `json:"missing"`
	// Unknown is the hosts that never reported the adapter; it is not a count of hosts without it.
	Unknown int `json:"unknown"`
	// Reasons are the most common reasons hosts give for not having it.
	Reasons []Facet `json:"reasons"`
}

func (s *Server) handleFleetCapabilities(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermHostRead, "fleet")
	if !ok {
		return
	}
	condition, args := authz.ScopeSQL(principal.ScopesFor(authz.PermHostRead), authz.HostColumns("h"), 0)
	visible := "true"
	if condition != "" {
		visible = condition
	}
	ctx := r.Context()
	result := FleetCapabilities{Items: []FleetCapability{}}

	if err := s.pool.QueryRow(ctx,
		`select count(*) from hosts h where h.lifecycle_state <> 'retired' and (`+visible+`)`, args...,
	).Scan(&result.Total); err != nil {
		s.fail(w, err)
		return
	}

	rows, err := s.pool.Query(ctx, `
		select r.name, count(*) filter (where r.available), count(*) filter (where not r.available)
		from host_capability_registry r join hosts h on h.id = r.host_id
		where h.lifecycle_state <> 'retired' and (`+visible+`)
		group by r.name order by r.name`, args...)
	if err != nil {
		s.fail(w, err)
		return
	}
	byName := map[string]int{}
	for rows.Next() {
		var item FleetCapability
		if err := rows.Scan(&item.Name, &item.Available, &item.Missing); err != nil {
			rows.Close()
			s.fail(w, err)
			return
		}
		item.Unknown = result.Total - item.Available - item.Missing
		item.Reasons = []Facet{}
		byName[item.Name] = len(result.Items)
		result.Items = append(result.Items, item)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		s.fail(w, err)
		return
	}

	reasons, err := s.pool.Query(ctx, `
		select name, reason, n from (
			select r.name, coalesce(nullif(r.reason, ''), '-') as reason, count(*) as n,
			       row_number() over (partition by r.name order by count(*) desc, r.reason) as rank
			from host_capability_registry r join hosts h on h.id = r.host_id
			where not r.available and h.lifecycle_state <> 'retired' and (`+visible+`)
			group by r.name, r.reason) ranked
		where rank <= 3 order by name, n desc`, args...)
	if err != nil {
		s.fail(w, err)
		return
	}
	for reasons.Next() {
		var name, reason string
		var n int
		if err := reasons.Scan(&name, &reason, &n); err != nil {
			reasons.Close()
			s.fail(w, err)
			return
		}
		if index, found := byName[name]; found {
			result.Items[index].Reasons = append(result.Items[index].Reasons, Facet{Key: reason, Count: n})
		}
	}
	reasons.Close()
	if err := reasons.Err(); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}
