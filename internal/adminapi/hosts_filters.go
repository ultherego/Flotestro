package adminapi

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/inventory"
	"github.com/ultherego/flotestro/internal/paging"
)

// attentionFilters reads the "needs attention" filters of the host list into
// the filter: the ones a dashboard tile links here with, so the count on the
// tile leads to the hosts it counted.
func attentionFilters(w http.ResponseWriter, query url.Values, filter *hosts.ListFilter) bool {
	flags := []struct {
		name   string
		target **bool
	}{
		{"failed_units", &filter.FailedUnits},
		{"package_db_broken", &filter.PackageDatabaseBroken},
		{"sssd_offline", &filter.SSSDOffline},
		{"agent_behind", &filter.AgentBehind},
	}
	for _, flag := range flags {
		value := query.Get(flag.name)
		if value == "" {
			continue
		}
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			problem(w, http.StatusBadRequest, "invalid_filter", flag.name+" must be true or false")
			return false
		}
		*flag.target = &parsed
	}
	// The relay is a typed column: an identifier that is not one would fail in
	// the database and come back as a server fault, when it is the request that
	// is wrong.
	if relay := strings.TrimSpace(query.Get("relay")); relay != "" {
		if _, err := uuid.Parse(relay); err != nil {
			problem(w, http.StatusBadRequest, "invalid_filter", "relay must be a relay identifier")
			return false
		}
		filter.Relay = relay
	}
	// The team is a typed column, like the relay: an identifier that is not one
	// would come back as a server fault when it is the request that is wrong.
	if team := strings.TrimSpace(query.Get("team")); team != "" {
		switch {
		case team == "none":
			filter.TeamUnassigned = true
		case hosts.ValidTeamID(team):
			filter.Team = team
		default:
			problem(w, http.StatusBadRequest, "invalid_filter",
				"team must be a team identifier or none")
			return false
		}
	}
	// A domain name is matched as an operator recorded it; a name that could not
	// have been recorded is refused for the same reason it could not be set.
	if domain := query.Get("failure_domain"); domain != "" {
		normalized, err := hosts.NormalizeFailureDomain(domain)
		if err != nil {
			problem(w, http.StatusBadRequest, "invalid_filter", err.Error())
			return false
		}
		filter.FailureDomain = normalized
	}
	return true
}

// The head of every fleet view.
type fleetCoverage struct {
	TotalHosts     int  `json:"total_hosts"`
	EvaluatedHosts int  `json:"evaluated_hosts"`
	UnknownHosts   int  `json:"unknown_hosts"`
	Partial        bool `json:"partial"`
	// PartialReason is one of the partial* codes when Partial is set.
	PartialReason string `json:"partial_reason,omitempty"`
	// UnknownReasons counts the unknown hosts by why they are unknown,
	// where the view can tell.
	UnknownReasons map[string]int `json:"unknown_reasons,omitempty"`
}

// The reasons a fleet view answers with a part of the fleet.
const (
	// partialTimeBudget means the sweep ran out of its time budget before
	// the last host; the hosts not reached are counted as unknown.
	partialTimeBudget = "time_budget"
	// partialCapReached means a cap on rows ended the answer before its
	// last row.
	partialCapReached = "cap_reached"
)

// The reasons a host is unknown to a fleet view.
const (
	unknownNoObservation    = "no_observation"
	unknownUnavailable      = "unavailable"
	unknownStaleObservation = "stale_observation"
	unknownNotReached       = "not_reached"
	unknownNoDefinition     = "no_definition"
	unknownNoAssessment     = "no_assessment"
)

// The page of a fleet view's rows: what a screen gets without asking and
// the most it may ask for. Beyond that a caller pages on with the cursor.
const (
	fleetPageDefault = 100
	fleetPageMax     = 500
)

// parseFleetPage reads the page size and the cursor of a fleet view. The
// answer has been written when the result is false.
func parseFleetPage(w http.ResponseWriter, r *http.Request) (limit int, cursor string, ok bool) {
	requested, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if r.URL.Query().Get("limit") != "" && (err != nil || requested < 0) {
		problem(w, http.StatusBadRequest, "invalid_limit", "limit must be a positive whole number")
		return 0, "", false
	}
	return paging.Limit(requested, fleetPageDefault, fleetPageMax), r.URL.Query().Get("cursor"), true
}

// invalidCursor refuses a cursor that did not come from this list.
func invalidCursor(w http.ResponseWriter, err error) {
	problem(w, http.StatusBadRequest, "invalid_cursor", "the cursor did not come from this list: "+err.Error())
}

// fleetSweepBudget bounds the time one request spends judging the fleet host
// by host in the panel.
const fleetSweepBudget = 20 * time.Second

// fleetSweep is the outcome of one sweep over the fleet.
type fleetSweep struct {
	// Swept counts the hosts the sweep visited.
	Swept int
	// Partial says the sweep did not reach the last host in scope, and
	// Reason why.
	Partial bool
	Reason  string
	// LastName and LastID key the last host visited, for a caller that
	// pages the sweep with a cursor.
	LastName string
	LastID   string
}

// sweepFleet visits every host of the filter in the order of the key
// (hostname, id), a page at a time, with the inventory fragments of the named
// modules.
func (s *Server) sweepFleet(ctx context.Context, filter hosts.ListFilter, afterName, afterID string,
	modules []string, visit func(host hosts.Host, fragments []inventory.Fragment) bool) (fleetSweep, error) {
	deadline := time.Now().Add(fleetSweepBudget)
	var sweep fleetSweep
	for {
		page, err := s.hosts.Page(ctx, filter, afterName, afterID, hosts.PageSize)
		if err != nil {
			return sweep, err
		}
		if len(page) == 0 {
			return sweep, nil
		}
		fragments, err := s.fleetFragments(ctx, hostIDs(page), modules)
		if err != nil {
			return sweep, err
		}
		for _, host := range page {
			sweep.Swept++
			sweep.LastName, sweep.LastID = host.Hostname, host.ID
			if !visit(host, fragments[host.ID]) {
				return sweep, nil
			}
		}
		if len(page) < hosts.PageSize {
			return sweep, nil
		}
		afterName, afterID = sweep.LastName, sweep.LastID
		if time.Now().After(deadline) {
			sweep.Partial, sweep.Reason = true, partialTimeBudget
			return sweep, nil
		}
	}
}

// fleetFragments reads the fragments of the named modules for many hosts at
// once.
func (s *Server) fleetFragments(ctx context.Context, ids, modules []string) (map[string][]inventory.Fragment, error) {
	result := map[string][]inventory.Fragment{}
	if len(ids) == 0 || len(modules) == 0 {
		return result, nil
	}
	rows, err := s.pool.Query(ctx, `
		select host_id, module, revision, source, payload, coalesce(unavailable_reason, ''), observed_at
		  from host_module_inventory
		 where host_id = any($1::uuid[]) and module = any($2)
		 order by host_id, module`, ids, modules)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var fragment inventory.Fragment
		if err := rows.Scan(&fragment.HostID, &fragment.Module, &fragment.Revision, &fragment.Source,
			&fragment.Payload, &fragment.UnavailableReason, &fragment.ObservedAt); err != nil {
			return nil, err
		}
		result[fragment.HostID] = append(result[fragment.HostID], fragment)
	}
	return result, rows.Err()
}
