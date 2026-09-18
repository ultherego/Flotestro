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
// tile leads to the hosts it counted. Each yes-or-no filter takes true or
// false, and a value that is neither is refused rather than read as one of
// them. The answer has been written when the result is false.
//
// The team filter is read here too, because this is the hook the fleet
// list hands the query to. It narrows within what the caller may see and
// never beyond it: the boundary is the scope condition the store applies
// to every listing, and a filter cannot lift it.
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
	// The relay is a typed column: an identifier that is not one would
	// fail in the database and come back as a server fault, when it is
	// the request that is wrong. A relay that does not exist is a valid
	// question with an empty answer.
	if relay := strings.TrimSpace(query.Get("relay")); relay != "" {
		if _, err := uuid.Parse(relay); err != nil {
			problem(w, http.StatusBadRequest, "invalid_filter", "relay must be a relay identifier")
			return false
		}
		filter.Relay = relay
	}
	// The team is a typed column, like the relay: an identifier that is
	// not one would come back as a server fault when it is the request
	// that is wrong. The word "none" asks for the other list - the hosts
	// nobody has placed in a team yet, which after the migration is every
	// host in the installation.
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
	// A domain name is matched as an operator recorded it; a name that
	// could not have been recorded is refused for the same reason it
	// could not be set.
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
//
// A screen of the whole fleet says three numbers before any other: how
// many hosts it covers, how many of them it judged, and how many it could
// not - the hosts without the fact, with a stale one, or without the
// adapter that reports it. An unknown host is never a zero: a fleet of a
// thousand hosts with findings on nine hundred and nothing known about the
// rest is a different fleet from one with a hundred clean hosts. When the
// answer is not complete the view says so outright, with a stable reason,
// and the screen shows a badge rather than a plausible number.
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

// fleetSweepBudget bounds the time one request spends judging the fleet
// host by host in the panel. The compliance checks and the trust store
// are judged from the inventory in Go, not counted by the database, so a
// fleet of ten thousand hosts is a sweep; the sweep stops at the budget
// and says so, rather than holding the socket until a proxy closes it and
// the screen shows nothing at all.
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
// (hostname, id), a page at a time, with the inventory fragments of the
// named modules. The visit stops the sweep by answering false; the sweep
// stops itself at fleetSweepBudget and reports a partial result. A store
// error ends the sweep with the error: a fleet judged from half its facts
// is not a fleet judged.
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

// fleetFragments reads the fragments of the named modules for many hosts
// at once. A sweep reads only the modules its checks compute from: the
// package list of a host is the largest fragment by far and no check
// reads it, so loading it for five hundred hosts a page would cost the
// panel the memory of the whole fleet's package lists for nothing.
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
