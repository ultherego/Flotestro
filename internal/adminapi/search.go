package adminapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/ultherego/flotestro/internal/authz"
)

// The global search answers the command palette of the panel: the operator
// types a few characters and gets the things of the fleet those characters
// name, whatever their kind, each with the address of its page.

// searchItem is one hit of the search: what it is, what it is called and
// where its page is.
type searchItem struct {
	Kind     string `json:"kind"`
	ID       string `json:"id"`
	Title    string `json:"title"`
	Subtitle string `json:"subtitle"`
	Path     string `json:"path"`
}

// searchMinimum is the shortest query the search answers. One character
// names nearly everything, and the palette would show a random screenful.
const searchMinimum = 2

// searchLimitDefault and searchLimitMaximum bound the hits per kind; the
// palette shows a handful, and a longer query narrows the rest.
const (
	searchLimitDefault = 8
	searchLimitMaximum = 25
)

// jobIDPrefixMinimum is the shortest identifier prefix the search takes for a
// job: the first group of the identifier is eight characters, and a shorter
// one matches thousands of jobs in a fleet of any size.
const jobIDPrefixMinimum = 8

// cvePattern is a CVE identifier as the operator types it, in any case.
var cvePattern = regexp.MustCompile(`^(?i)cve-\d{4}-\d{4,}$`)

// jobIDPrefixPattern is the beginning of a job identifier: hexadecimal
// digits with the dashes of the canonical form, or without them.
var jobIDPrefixPattern = regexp.MustCompile(`^[0-9a-fA-F-]+$`)

// handleSearch answers GET /api/v1/search?q=<text>&limit=<n>.
func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	principal := authz.FromContext(r.Context())
	if !principal.Authenticated() {
		w.Header().Set("WWW-Authenticate", `Bearer realm="flotestro"`)
		problem(w, http.StatusUnauthorized, "unauthenticated", "no valid token")
		return
	}
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > searchLimitMaximum {
		limit = searchLimitDefault
	}
	items := []searchItem{}
	// A query too short to mean anything is answered with nothing rather than
	// refused: the palette asks on every keystroke, and an empty answer is what
	// an empty field deserves.
	if len([]rune(query)) < searchMinimum {
		writeJSON(w, http.StatusOK, map[string]any{"items": items})
		return
	}
	ctx := r.Context()
	// The kinds are asked in the order the palette shows them; each one is one
	// bounded query, and a kind the principal may not read costs nothing.
	for _, kind := range []func(context.Context, authz.Principal, string, int) ([]searchItem, error){
		s.searchHosts, s.searchCampaigns, s.searchJobs, s.searchPolicies, s.searchGroups,
		s.searchRelays, s.searchSecrets, s.searchPrincipals, s.searchCVEs,
	} {
		found, err := kind(ctx, principal, query, limit)
		if err != nil {
			s.fail(w, err)
			return
		}
		items = append(items, found...)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// namePrefixes returns the two LIKE patterns a name is matched with: the name
// begins with the text, or one of its words does.
func namePrefixes(query string) (string, string) {
	escaped := escapeLike(strings.ToLower(query))
	return escaped + "%", "% " + escaped + "%"
}

// escapeLike makes a typed text literal inside a LIKE pattern: a percent
// sign or an underscore in a name is a character, not a wildcard.
func escapeLike(value string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(value)
}

// nameCondition renders the name match over the column with the two
// patterns numbered from the offset.
func nameCondition(column string, offset int) string {
	return fmt.Sprintf("(lower(%[1]s) like $%[2]d or lower(%[1]s) like $%[3]d)", column, offset+1, offset+2)
}

// searchHosts finds the hosts by the beginning of the hostname, of the machine
// identifier or of the management address, in the scopes the principal reads
// hosts in.
func (s *Server) searchHosts(ctx context.Context, principal authz.Principal, query string, limit int) ([]searchItem, error) {
	if !principal.CanAnywhere(authz.PermHostRead) {
		return nil, nil
	}
	prefix, word := namePrefixes(query)
	args := []any{prefix, word}
	condition := "(" + nameCondition("h.hostname", 0) +
		fmt.Sprintf(" or lower(h.machine_id) like $1 or h.management_address like $%d)", len(args)+1)
	args = append(args, escapeLike(query)+"%")
	scope, scopeArgs := authz.ScopeSQL(principal.ScopesFor(authz.PermHostRead), "h.site", "h.environment", len(args))
	if scope != "" {
		condition += " and " + scope
		args = append(args, scopeArgs...)
	}
	args = append(args, limit)
	rows, err := s.pool.Query(ctx, `
		select h.id::text, h.hostname, coalesce(h.management_address, ''), h.site, h.environment,
		       h.connection_state, coalesce(h.os_family, ''), h.lifecycle_state
		  from hosts h
		 where `+condition+`
		 order by h.hostname, h.id
		 limit $`+strconv.Itoa(len(args)), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectSearch(rows, func(row pgx.Rows) (searchItem, error) {
		var id, hostname, address, site, environment, state, family, lifecycle string
		if err := row.Scan(&id, &hostname, &address, &site, &environment, &state, &family, &lifecycle); err != nil {
			return searchItem{}, err
		}
		subtitle := site + " / " + environment
		if address != "" {
			subtitle = address + " · " + subtitle
		}
		if family != "" {
			subtitle += " · " + family
		}
		subtitle += " · " + state
		// A host that is no longer active says so: the operator jumping to
		// a retired host by name should not mistake it for a live one.
		if lifecycle != "active" {
			subtitle += " · " + lifecycle
		}
		return searchItem{
			Kind: "host", ID: id, Title: hostname, Subtitle: subtitle,
			Path: "/hosts/" + id + "/overview",
		}, nil
	})
}

// searchCampaigns finds the campaigns by name, among those that touch a
// host of the principal's scope - the rule the campaign list follows.
func (s *Server) searchCampaigns(ctx context.Context, principal authz.Principal, query string, limit int) ([]searchItem, error) {
	if !principal.CanAnywhere(authz.PermCampaignRead) {
		return nil, nil
	}
	prefix, word := namePrefixes(query)
	args := []any{prefix, word}
	condition := nameCondition("c.name", 0)
	scope, scopeArgs := authz.ScopeSQL(principal.ScopesFor(authz.PermCampaignRead), "h.site", "h.environment", len(args))
	if scope != "" {
		condition += " and exists (select 1 from campaign_targets t join hosts h on h.id = t.host_id" +
			" where t.campaign_id = c.id and " + scope + ")"
		args = append(args, scopeArgs...)
	}
	args = append(args, limit)
	rows, err := s.pool.Query(ctx, `
		select c.id::text, c.name, c.state, c.action_type
		  from campaigns c
		 where `+condition+`
		 order by c.created_at desc
		 limit $`+strconv.Itoa(len(args)), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectSearch(rows, func(row pgx.Rows) (searchItem, error) {
		var id, name, state, action string
		if err := row.Scan(&id, &name, &state, &action); err != nil {
			return searchItem{}, err
		}
		return searchItem{
			Kind: "campaign", ID: id, Title: name, Subtitle: action + " · " + state,
			Path: "/campaigns/" + id,
		}, nil
	})
}

// jobIDRange turns the beginning of a job identifier into the two identifiers
// it lies between, so the primary key answers the question instead of a scan
// over the text of every identifier.
func jobIDRange(query string) (string, string, bool) {
	if !jobIDPrefixPattern.MatchString(query) {
		return "", "", false
	}
	digits := strings.ToLower(strings.ReplaceAll(query, "-", ""))
	if len(digits) < jobIDPrefixMinimum || len(digits) > 32 {
		return "", "", false
	}
	low := digits + strings.Repeat("0", 32-len(digits))
	high := digits + strings.Repeat("f", 32-len(digits))
	canonical := func(hex string) string {
		return hex[0:8] + "-" + hex[8:12] + "-" + hex[12:16] + "-" + hex[16:20] + "-" + hex[20:32]
	}
	return canonical(low), canonical(high), true
}

// searchJobs finds the jobs by the beginning of their identifier, in the
// scopes of the hosts the principal reads jobs on.
func (s *Server) searchJobs(ctx context.Context, principal authz.Principal, query string, limit int) ([]searchItem, error) {
	if !principal.CanAnywhere(authz.PermJobRead) {
		return nil, nil
	}
	low, high, ok := jobIDRange(query)
	if !ok {
		return nil, nil
	}
	args := []any{low, high}
	condition := "j.id >= $1::uuid and j.id <= $2::uuid"
	scope, scopeArgs := authz.ScopeSQL(principal.ScopesFor(authz.PermJobRead), "h.site", "h.environment", len(args))
	if scope != "" {
		condition += " and " + scope
		args = append(args, scopeArgs...)
	}
	args = append(args, limit)
	rows, err := s.pool.Query(ctx, `
		select j.id::text, j.action_type, j.state, h.hostname
		  from jobs j
		  join hosts h on h.id = j.host_id
		 where `+condition+`
		 order by j.created_at desc
		 limit $`+strconv.Itoa(len(args)), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectSearch(rows, func(row pgx.Rows) (searchItem, error) {
		var id, action, state, hostname string
		if err := row.Scan(&id, &action, &state, &hostname); err != nil {
			return searchItem{}, err
		}
		return searchItem{
			Kind: "job", ID: id, Title: action + " on " + hostname, Subtitle: id + " · " + state,
			Path: "/jobs/" + id,
		}, nil
	})
}

// searchPolicies finds the policies by name. A policy has no scope of its
// own, so the right to read policies anywhere is enough, as for the list.
func (s *Server) searchPolicies(ctx context.Context, principal authz.Principal, query string, limit int) ([]searchItem, error) {
	if !principal.CanAnywhere(authz.PermPolicyRead) {
		return nil, nil
	}
	prefix, word := namePrefixes(query)
	rows, err := s.pool.Query(ctx, `
		select p.id::text, p.name, p.version, p.enabled, p.remediation_mode
		  from policies p
		 where `+nameCondition("p.name", 0)+`
		 order by p.name
		 limit $3`, prefix, word, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectSearch(rows, func(row pgx.Rows) (searchItem, error) {
		var id, name, mode string
		var version int
		var enabled bool
		if err := row.Scan(&id, &name, &version, &enabled, &mode); err != nil {
			return searchItem{}, err
		}
		subtitle := mode
		if version == 0 {
			subtitle += " · draft"
		} else {
			subtitle += " · version " + strconv.Itoa(version)
		}
		if !enabled {
			subtitle += " · disabled"
		}
		return searchItem{Kind: "policy", ID: id, Title: name, Subtitle: subtitle, Path: "/policies/" + id}, nil
	})
}

// searchGroups finds the host groups by name, with the right the group
// list is read with.
func (s *Server) searchGroups(ctx context.Context, principal authz.Principal, query string, limit int) ([]searchItem, error) {
	if !principal.CanAnywhere(authz.PermHostRead) || s.groups == nil {
		return nil, nil
	}
	prefix, word := namePrefixes(query)
	rows, err := s.pool.Query(ctx, `
		select g.id::text, g.name, g.kind, g.description
		  from host_groups g
		 where `+nameCondition("g.name", 0)+`
		 order by g.name
		 limit $3`, prefix, word, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectSearch(rows, func(row pgx.Rows) (searchItem, error) {
		var id, name, kind, description string
		if err := row.Scan(&id, &name, &kind, &description); err != nil {
			return searchItem{}, err
		}
		subtitle := kind
		if description != "" {
			subtitle += " · " + description
		}
		return searchItem{Kind: "group", ID: id, Title: name, Subtitle: subtitle, Path: "/groups/" + id}, nil
	})
}

// relayScopeSQL renders the visibility of a relay the way the relay list
// decides it: a binding to the relay's site sees it, and a relay without an
// environment serves its whole site, so a binding to any environment of the
func relayScopeSQL(scopes []authz.Scope, offset int) (string, []any) {
	if len(scopes) == 0 {
		return "false", nil
	}
	var conditions []string
	var args []any
	for _, scope := range scopes {
		var parts []string
		switch scope.Site {
		case authz.Wildcard:
		case "":
			parts = append(parts, "false")
		default:
			args = append(args, scope.Site)
			parts = append(parts, fmt.Sprintf("r.site = $%d", offset+len(args)))
		}
		switch scope.Environment {
		case authz.Wildcard:
		case "":
			parts = append(parts, "r.environment is null")
		default:
			args = append(args, scope.Environment)
			parts = append(parts, fmt.Sprintf("(r.environment is null or r.environment = $%d)", offset+len(args)))
		}
		if len(parts) == 0 {
			return "", nil
		}
		conditions = append(conditions, "("+strings.Join(parts, " and ")+")")
	}
	return "(" + strings.Join(conditions, " or ") + ")", args
}

// searchRelays finds the relays by name, in the sites the principal may
// prepare installations in - the right the relay list is read with.
func (s *Server) searchRelays(ctx context.Context, principal authz.Principal, query string, limit int) ([]searchItem, error) {
	if s.relays == nil || !principal.CanAnywhere(authz.PermHostEnrollRead) {
		return nil, nil
	}
	prefix, word := namePrefixes(query)
	args := []any{prefix, word}
	condition := nameCondition("r.name", 0)
	if scope, scopeArgs := relayScopeSQL(principal.ScopesFor(authz.PermHostEnrollRead), len(args)); scope != "" {
		condition += " and " + scope
		args = append(args, scopeArgs...)
	}
	args = append(args, limit)
	rows, err := s.pool.Query(ctx, `
		select r.id::text, r.name, r.site, coalesce(r.environment, ''), r.revoked_at is not null
		  from relays r
		 where `+condition+`
		 order by r.name
		 limit $`+strconv.Itoa(len(args)), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectSearch(rows, func(row pgx.Rows) (searchItem, error) {
		var id, name, site, environment string
		var revoked bool
		if err := row.Scan(&id, &name, &site, &environment, &revoked); err != nil {
			return searchItem{}, err
		}
		subtitle := site
		if environment != "" {
			subtitle += " / " + environment
		}
		if revoked {
			subtitle += " · revoked"
		}
		return searchItem{Kind: "relay", ID: id, Title: name, Subtitle: subtitle, Path: "/relays/" + id}, nil
	})
}

// searchSecrets finds the secrets by name. Only the name travels, as in
// the list: the search is one more way to a page, not to a value.
func (s *Server) searchSecrets(ctx context.Context, principal authz.Principal, query string, limit int) ([]searchItem, error) {
	if s.secrets == nil || !principal.CanAnywhere(authz.PermSecretRead) {
		return nil, nil
	}
	prefix, word := namePrefixes(query)
	rows, err := s.pool.Query(ctx, `
		select s.name, s.current_version, s.retired_at is not null
		  from secrets s
		 where `+nameCondition("s.name", 0)+`
		 order by s.name
		 limit $3`, prefix, word, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectSearch(rows, func(row pgx.Rows) (searchItem, error) {
		var name string
		var version int
		var retired bool
		if err := row.Scan(&name, &version, &retired); err != nil {
			return searchItem{}, err
		}
		subtitle := "version " + strconv.Itoa(version)
		if retired {
			subtitle += " · retired"
		}
		return searchItem{Kind: "secret", ID: name, Title: name, Subtitle: subtitle, Path: "/secrets/" + name}, nil
	})
}

// searchPrincipals finds the identities by subject or display name, for
// whoever manages access - the identity list is read with the global right,
// and the search follows it.
func (s *Server) searchPrincipals(ctx context.Context, principal authz.Principal, query string, limit int) ([]searchItem, error) {
	if !principal.Can(authz.PermPrincipalManage, authz.GlobalScope) {
		return nil, nil
	}
	prefix, word := namePrefixes(query)
	rows, err := s.pool.Query(ctx, `
		select p.id::text, p.subject, p.display_name, p.kind,
		       p.disabled_at is not null, p.denied_at is not null
		  from principals p
		 where (`+nameCondition("p.subject", 0)+` or `+nameCondition("p.display_name", 0)+`)
		 order by p.subject
		 limit $3`, prefix, word, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectSearch(rows, func(row pgx.Rows) (searchItem, error) {
		var id, subject, displayName, kind string
		var disabled, denied bool
		if err := row.Scan(&id, &subject, &displayName, &kind, &disabled, &denied); err != nil {
			return searchItem{}, err
		}
		title := subject
		subtitle := kind
		if displayName != "" && displayName != subject {
			title = displayName
			subtitle = subject + " · " + kind
		}
		if disabled {
			subtitle += " · disabled"
		}
		if denied {
			subtitle += " · denied"
		}
		return searchItem{
			Kind: "principal", ID: id, Title: title, Subtitle: subtitle,
			Path: "/access?tab=identities&q=" + url.QueryEscape(subject),
		}, nil
	})
}

// searchCVEs answers a CVE identifier typed in full with the entry of the
// vulnerability feed, if the feed has it.
func (s *Server) searchCVEs(ctx context.Context, principal authz.Principal, query string, _ int) ([]searchItem, error) {
	if s.vulnerabilities == nil || !cvePattern.MatchString(query) || !principal.CanAnywhere(authz.PermVulnerabilityRead) {
		return nil, nil
	}
	cve := strings.ToUpper(query)
	var severity, summary string
	var score *float64
	err := s.pool.QueryRow(ctx, `
		select cvss_severity, summary, cvss_score
		  from vuln_cve_details
		 where cve = $1`, cve).Scan(&severity, &summary, &score)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var parts []string
	if severity != "" {
		parts = append(parts, strings.ToLower(severity))
	}
	if score != nil {
		parts = append(parts, "CVSS "+strconv.FormatFloat(*score, 'f', 1, 64))
	}
	if summary != "" {
		parts = append(parts, shorten(summary, 120))
	}
	return []searchItem{{
		Kind: "cve", ID: cve, Title: cve, Subtitle: strings.Join(parts, " · "),
		Path: "/vulnerabilities/" + cve,
	}}, nil
}

// collectSearch reads every row of a query into hits with the given
// reader, so the kinds share the loop rather than each repeating it.
func collectSearch(rows pgx.Rows, read func(pgx.Rows) (searchItem, error)) ([]searchItem, error) {
	var items []searchItem
	for rows.Next() {
		item, err := read(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// shorten cuts a text to the limit on a rune boundary, with an ellipsis.
func shorten(text string, limit int) string {
	runes := []rune(strings.TrimSpace(text))
	if len(runes) <= limit {
		return string(runes)
	}
	return strings.TrimSpace(string(runes[:limit])) + "…"
}
