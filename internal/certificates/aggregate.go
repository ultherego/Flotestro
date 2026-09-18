package certificates

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/paging"
)

// The fleet screen, counted by the database.
//
// The certificates a host reports live in its inventory fragment as a
// JSON list. The screen used to read the fragments of the first five
// hundred hosts and count in the panel; on a bigger fleet it showed a
// wrong number with nothing to say it was wrong. The queries here unnest
// the lists of every host in scope and let the database count the
// states, the timeline and the hosts, and hand the rows out a page at a
// time by a key that does not move under the reader.

// Module is the inventory module the certificate facts come from.
const Module = "certificates"

// The size of a page of the fleet list: what a screen gets without
// asking, and the most it may ask for.
const (
	DefaultPage = 100
	MaxPage     = 500
)

// FleetSummary is what the database counted over the visible fleet.
type FleetSummary struct {
	// Hosts is the number of hosts in scope.
	Hosts int
	// Observed counts the hosts with a readable certificates fragment;
	// Unavailable those whose fragment says the module could not be read;
	// Stale the observed ones whose fragment is older than MaxReadAge.
	Observed    int
	Unavailable int
	Stale       int
	// WithoutCertificates counts the observed hosts that report an empty
	// list: a host nobody has pointed at a path yet, not a host without
	// certificates.
	WithoutCertificates int
	// Certificates is the number of rows the list has across every page.
	Certificates int
	// Counts is the number of certificates in every state of State.
	Counts map[string]int
	// Timeline groups the certificates by the time they have left: the
	// buckets of TimelineBuckets, in that order.
	Timeline map[string]int
}

// TimelineBuckets names the buckets of the expiry timeline in the order
// the screen shows them.
var TimelineBuckets = []string{"expired", "7 days", "30 days", "90 days", "later", "no expiry"}

// scopeCondition renders the visibility of a host row; an empty scope
// list sees nothing.
func scopeCondition(scopes []authz.Scope, offset int) (string, []any) {
	condition, args := authz.ScopeSQL(scopes, "h.site", "h.environment", offset)
	if condition == "" {
		return "true", nil
	}
	return condition, args
}

// leafSQL unnests the certificate lists of the hosts in scope. Every row
// is one certificate of one host with the date and the reason the
// assessment reads; the host columns come along for the list.
const leafSQL = `
	with scoped as (
		select h.id, h.hostname from hosts h where %s
	),
	observed as (
		select s.id as host_id, s.hostname, i.payload, i.observed_at,
		       coalesce(i.unavailable_reason, '') as reason
		from scoped s
		join host_module_inventory i on i.host_id = s.id and i.module = '` + Module + `'
	),
	leaf as (
		select o.host_id, o.hostname, c.item,
		       (c.item->>'not_after')::timestamptz as not_after,
		       coalesce(c.item->>'path', '') as path,
		       coalesce(c.item->>'unavailable_reason', '') as reason
		from observed o
		cross join lateral jsonb_array_elements(coalesce(o.payload->'certificates', '[]'::jsonb)) as c(item)
		where o.reason = ''
	)`

// FleetSummary counts the certificates of the visible fleet at the
// moment now. The thresholds are the ones of State, so a certificate
// counted here as critical is the one the host tab calls critical.
func (s *Store) FleetSummary(ctx context.Context, scopes []authz.Scope, now time.Time) (FleetSummary, error) {
	args := []any{
		now, now.Add(CriticalThreshold), now.Add(WarningThreshold),
		now.Add(90 * 24 * time.Hour), now.Add(-MaxReadAge),
	}
	condition, extra := scopeCondition(scopes, len(args))
	args = append(args, extra...)
	query := fmt.Sprintf(leafSQL, condition) + `
		select
			(select count(*) from scoped),
			(select count(*) from observed where reason = ''),
			(select count(*) from observed where reason <> ''),
			(select count(*) from observed where reason = '' and observed_at < $5),
			(select count(*) from observed o where o.reason = ''
			    and not exists (select 1 from leaf l where l.host_id = o.host_id)),
			count(*),
			count(*) filter (where reason <> '' or not_after is null),
			count(*) filter (where reason = '' and not_after <= $1),
			count(*) filter (where reason = '' and not_after > $1 and not_after <= $2),
			count(*) filter (where reason = '' and not_after > $2 and not_after <= $3),
			count(*) filter (where reason = '' and not_after > $3),
			count(*) filter (where not_after is null),
			count(*) filter (where not_after <= $1),
			count(*) filter (where not_after > $1 and not_after <= $2),
			count(*) filter (where not_after > $2 and not_after <= $3),
			count(*) filter (where not_after > $3 and not_after <= $4),
			count(*) filter (where not_after > $4)
		from leaf`
	summary := FleetSummary{Counts: map[string]int{}, Timeline: map[string]int{}}
	var unknown, expired, critical, warning, valid int
	var noExpiry, tExpired, t7, t30, t90, later int
	if err := s.pool.QueryRow(ctx, query, args...).Scan(
		&summary.Hosts, &summary.Observed, &summary.Unavailable, &summary.Stale,
		&summary.WithoutCertificates, &summary.Certificates,
		&unknown, &expired, &critical, &warning, &valid,
		&noExpiry, &tExpired, &t7, &t30, &t90, &later); err != nil {
		return summary, err
	}
	summary.Counts[StateUnknown] = unknown
	summary.Counts[StateExpired] = expired
	summary.Counts[StateCritical] = critical
	summary.Counts[StateWarning] = warning
	summary.Counts[StateValid] = valid
	summary.Timeline["expired"] = tExpired
	summary.Timeline["7 days"] = t7
	summary.Timeline["30 days"] = t30
	summary.Timeline["90 days"] = t90
	summary.Timeline["later"] = later
	summary.Timeline["no expiry"] = noExpiry
	return summary, nil
}

// FleetRow is one certificate of the fleet list: the host it stands on
// and the certificate as the host reported it, for the caller to read
// with the module's own type.
type FleetRow struct {
	HostID      string
	Hostname    string
	Certificate json.RawMessage
}

// FleetCursor is the key of the last row of a page: the expiry, the host
// and the path, in the order of the list. A certificate without an expiry
// sorts last, under the key "infinity", which the database reads as the
// timestamp after every other.
type FleetCursor struct {
	NotAfter string
	Hostname string
	HostID   string
	Path     string
	Set      bool
}

// noExpiryKey is the sort key of a certificate without a date.
const noExpiryKey = "infinity"

// ParseFleetCursor reads a cursor issued by FleetPage; an empty value is
// the first page. A key that is not a timestamp or a host identifier is
// refused before it reaches the database.
func ParseFleetCursor(value string) (FleetCursor, error) {
	parts, err := paging.Decode(value, 4)
	if err != nil {
		return FleetCursor{}, err
	}
	if parts == nil {
		return FleetCursor{}, nil
	}
	if parts[0] != noExpiryKey {
		if _, err := paging.ParseTime(parts[0]); err != nil {
			return FleetCursor{}, err
		}
	}
	if _, err := uuid.Parse(parts[2]); err != nil {
		return FleetCursor{}, fmt.Errorf("%w: %v", paging.ErrInvalidCursor, err)
	}
	return FleetCursor{NotAfter: parts[0], Hostname: parts[1], HostID: parts[2], Path: parts[3], Set: true}, nil
}

// String renders the cursor for the next request.
func (c FleetCursor) String() string {
	return paging.Encode(c.NotAfter, c.Hostname, c.HostID, c.Path)
}

// FleetPage reads one page of the certificates of the visible fleet,
// the nearest expiry first and the certificates without a date last. The
// next cursor is empty on the last page.
func (s *Store) FleetPage(ctx context.Context, scopes []authz.Scope, cursor FleetCursor, limit int) ([]FleetRow, string, error) {
	// A caller asking for more than a page may hold gets the page, not the
	// default: it then pages on with the cursor rather than quietly
	// receiving a fifth of what it asked for.
	limit = paging.Limit(limit, DefaultPage, MaxPage)
	condition, args := scopeCondition(scopes, 0)
	query := fmt.Sprintf(leafSQL, condition) + `
		select host_id::text, hostname, item from leaf`
	if cursor.Set {
		args = append(args, cursor.NotAfter, cursor.Hostname, cursor.HostID, cursor.Path)
		query += fmt.Sprintf(` where (coalesce(not_after, 'infinity'::timestamptz), hostname, host_id, path)
		       > ($%d::timestamptz, $%d, $%d::uuid, $%d)`, len(args)-3, len(args)-2, len(args)-1, len(args))
	}
	// One row more than the page says whether there is a next page
	// without a second count.
	args = append(args, limit+1)
	query += fmt.Sprintf(` order by coalesce(not_after, 'infinity'::timestamptz), hostname, host_id, path limit $%d`, len(args))

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	result := []FleetRow{}
	for rows.Next() {
		var row FleetRow
		if err := rows.Scan(&row.HostID, &row.Hostname, &row.Certificate); err != nil {
			return nil, "", err
		}
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	if len(result) <= limit {
		return result, "", nil
	}
	result = result[:limit]
	return result, cursorAfter(result[limit-1]).String(), nil
}

// cursorAfter is the key of a row, read from the certificate the way
// the query reads it: the date cast from the same text and the same
// path, so the next page starts right after this row.
func cursorAfter(row FleetRow) FleetCursor {
	var certificate struct {
		NotAfter *time.Time `json:"not_after"`
		Path     string     `json:"path"`
	}
	_ = json.Unmarshal(row.Certificate, &certificate)
	cursor := FleetCursor{NotAfter: noExpiryKey, Hostname: row.Hostname, HostID: row.HostID, Path: certificate.Path, Set: true}
	if certificate.NotAfter != nil {
		cursor.NotAfter = paging.FormatTime(*certificate.NotAfter)
	}
	return cursor
}
