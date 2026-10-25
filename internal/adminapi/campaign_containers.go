package adminapi

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/opspec"
)

// A campaign that names a container names it once, and the hosts that qualify for it - the
// ones with the capability - are not the hosts that run it. The panel does not know which do:
// the routine inventory carries the number of containers of a host, not their names, and the
// names come only from a full read of the engine. What it can say is what the last full read
// of each host said, how old that is, and that everything else is settled on the host itself,
// when the order arrives, where a host without the container is skipped.

// containerEvidenceMaxAge is how old the full read of a host may be to count as
// evidence of what is on it; an older read says nothing either way.
const containerEvidenceMaxAge = 24 * time.Hour

// containerOrderName is the name a start, stop or restart addresses its container by, or
// empty when the order names an identifier, which belongs to one host.
func containerOrderName(action opspec.ActionType, payload opspec.Payload) string {
	switch action {
	case opspec.ActionDockerStart, opspec.ActionDockerStop, opspec.ActionDockerRestart:
		if payload.DockerContainer.AddressedByName() {
			return payload.DockerContainer.Name
		}
	}
	return ""
}

// containerEvidence sorts the hosts by what their last full read of the engine says of
// a container of this name.
type containerEvidence struct {
	Present, Absent, Unknown []hosts.Host
	// Oldest is the oldest read that was taken for evidence.
	Oldest *time.Time
}

// containerPresence reads, for the given hosts, whether the last full read of the engine lists
// a container with this exact name. A host with no read, a read older than
// containerEvidenceMaxAge, or a read of an engine that was not available, is unknown: an
// engine that was not read has not been shown to lack the container.
func (s *Server) containerPresence(ctx context.Context, ready []hosts.Host, name string) (containerEvidence, error) {
	evidence := containerEvidence{}
	if len(ready) == 0 {
		return evidence, nil
	}
	ids := make([]string, 0, len(ready))
	for _, host := range ready {
		ids = append(ids, host.ID)
	}
	rows, err := s.hosts.Pool().Query(ctx, `
		select i.host_id::text, i.observed_at,
		       coalesce(i.unavailable_reason, '') <> ''
		       or coalesce(i.payload->'summary'->>'unavailable_reason', '') <> '',
		       exists (select 1 from jsonb_array_elements(coalesce(i.payload->'containers', '[]'::jsonb)) c
		                where c->>'name' = $2)
		  from host_module_inventory i
		 where i.module = 'containers.full' and i.host_id = any($1::uuid[])`, ids, name)
	if err != nil {
		return evidence, err
	}
	type reading struct {
		observed    time.Time
		unavailable bool
		present     bool
	}
	readings := map[string]reading{}
	defer rows.Close()
	for rows.Next() {
		var id string
		var one reading
		if err := rows.Scan(&id, &one.observed, &one.unavailable, &one.present); err != nil {
			return evidence, err
		}
		readings[id] = one
	}
	if err := rows.Err(); err != nil && err != pgx.ErrNoRows {
		return evidence, err
	}
	now := time.Now()
	for _, host := range ready {
		one, read := readings[host.ID]
		switch {
		case !read || one.unavailable || now.Sub(one.observed) > containerEvidenceMaxAge:
			evidence.Unknown = append(evidence.Unknown, host)
			continue
		case one.present:
			evidence.Present = append(evidence.Present, host)
		default:
			evidence.Absent = append(evidence.Absent, host)
		}
		if evidence.Oldest == nil || one.observed.Before(*evidence.Oldest) {
			observed := one.observed
			evidence.Oldest = &observed
		}
	}
	return evidence, nil
}

// ordered puts the hosts on which the container was seen first, the unknown ones next and the
// ones on which it was not seen last, each group in the order it came: the canary is then a host
// that has the container, whenever the panel has any evidence of one.
func (e containerEvidence) ordered() []hosts.Host {
	out := make([]hosts.Host, 0, len(e.Present)+len(e.Unknown)+len(e.Absent))
	out = append(out, e.Present...)
	out = append(out, e.Unknown...)
	out = append(out, e.Absent...)
	return out
}

// summary is what the preview says: how many hosts have the capability is already
// in "eligible"; this is how many of them are known to have the container.
func (e containerEvidence) summary(name string) map[string]any {
	group := func(list []hosts.Host) map[string]any {
		return map[string]any{"count": len(list), "sample": hostNames(list[:min(len(list), previewSampleSize)])}
	}
	out := map[string]any{
		"name":                      name,
		"present":                   group(e.Present),
		"absent":                    group(e.Absent),
		"unknown":                   group(e.Unknown),
		"evidence_max_age_seconds":  int(containerEvidenceMaxAge.Seconds()),
		"settled_on_the_host":       true,
		"skipped_when_not_found_as": "container_not_found",
	}
	if e.Oldest != nil {
		out["oldest_read_at"] = e.Oldest.UTC().Format(time.RFC3339)
	}
	return out
}
