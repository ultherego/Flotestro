package adminapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/hosts"
)

// The bulk edit of what the panel records about hosts by hand: tags, the
// owner, the failure domain, the placement and the maintenance window,
// applied to a selection of hosts at once.
//
// The route is the single routes in a loop, not a new kind of write: every
// host is judged the way its own route would judge it - the same
// permission in the host's own scope, the same checks on the values - and
// answered one by one. A selection of fifty hosts where three are out of
// the operator's scope is not refused as a whole and not applied
// silently on forty-seven: the forty-seven are changed, the three are
// answered with the code their own route would have given, and the caller
// reads the list. The values are checked once, before the first host,
// because a tag the tag editor would refuse is refused for every host.

// maxBulkHosts bounds one bulk edit. The fleet list selects a page, not
// the fleet; a larger selection is a campaign's job or several calls.
const maxBulkHosts = 1000

type hostsBulkMetadataRequest struct {
	HostIDs []string             `json:"host_ids"`
	Reason  string               `json:"reason"`
	Set     hostsBulkMetadataSet `json:"set"`
}

// hostsBulkMetadataSet is what changes on every host. A field left out
// leaves that fact alone; the pointer fields tell an empty value, which
// clears the fact, from an absent one.
type hostsBulkMetadataSet struct {
	// TagsAdd and TagsRemove are applied to what each host carries: a bulk
	// edit adds "patched=2026-09" to fifty hosts with fifty different tag
	// lists, so unlike the single route it cannot send whole lists.
	TagsAdd    []string `json:"tags_add,omitempty"`
	TagsRemove []string `json:"tags_remove,omitempty"`
	// Owner and FailureDomain replace the fact; an empty string clears it.
	Owner         *string `json:"owner,omitempty"`
	FailureDomain *string `json:"failure_domain,omitempty"`
	// Site and Environment move the hosts; one given without the other
	// keeps each host's current value of the other.
	Site        *string `json:"site,omitempty"`
	Environment *string `json:"environment,omitempty"`
	// Maintenance is a window to open on every host, or the JSON null to
	// close the windows. It is kept raw so that null can be told from
	// absent: absent leaves the windows alone.
	Maintenance json.RawMessage `json:"maintenance,omitempty"`
}

// bulkMaintenance is the window of a bulk edit: an end and a reason, the
// way the single route takes them.
type bulkMaintenance struct {
	Until           string `json:"until,omitempty"`
	DurationMinutes int    `json:"duration_minutes,omitempty"`
	Reason          string `json:"reason,omitempty"`
}

// bulkHostOutcome is the answer for one host. Code is the reason code the
// single route would have given on refusal, or "applied" on success, so a
// caller reads one list and not a mix of a list and errors.
type bulkHostOutcome struct {
	HostID string `json:"host_id"`
	OK     bool   `json:"ok"`
	Code   string `json:"code"`
	Detail string `json:"detail,omitempty"`
}

type hostsBulkMetadataResponse struct {
	Results []bulkHostOutcome `json:"results"`
	Applied int               `json:"applied"`
	Failed  int               `json:"failed"`
}

// bulkChange is the request after its values were checked: what the loop
// applies to each host.
type bulkChange struct {
	tagsAdd, tagsRemove  []string
	owner, failureDomain *string
	site, environment    *string
	// maintenanceSet says the window is touched; maintenanceUntil is nil
	// when it is to be closed.
	maintenanceSet    bool
	maintenanceUntil  *time.Time
	maintenanceReason string
	reason            string
}

// touchesFacts says whether the change needs the tag permission: any of
// the facts the single tag, owner, domain and placement routes guard.
func (c bulkChange) touchesFacts() bool {
	return len(c.tagsAdd) > 0 || len(c.tagsRemove) > 0 || c.owner != nil ||
		c.failureDomain != nil || c.site != nil || c.environment != nil
}

// handleBulkHostMetadata applies one change to a selection of hosts and
// answers for every host.
func (s *Server) handleBulkHostMetadata(w http.ResponseWriter, r *http.Request) {
	var request hostsBulkMetadataRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return
	}
	change, code, detail := parseBulkChange(request)
	if code != "" {
		problem(w, http.StatusBadRequest, code, detail)
		return
	}
	if len(request.HostIDs) == 0 {
		problem(w, http.StatusBadRequest, "hosts_required", "host_ids names no host")
		return
	}
	if len(request.HostIDs) > maxBulkHosts {
		problem(w, http.StatusBadRequest, "too_many_hosts",
			"a bulk edit covers at most 1000 hosts; split the selection")
		return
	}
	// The call as a whole needs the permission somewhere; each host then
	// needs it in its own scope. A principal with the right nowhere gets
	// the refusal once, not a thousand times in a list.
	permission := authz.PermHostTagWrite
	if !change.touchesFacts() {
		permission = authz.PermHostMaintenanceWrite
	}
	principal, ok := s.authorizeCollection(w, r, permission, "host")
	if !ok {
		return
	}

	// A host named twice is answered once: the second application would
	// re-add a tag just removed or record the move twice.
	hostIDs := slices.Compact(slices.Sorted(slices.Values(request.HostIDs)))
	response := hostsBulkMetadataResponse{Results: make([]bulkHostOutcome, 0, len(hostIDs))}
	for _, hostID := range hostIDs {
		outcome := s.applyBulkChange(r, principal, hostID, change)
		if outcome.OK {
			response.Applied++
		} else {
			response.Failed++
		}
		response.Results = append(response.Results, outcome)
	}
	writeJSON(w, http.StatusOK, response)
}

// parseBulkChange checks the values of the request the way the single
// routes check them, once for all the hosts. A code names the first
// problem; an empty code means a change ready to apply.
func parseBulkChange(request hostsBulkMetadataRequest) (bulkChange, string, string) {
	var change bulkChange
	change.reason = strings.TrimSpace(request.Reason)
	if len([]rune(change.reason)) < minimalStepUpReason {
		return change, "reason_required",
			"a bulk edit must state its reason (field reason, min. 8 characters)"
	}
	set := request.Set
	var err error
	if change.tagsAdd, err = hosts.NormalizeTags(set.TagsAdd); err != nil {
		return change, "invalid_tags", err.Error()
	}
	if change.tagsRemove, err = hosts.NormalizeTags(set.TagsRemove); err != nil {
		return change, "invalid_tags", err.Error()
	}
	if set.Owner != nil {
		owner, err := hosts.NormalizeOwner(*set.Owner)
		if err != nil {
			return change, "invalid_owner", err.Error()
		}
		change.owner = &owner
	}
	if set.FailureDomain != nil {
		domain, err := hosts.NormalizeFailureDomain(*set.FailureDomain)
		if err != nil {
			return change, "invalid_failure_domain", err.Error()
		}
		change.failureDomain = &domain
	}
	// The placement is checked against a stand-in for the field left out,
	// so that a site alone is checked as a site; each host fills in its
	// own other half at application time.
	if set.Site != nil || set.Environment != nil {
		site, environment := "default", "unassigned"
		if set.Site != nil {
			site = *set.Site
		}
		if set.Environment != nil {
			environment = *set.Environment
		}
		site, environment, err := hosts.NormalizePlacement(site, environment)
		if err != nil {
			return change, "invalid_placement", err.Error()
		}
		if set.Site != nil {
			change.site = &site
		}
		if set.Environment != nil {
			change.environment = &environment
		}
	}
	if len(set.Maintenance) > 0 {
		change.maintenanceSet = true
		if !bytes.Equal(bytes.TrimSpace(set.Maintenance), []byte("null")) {
			var window bulkMaintenance
			if err := json.Unmarshal(set.Maintenance, &window); err != nil {
				return change, "invalid_window", "maintenance must be an object with until or duration_minutes, or null"
			}
			deadline, err := windowDeadline(maintenanceWindowRequest{
				Until: window.Until, DurationMinutes: window.DurationMinutes,
			})
			if err != nil {
				return change, "invalid_window", err.Error()
			}
			change.maintenanceReason = strings.TrimSpace(window.Reason)
			if change.maintenanceReason == "" {
				return change, "reason_required",
					"a maintenance window needs a reason; it is what the next person on call will read"
			}
			change.maintenanceUntil = &deadline
		}
	}
	if !change.touchesFacts() && !change.maintenanceSet {
		return change, "nothing_to_set", "the set names no fact to change"
	}
	return change, "", ""
}

// applyBulkChange applies the change to one host and answers for it. The
// permission is judged in the host's own scope, exactly as the single
// route would; a refusal goes to the trail like any other refusal, with
// the host as its target, so the trail of a bulk edit reads as the trail
// of its single edits would.
func (s *Server) applyBulkChange(r *http.Request, principal authz.Principal, hostID string,
	change bulkChange) bulkHostOutcome {
	ctx := r.Context()
	host, err := s.hosts.Get(ctx, hostID)
	if errors.Is(err, hosts.ErrNotFound) {
		return bulkHostOutcome{HostID: hostID, Code: "host_not_found", Detail: "no such host"}
	}
	if err != nil {
		s.log.Error("bulk metadata: reading the host failed", "host", hostID, "err", err)
		return bulkHostOutcome{HostID: hostID, Code: "internal_error", Detail: "internal error"}
	}
	scope := hosts.ScopeOf(host)
	target := scope
	if change.site != nil {
		target.Site = *change.site
	}
	if change.environment != nil {
		target.Environment = *change.environment
	}
	needed := []authz.Permission{}
	if change.touchesFacts() {
		needed = append(needed, authz.PermHostTagWrite)
	}
	if change.maintenanceSet {
		needed = append(needed, authz.PermHostMaintenanceWrite)
	}
	for _, permission := range needed {
		// The destination of a move is judged like its origin.
		for _, where := range []authz.Scope{scope, target} {
			if principal.Can(permission, where) {
				continue
			}
			s.audit.Record(ctx, audit.Event{
				ActorType: audit.ActorUser, ActorID: principal.Subject,
				Action: string(permission), TargetType: "host", TargetID: hostID,
				RequestID: requestIDOf(r), Outcome: audit.OutcomeDenied,
				Detail: map[string]any{
					"reason": "permission_denied", "permission": string(permission),
					"scope": where.String(), "roles": principal.Roles(), "bulk": true,
				},
			})
			return bulkHostOutcome{HostID: hostID, Code: "permission_denied",
				Detail: "missing permission " + string(permission) + " in scope " + where.String()}
		}
	}

	before := bulkFacts(host)
	updated, err := s.writeBulkChange(ctx, host, change, principal.Subject)
	if err != nil {
		s.log.Error("bulk metadata: writing the host failed", "host", hostID, "err", err)
		return bulkHostOutcome{HostID: hostID, Code: "internal_error", Detail: "internal error"}
	}
	s.audit.Record(ctx, audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "host.metadata", TargetType: "host", TargetID: hostID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{"reason": change.reason, "bulk": true},
		Before: before,
		After:  bulkFacts(updated),
	})
	return bulkHostOutcome{HostID: hostID, OK: true, Code: "applied"}
}

// writeBulkChange writes the facts of the change on one host, in the
// order the single routes would: the tags, the owner, the domain, the
// placement, the window. The last view of the host is returned.
func (s *Server) writeBulkChange(ctx context.Context, host *hosts.Host, change bulkChange,
	actor string) (*hosts.Host, error) {
	updated := host
	var err error
	if len(change.tagsAdd) > 0 || len(change.tagsRemove) > 0 {
		tags := make([]string, 0, len(host.Tags)+len(change.tagsAdd))
		for _, tag := range host.Tags {
			if !slices.Contains(change.tagsRemove, tag) {
				tags = append(tags, tag)
			}
		}
		tags = append(tags, change.tagsAdd...)
		if tags, err = hosts.NormalizeTags(tags); err != nil {
			return nil, err
		}
		if updated, err = s.hosts.SetTags(ctx, host.ID, tags); err != nil {
			return nil, err
		}
	}
	if change.owner != nil {
		if updated, err = s.hosts.SetOwner(ctx, host.ID, *change.owner); err != nil {
			return nil, err
		}
	}
	if change.failureDomain != nil {
		if updated, err = s.hosts.SetFailureDomain(ctx, host.ID, *change.failureDomain); err != nil {
			return nil, err
		}
	}
	if change.site != nil || change.environment != nil {
		site, environment := host.Site, host.Environment
		if change.site != nil {
			site = *change.site
		}
		if change.environment != nil {
			environment = *change.environment
		}
		if updated, err = s.hosts.SetPlacement(ctx, host.ID, site, environment); err != nil {
			return nil, err
		}
	}
	if change.maintenanceSet {
		updated, err = s.hosts.SetMaintenanceWindow(ctx, host.ID, change.maintenanceUntil,
			change.maintenanceReason, actor)
		if err != nil {
			return nil, err
		}
	}
	return updated, nil
}

// bulkFacts renders the facts a bulk edit may touch, for one side of the
// audit event. All of them are kept, changed or not: the question asked
// of the trail is what the host carried, not what the edit named.
func bulkFacts(host *hosts.Host) map[string]any {
	return map[string]any{
		"tags": tagList(host.Tags), "owner": host.Owner, "failure_domain": host.FailureDomain,
		"site": host.Site, "environment": host.Environment,
		"maintenance": windowState(host.Maintenance),
	}
}
