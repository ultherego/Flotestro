package adminapi

import (
	"context"
	"time"

	"github.com/ultherego/flotestro/internal/campaigns"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/opspec"
)

// Reasons a host from the snapshot will not run the operation. Each is a
// separate answer: a host in a maintenance window comes back on its own, a
// host without an adapter never comes back, and a host the panel knows
// nothing about needs a read, not a decision.
const (
	// ReasonMaintenance means a host in a maintenance window: somebody is
	// working on it.
	ReasonMaintenance = "maintenance"
	// ReasonCapabilityMissing means a host without the adapter the
	// operation requires.
	ReasonCapabilityMissing = "capability_missing"
	// ReasonQuarantined means a host cut off from management.
	ReasonQuarantined = "quarantined"
	// ReasonCapabilityUnknown means a host that has not reported its
	// adapter registry yet. That is not a missing capability - it is
	// missing knowledge, and the cure is an inventory read, not exclusion
	// from the campaign.
	ReasonCapabilityUnknown = "capability_unknown"
	// ReasonOutOfScope means a host outside the operator's permission
	// scope.
	ReasonOutOfScope = "out_of_scope"
	// ReasonConflict means a host that is already the target of another
	// running campaign. It does not block the order - the resource locks
	// queue the operations anyway - but the operator is meant to know
	// before the start.
	ReasonConflict = "conflict"
	// ReasonOffline means a disconnected host. The campaign waits for it
	// instead of excluding it: the host comes back and does its part.
	ReasonOffline = "offline"
)

// hostGroup gathers hosts with a common reason.
type hostGroup struct {
	Reason string   `json:"reason"`
	Count  int      `json:"count"`
	Sample []string `json:"sample"`
}

// qualification is the decision which hosts of the snapshot really move.
//
// One function computes it for the preview and for creating the campaign. A
// drift between them would be the worst kind of bug: the operator would see
// a different campaign on the screen than the one they approve.
type qualification struct {
	Ready []hosts.Host
	// Closed are the hosts that enter the snapshot already closed. The
	// order matches Ready: it is one target list, not two campaigns.
	Closed []closedHost
	// Notes do not exclude a host - they describe what the operator is
	// meant to know before approving. An offline host comes back, a
	// conflicting host waits for the lock.
	Notes []hostGroup
}

// closedHost is a host in the snapshot that will not move.
type closedHost struct {
	Host    hosts.Host
	State   campaigns.TargetState
	Reason  string
	Message string
}

// assessCandidates decides every host against the operation.
//
// The order matters: the most serious obstacle is reported, not the first
// one met. Quarantine comes before the maintenance window, because a host
// cut off from management does not come back on its own after an hour.
func assessCandidates(candidates []hosts.Host, action opspec.ActionType,
	conflicts map[string]string, now time.Time) qualification {
	result := qualification{}
	requirement := action.RequiredCapability()
	offline := hostGroup{Reason: ReasonOffline}
	conflicting := hostGroup{Reason: ReasonConflict}
	unknown := hostGroup{Reason: ReasonCapabilityUnknown}

	for _, host := range candidates {
		switch {
		case host.LifecycleState == "quarantined":
			result.close(host, campaigns.TargetIneligible, ReasonQuarantined,
				"the host is quarantined and accepts no operations")
			continue
		case host.Maintenance.Active(now):
			result.close(host, campaigns.TargetSkipped, ReasonMaintenance,
				"the host is in a maintenance window until "+host.Maintenance.Until.Format(time.RFC3339))
			continue
		}

		// A host that has not reported its adapter registry yet is not a
		// host without adapters. It is let in and said so directly: the
		// preflight on the host itself decides.
		if requirement != "" && len(host.Capabilities) == 0 {
			add(&unknown, host)
		} else if requirement != "" && !host.Capabilities.Satisfies(requirement) {
			result.close(host, campaigns.TargetIneligible, ReasonCapabilityMissing,
				"the host lacks the adapter this operation requires: "+requirement)
			continue
		}

		if host.ConnectionState != "online" {
			add(&offline, host)
		}
		if conflicts[host.ID] != "" {
			add(&conflicting, host)
		}
		result.Ready = append(result.Ready, host)
	}

	for _, group := range []hostGroup{offline, conflicting, unknown} {
		if group.Count > 0 {
			result.Notes = append(result.Notes, group)
		}
	}
	return result
}

// Uncertain lists the hosts that will not apply the change now: closed in
// the snapshot and those the campaign only waits for.
//
// For most operations these are only notes. For a change that binds the
// whole fleet at once they are a reason not to start it.
func (q qualification) Uncertain() []hostGroup {
	groups := q.Exclusions()
	for _, note := range q.Notes {
		if note.Reason == ReasonOffline || note.Reason == ReasonCapabilityUnknown {
			groups = append(groups, note)
		}
	}
	return groups
}

func (q *qualification) close(host hosts.Host, state campaigns.TargetState, reason, message string) {
	q.Closed = append(q.Closed, closedHost{
		Host: host, State: state, Reason: reason, Message: message,
	})
}

// Exclusions groups the closed hosts by reason.
func (q qualification) Exclusions() []hostGroup {
	order := []string{}
	byReason := map[string]*hostGroup{}
	for _, entry := range q.Closed {
		group, present := byReason[entry.Reason]
		if !present {
			group = &hostGroup{Reason: entry.Reason}
			byReason[entry.Reason] = group
			order = append(order, entry.Reason)
		}
		add(group, entry.Host)
	}
	groups := make([]hostGroup, 0, len(order))
	for _, reason := range order {
		groups = append(groups, *byReason[reason])
	}
	return groups
}

// Targets assembles the campaign snapshot: ready and closed hosts in one
// list.
func (q qualification) Targets() []campaigns.TargetHost {
	targets := make([]campaigns.TargetHost, 0, len(q.Ready)+len(q.Closed))
	for _, host := range q.Ready {
		targets = append(targets, campaigns.TargetHost{ID: host.ID, BootID: host.BootID})
	}
	for _, entry := range q.Closed {
		targets = append(targets, campaigns.TargetHost{
			ID: entry.Host.ID, BootID: entry.Host.BootID,
			State: entry.State, Reason: entry.Reason, Message: entry.Message,
		})
	}
	return targets
}

// add appends a host to a group, keeping the sample short.
//
// The sample is a sample and that is what it is called: the count talks
// about the whole, and the names are there for the operator to recognise
// which machines are meant.
func add(group *hostGroup, host hosts.Host) {
	group.Count++
	if len(group.Sample) < previewSampleSize {
		group.Sample = append(group.Sample, host.Hostname)
	}
}

// activeConflicts says which hosts are already targets of running
// campaigns.
func (s *Server) activeConflicts(ctx context.Context) map[string]string {
	conflicts, err := s.campaigns.ActiveTargets(ctx)
	if err != nil {
		// Missing this knowledge does not stop the order: a conflict is a
		// note, not an exclusion. It is kept silent instead of invented.
		s.log.Error("the targets of the running campaigns were not read", "err", err)
		return nil
	}
	return conflicts
}
