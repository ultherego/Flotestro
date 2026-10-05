package firewall

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// ZonePlan describes the difference between the firewalld zone found and the
// one requested on a single host.
type ZonePlan struct {
	Zone string `json:"zone"`
	// Kind names the entry kind: port or service; Entry is the entry in the
	// form firewalld shows it ("8080/tcp", "http").
	Kind  string `json:"kind"`
	Entry string `json:"entry"`
	// Enable says whether the order opens or closes.
	Enable bool `json:"enable"`

	// The zone state found. ZoneExists and Present come from the configuration
	// the change writes; ZoneActive from the one the host filters with now,
	// which is the only one that knows about interfaces.
	ZoneExists bool `json:"zone_exists"`
	ZoneActive bool `json:"zone_active,omitempty"`
	Present    bool `json:"present"`

	// Action names what would happen: create (the entry appears), remove
	// (the entry disappears) or no_change.
	Action  string   `json:"action"`
	Changes []string `json:"changes,omitempty"`

	// RulesetHash is the fingerprint of the whole host ruleset at planning;
	// firewalld rewrites nftables at every zone change, so a ruleset changed
	// after planning stops the change.
	RulesetHash string `json:"ruleset_hash"`
	Adapter     string `json:"adapter,omitempty"`
	Refusal     string `json:"refusal,omitempty"`

	PlanHash string `json:"plan_hash"`
}

// ZoneViews are the two zone configurations of a firewalld host. What the plan
// decides - whether the entry is already there, and so what the way back is -
// is read from the permanent one, because that is the configuration
// firewall-cmd --permanent writes and a reload makes running. The running one
// answers only what it alone can answer: whether the zone is active on an
// interface now.
type ZoneViews struct {
	Permanent []Zone
	Runtime   []Zone
}

// Zone entry kinds.
const (
	EntryPort    = "port"
	EntryService = "service"
)

// ComputePort computes the difference for opening or closing a port in a
// zone.
func ComputePort(views ZoneViews, zone, port, protocol string, open bool,
	rulesetHash, adapter string) ZonePlan {
	plan := ZonePlan{
		Zone: zone, Kind: EntryPort, Entry: port + "/" + protocol, Enable: open,
		RulesetHash: rulesetHash, Adapter: adapter,
	}
	if _, err := PortArguments(zone, port, protocol, open); err != nil {
		return plan.withRefusal(err.Error())
	}
	return plan.against(views, func(z Zone) []string { return z.Ports })
}

// ComputeService computes the difference for enabling or disabling a
// service in a zone.
func ComputeService(views ZoneViews, zone, service string, enable bool,
	rulesetHash, adapter string) ZonePlan {
	plan := ZonePlan{
		Zone: zone, Kind: EntryService, Entry: service, Enable: enable,
		RulesetHash: rulesetHash, Adapter: adapter,
	}
	if _, err := ServiceArguments(zone, service, enable); err != nil {
		return plan.withRefusal(err.Error())
	}
	return plan.against(views, func(z Zone) []string { return z.Services })
}

// Refuse records a refusal reason learned after the differences were computed
// and recomputes the fingerprint: a plan with a refusal is a different answer
// than a plan without one.
func (p *ZonePlan) Refuse(reason string) {
	p.Refusal = reason
	p.PlanHash = zonePlanFingerprint(*p)
}

func (p ZonePlan) withRefusal(reason string) ZonePlan {
	p.Refusal = reason
	p.PlanHash = zonePlanFingerprint(p)
	return p
}

// against compares the order with the zone the host keeps, which is the zone
// the change writes.
func (p ZonePlan) against(views ZoneViews, entries func(Zone) []string) ZonePlan {
	kept, inPermanent := zoneNamed(views.Permanent, p.Zone)
	if !inPermanent {
		// The zone is absent from the configuration a change writes: firewalld would
		// refuse at write time, and it is better for the operator to see that in the
		// plan than half-way through the fleet.
		return p.withRefusal(fmt.Sprintf("the host keeps no zone %s, "+
			"so there is nowhere to write the change", p.Zone))
	}
	p.ZoneExists = true
	// Whether the zone is on an interface is a fact of the running
	// configuration only; the permanent listing has no such notion.
	if running, inRuntime := zoneNamed(views.Runtime, p.Zone); inRuntime {
		p.ZoneActive = running.Active
	}
	for _, entry := range entries(kept) {
		if entry == p.Entry {
			p.Present = true
			break
		}
	}
	switch {
	case p.Enable && !p.Present:
		p.Action = PlanCreate
		p.Changes = []string{p.Kind + " " + p.Entry + " will be opened in the zone " + p.Zone}
	case !p.Enable && p.Present:
		p.Action = PlanRemove
		p.Changes = []string{p.Kind + " " + p.Entry + " will be closed in the zone " + p.Zone}
	default:
		p.Action = PlanNoChange
	}
	if !p.ZoneActive && p.Action != PlanNoChange {
		// A change in an inactive zone is legal, but does not change what
		// the host accepts. The operator is meant to know before approving.
		p.Changes = append(p.Changes, "the zone "+p.Zone+" is not active on any interface")
	}
	p.PlanHash = zonePlanFingerprint(p)
	return p
}

// zonePlanFingerprint computes the plan fingerprint excluding the
// fingerprint itself.
func zonePlanFingerprint(plan ZonePlan) string {
	stripped := plan
	stripped.PlanHash = ""
	encoded, err := json.Marshal(stripped)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
