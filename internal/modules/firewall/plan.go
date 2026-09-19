package firewall

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"sort"
)

// Plan describes the difference between the rule found and the one requested
// on a single host.
type Plan struct {
	RuleID string `json:"rule_id"`
	// Action names what would happen: create, update, no_change, remove or
	// remove_absent.
	Action string `json:"action"`

	// Current is the panel rule the host has now. Nil means the host does
	// not know this rule.
	Current *RuleSpec `json:"current,omitempty"`
	// Desired is the requested rule. Nil on removal.
	Desired *RuleSpec `json:"desired,omitempty"`
	// Changes lists in human terms what will change.
	Changes []string `json:"changes,omitempty"`

	// RulesetHash is the fingerprint of the whole ruleset the host had at
	// planning.
	RulesetHash string `json:"ruleset_hash"`
	// Adapter says what mechanism the host has underneath. A plan for a
	// host without nftables is a refusal, not an empty list of changes.
	Adapter string `json:"adapter,omitempty"`
	// Refusal names the reason the change cannot land on this host: it would cut
	// off the management channel or the rule does not belong to the panel.
	Refusal string `json:"refusal,omitempty"`
	// Commands lists, for a mechanism driven by its command line (ufw), the
	// commands the change runs - as the operator would type them.
	Commands []string `json:"commands,omitempty"`

	PlanHash string `json:"plan_hash"`
}

// Plan action names.
const (
	PlanCreate       = "create"
	PlanUpdate       = "update"
	PlanNoChange     = "no_change"
	PlanRemove       = "remove"
	PlanRemoveAbsent = "remove_absent"
)

// ComputeRule computes the difference for creating or changing a rule.
func ComputeRule(registry Registry, requested RuleSpec, rulesetHash, adapter string) Plan {
	plan := Plan{RuleID: requested.ID, RulesetHash: rulesetHash, Adapter: adapter}
	desired := requested
	plan.Desired = &desired

	current, present := registry.Find(requested.ID)
	switch {
	case !present:
		plan.Action = PlanCreate
		plan.Changes = []string{"the rule will be created"}
	case reflect.DeepEqual(normalise(current), normalise(requested)):
		found := current
		plan.Current = &found
		plan.Action = PlanNoChange
	default:
		found := current
		plan.Current = &found
		plan.Action = PlanUpdate
		plan.Changes = differences(current, requested)
	}
	plan.PlanHash = planFingerprint(plan)
	return plan
}

// ComputeRemoval computes the difference for removing a rule.
func ComputeRemoval(registry Registry, id, rulesetHash, adapter string) Plan {
	plan := Plan{RuleID: id, RulesetHash: rulesetHash, Adapter: adapter}
	current, present := registry.Find(id)
	if !present {
		// Removing a rule the host does not know is not an error and not a
		// change. The operator is meant to see it before approving.
		plan.Action = PlanRemoveAbsent
	} else {
		found := current
		plan.Current = &found
		plan.Action = PlanRemove
	}
	plan.PlanHash = planFingerprint(plan)
	return plan
}

// Refuse records a refusal reason learned after the differences were computed
// - for example the management channel protection - and recomputes the
// fingerprint: a plan with a refusal is a different answer than a plan without
func (p *Plan) Refuse(reason string) {
	p.Refusal = reason
	p.PlanHash = planFingerprint(*p)
}

// Describe records the commands the change runs and recomputes the
// fingerprint: a plan with other commands is another change.
func (p *Plan) Describe(commands []string) {
	p.Commands = commands
	p.PlanHash = planFingerprint(*p)
}

// Find returns the panel rule with the given identifier.
func (r Registry) Find(id string) (RuleSpec, bool) {
	for _, rule := range r.Rules {
		if rule.ID == id {
			return rule, true
		}
	}
	return RuleSpec{}, false
}

// normalise brings a rule to a comparable form: the order of ports and
// sources is not the operator's decision.
func normalise(rule RuleSpec) RuleSpec {
	copied := rule
	copied.Ports = append([]string(nil), rule.Ports...)
	copied.Sources = append([]string(nil), rule.Sources...)
	sort.Strings(copied.Ports)
	sort.Strings(copied.Sources)
	if len(copied.Ports) == 0 {
		copied.Ports = nil
	}
	if len(copied.Sources) == 0 {
		copied.Sources = nil
	}
	return copied
}

// differences lists the changes visible to a human.
func differences(current, requested RuleSpec) []string {
	a, b := normalise(current), normalise(requested)
	var changes []string
	if a.Chain != b.Chain {
		changes = append(changes, "chain from "+a.Chain+" to "+b.Chain)
	}
	if a.Action != b.Action {
		changes = append(changes, "action from "+a.Action+" to "+b.Action)
	}
	if a.Protocol != b.Protocol {
		changes = append(changes, "protocol from "+orAny(a.Protocol)+" to "+orAny(b.Protocol))
	}
	if !reflect.DeepEqual(a.Ports, b.Ports) {
		changes = append(changes, "ports")
	}
	if !reflect.DeepEqual(a.Sources, b.Sources) {
		changes = append(changes, "sources")
	}
	if a.Interface != b.Interface {
		changes = append(changes, "interface from "+orAny(a.Interface)+" to "+orAny(b.Interface))
	}
	if a.Comment != b.Comment {
		changes = append(changes, "comment")
	}
	sort.Strings(changes)
	return changes
}

func orAny(value string) string {
	if value == "" {
		return "any"
	}
	return value
}

// planFingerprint computes the plan fingerprint excluding the fingerprint
// itself.
func planFingerprint(plan Plan) string {
	stripped := plan
	stripped.PlanHash = ""
	encoded, err := json.Marshal(stripped)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
