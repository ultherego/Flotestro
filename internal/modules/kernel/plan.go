package kernel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

// ModulePlan describes the difference between the module block found and
// the one requested on a single host.
//
// "Block module X" is a file entry on one host, already present on another,
// and on a third the module happens to be running and holding other modules
// - then the entry takes effect only after a reboot. The operator is meant
// to see this before approving.
type ModulePlan struct {
	Module string `json:"module"`
	// Blacklist says whether the order blocks or unblocks.
	Blacklist bool `json:"blacklist"`

	// The state found: whether the panel already blocks the module and
	// whether the kernel has it loaded, and if so - who uses it.
	Blacklisted bool     `json:"blacklisted"`
	Loaded      bool     `json:"loaded"`
	UsedBy      []string `json:"used_by,omitempty"`

	// Action names what would happen: create (the block appears), remove
	// (the block disappears) or no_change.
	Action  string   `json:"action"`
	Changes []string `json:"changes,omitempty"`

	// ManagedHash is the fingerprint of the panel's blacklist file: the
	// write overwrites it whole, so a file changed after planning is a
	// different change.
	ManagedHash string `json:"managed_hash,omitempty"`
	Refusal     string `json:"refusal,omitempty"`

	PlanHash string `json:"plan_hash"`
}

// Plan action names.
const (
	PlanCreate   = "create"
	PlanRemove   = "remove"
	PlanNoChange = "no_change"
)

// PlanBlacklist computes the difference for blocking or unblocking a module.
func PlanBlacklist(state Snapshot, module string, block bool) ModulePlan {
	plan := ModulePlan{Module: module, Blacklist: block}
	if state.Managed != "" {
		plan.ManagedHash = textFingerprint(state.Managed)
	}
	if state.UnavailableReason != "" {
		return plan.withRefusal(state.UnavailableReason)
	}
	if err := ValidateModule(module); err != nil {
		return plan.withRefusal(err.Error())
	}
	for _, name := range state.Blacklist {
		if name == module {
			plan.Blacklisted = true
		}
	}
	for _, loaded := range state.Modules {
		if loaded.Name == module {
			plan.Loaded = true
			plan.UsedBy = append([]string(nil), loaded.UsedBy...)
		}
	}

	switch {
	case block && !plan.Blacklisted:
		plan.Action = PlanCreate
		plan.Changes = []string{"the block of the module " + module + " will be created"}
		if reason := InitramfsRequired(module, plan.Loaded); reason != "" {
			plan.Changes = append(plan.Changes, reason)
		}
		if len(plan.UsedBy) > 0 {
			plan.Changes = append(plan.Changes,
				"the module is used by: "+strings.Join(plan.UsedBy, ", "))
		}
	case !block && plan.Blacklisted:
		plan.Action = PlanRemove
		plan.Changes = []string{"the block of the module " + module + " will be removed"}
	default:
		plan.Action = PlanNoChange
	}
	plan.PlanHash = modulePlanFingerprint(plan)
	return plan
}

// Refuse records a refusal reason learned after the differences were
// computed and recomputes the fingerprint: a plan with a refusal is a
// different answer than a plan without one.
func (p *ModulePlan) Refuse(reason string) {
	p.Refusal = reason
	p.PlanHash = modulePlanFingerprint(*p)
}

func (p ModulePlan) withRefusal(reason string) ModulePlan {
	p.Refusal = reason
	p.PlanHash = modulePlanFingerprint(p)
	return p
}

func textFingerprint(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

// modulePlanFingerprint computes the plan fingerprint excluding the
// fingerprint itself.
func modulePlanFingerprint(plan ModulePlan) string {
	stripped := plan
	stripped.PlanHash = ""
	encoded, err := json.Marshal(stripped)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
