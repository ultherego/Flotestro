package firewall

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// RegistryDir holds the state of the panel rules and their rollback plans.
//
// The directory belongs to root. The registry is a list of rules in a form
// the panel understands - not an nft script. A file that could steer the
// execution would be a door to root even for a root that made a mistake.
const (
	RegistryDir  = "/var/lib/flotestro-helper/firewall"
	RegistryFile = "rules.json"
)

// Registry holds the rules the panel considers its own.
//
// The handle is assigned by the kernel and changes at every table reload,
// so it is not fit for a rule identity. The registry is the source of truth
// about what the panel created and allows rebuilding the table from scratch
// - also on rollback.
type Registry struct {
	Rules     []RuleSpec `json:"rules"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// LoadRegistry reads the rule registry. A missing file means a host on
// which the panel has not created anything yet - and that is not an error.
func LoadRegistry(dir string) (Registry, error) {
	data, err := os.ReadFile(filepath.Join(dir, RegistryFile))
	if os.IsNotExist(err) {
		return Registry{}, nil
	}
	if err != nil {
		return Registry{}, err
	}
	var registry Registry
	if err := json.Unmarshal(data, &registry); err != nil {
		return Registry{}, err
	}
	return registry, nil
}

// SaveRegistry writes the rule registry.
func SaveRegistry(dir string, registry Registry) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(registry)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, RegistryFile)
	// Atomic write: a registry read half-way would not rebuild the table,
	// and that is exactly when it is needed.
	temporary := path + ".new"
	if err := os.WriteFile(temporary, data, 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

// Set adds or replaces the rule with the same name.
//
// The same name means the same rule: repeating the operation with the same
// payload duplicates nothing.
func (r Registry) Set(rule RuleSpec) Registry {
	updated := Registry{Rules: make([]RuleSpec, 0, len(r.Rules)+1)}
	replaced := false
	for _, existing := range r.Rules {
		if existing.ID == rule.ID {
			updated.Rules = append(updated.Rules, rule)
			replaced = true
			continue
		}
		updated.Rules = append(updated.Rules, existing)
	}
	if !replaced {
		updated.Rules = append(updated.Rules, rule)
	}
	return updated
}

// Remove deletes the rule with the given name.
func (r Registry) Remove(id string) (Registry, bool) {
	updated := Registry{Rules: make([]RuleSpec, 0, len(r.Rules))}
	found := false
	for _, rule := range r.Rules {
		if rule.ID == id {
			found = true
			continue
		}
		updated.Rules = append(updated.Rules, rule)
	}
	return updated, found
}

// RebuildArguments assembles the commands recreating the panel table from
// the registry.
//
// The table is built from scratch, not patched: the rule order decides
// which one acts first, so appending at the end would give a different
// effect than what the operator saw in the plan.
func RebuildArguments(registry Registry) ([][]string, error) {
	steps := TableSetupArguments()
	// Flush clears the rules, leaving the chains: a chain removed and
	// recreated loses its hook in the packet path for the duration of the
	// rebuild.
	steps = append(steps, []string{NftPath, "flush", "table", FlotestroFamily, FlotestroTable})
	for _, rule := range registry.Rules {
		arguments, err := RuleArguments(rule)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", rule.ID, err)
		}
		steps = append(steps, arguments)
	}
	return steps, nil
}

// TableRemovalArguments deletes the whole panel table.
//
// Used when the panel has no rule left: an empty table with hooked chains
// filters nothing, but leaves an object nobody needs in the listing.
func TableRemovalArguments() []string {
	return []string{NftPath, "delete", "table", FlotestroFamily, FlotestroTable}
}
