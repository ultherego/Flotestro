package hosttime

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"
)

// Plan describes the difference between the time sources the panel has on
// the host and the requested ones.
//
// The same server list on two hosts is two changes: one has chrony with a
// sources directory and reloads without a restart, another has timesyncd
// and restarts the daemon, a third includes no directory and needs a line
// appended to somebody else's file. The operator is meant to see that
// before approving, not half-way through the fleet.
type Plan struct {
	// Service names the host time daemon; Action - what would happen:
	// update or no_change.
	Service string `json:"service,omitempty"`
	Action  string `json:"action"`

	// CurrentServers are the servers written by the panel; DesiredServers -
	// the order.
	CurrentServers []string `json:"current_servers,omitempty"`
	DesiredServers []string `json:"desired_servers"`
	// ManagedPath is the file the write overwrites; empty means the host
	// has nowhere to accept the change without enabling a directory.
	ManagedPath string `json:"managed_path,omitempty"`
	ManagedHash string `json:"managed_hash,omitempty"`
	// EnablesSourceDir says the change appends the panel directory to the
	// main chrony file - the only place where the panel touches somebody
	// else's configuration.
	EnablesSourceDir bool `json:"enables_source_dir,omitempty"`
	// Restart says whether the daemon is restarted or only reloads its
	// sources. A restart is a moment without synchronisation.
	Restart bool `json:"restart,omitempty"`

	Changes []string `json:"changes,omitempty"`
	Refusal string   `json:"refusal,omitempty"`

	PlanHash string `json:"plan_hash"`
}

// Plan action names.
const (
	PlanUpdate   = "update"
	PlanNoChange = "no_change"
)

// Compute computes the difference for a time sources change.
func Compute(state Snapshot, servers []string, allowSourceDir bool) Plan {
	plan := Plan{Service: state.Service, DesiredServers: append([]string(nil), servers...),
		ManagedPath: state.ManagedPath}
	if state.Managed != "" {
		plan.ManagedHash = textFingerprint(state.Managed)
	}
	for _, server := range state.Configured {
		if server.Managed {
			plan.CurrentServers = append(plan.CurrentServers, server.Address)
		}
	}
	if state.UnavailableReason != "" {
		return plan.withRefusal(state.UnavailableReason)
	}
	if err := ValidateServers(servers); err != nil {
		return plan.withRefusal(err.Error())
	}

	var content string
	switch state.Service {
	case DaemonChrony:
		if state.ManagedPath == "" {
			if !allowSourceDir {
				reason := state.WriteReason
				if reason == "" {
					reason = "chrony on this host includes no configuration directory"
				}
				return plan.withRefusal(reason)
			}
			if !state.CanAddSourceDir || state.ConfigPath == "" {
				return plan.withRefusal("no main chrony file found to append the sources directory to")
			}
			plan.EnablesSourceDir = true
			plan.Restart = true
			plan.ManagedPath = filepath.Join(PanelSourceDir, ChronyFileName(KindSources))
		}
		kind := KindConfiguration
		if filepath.Ext(plan.ManagedPath) == ".sources" {
			kind = KindSources
		}
		if kind != KindSources {
			plan.Restart = true
		}
		content, _ = ComposeChrony(servers, kind)
	case DaemonTimesyncd:
		plan.ManagedPath = TimesyncdFile
		plan.Restart = true
		content, _ = ComposeTimesyncd(servers)
	default:
		return plan.withRefusal("this host has no time daemon the panel could point at servers")
	}

	if !sameSet(plan.CurrentServers, servers) {
		plan.Changes = append(plan.Changes, "panel servers from "+list(plan.CurrentServers)+
			" to "+list(servers))
	}
	switch {
	case state.Managed == "" && state.ManagedPath == "":
		plan.Changes = append(plan.Changes, "the panel file "+plan.ManagedPath+" will be created")
	case state.Managed != content:
		if state.Managed == "" {
			plan.Changes = append(plan.Changes, "the panel file "+plan.ManagedPath+" will be created")
		} else {
			plan.Changes = append(plan.Changes, "the panel file "+plan.ManagedPath+" will be overwritten")
		}
	}
	if plan.EnablesSourceDir {
		plan.Changes = append(plan.Changes,
			"the panel sources directory will be appended to "+state.ConfigPath)
	}
	if len(plan.Changes) > 0 {
		if plan.Restart {
			plan.Changes = append(plan.Changes, "the time daemon will be restarted")
		} else {
			plan.Changes = append(plan.Changes, "the sources will be reloaded without a daemon restart")
		}
	}

	plan.Action = PlanUpdate
	if len(plan.Changes) == 0 {
		plan.Action = PlanNoChange
	}
	plan.PlanHash = planFingerprint(plan)
	return plan
}

// Refuse records a refusal reason learned after the differences were
// computed and recomputes the fingerprint: a plan with a refusal is a
// different answer than a plan without one.
func (p *Plan) Refuse(reason string) {
	p.Refusal = reason
	p.PlanHash = planFingerprint(*p)
}

func (p Plan) withRefusal(reason string) Plan {
	p.Refusal = reason
	p.PlanHash = planFingerprint(p)
	return p
}

func sameSet(a, b []string) bool {
	x := append([]string(nil), a...)
	y := append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	return strings.Join(x, "\x00") == strings.Join(y, "\x00")
}

func list(items []string) string {
	if len(items) == 0 {
		return "none"
	}
	return strings.Join(items, ",")
}

func textFingerprint(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
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
