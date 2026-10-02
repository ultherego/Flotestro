package opspec

import "strings"

// The inventory module whose picture an operation changes. The panel shows a
// host through the modules of its inventory, and until one is collected again
// the page says what was true before the change: a VLAN built through the panel
// was missing from the host's network for up to the whole inventory interval,
// fifteen minutes by default. So the agent collects the module it has just
// written to, and the names of those modules are here because the action table
// is here.
//
// The key is the first segment of the action, which is how the actions are
// named, and the value is the module of the inventory - the two differ where
// the operation is named after the tool and the module after what it holds
// ("docker" writes "containers"). A prefix that is not listed yields no module
// and orders no collection: silence is the behaviour the agent had before, so
// an operation nobody mapped cannot be made worse by this table.
var inventoryModuleOfAction = map[string]string{
	"agent":       "packages",
	"backup":      "backups",
	"certificate": "certificates",
	"disk":        "storage",
	"dns":         "dns",
	"docker":      "containers",
	"file":        "files",
	"filesystem":  "storage",
	"firewall":    "firewall",
	"host":        "system",
	"identity":    "identity",
	"kernel":      "kernel",
	"localuser":   "accounts",
	"lvm":         "storage",
	"mount":       "storage",
	"network":     "network",
	"packages":    "packages",
	"raid":        "storage",
	"schedule":    "schedules",
	"security":    "security",
	"selinux":     "security",
	"ssh":         "ssh",
	"storage":     "storage",
	"sysctl":      "kernel",
	"system":      "system",
	"time":        "time",
	"unit":        "services",
}

// InventoryModule returns the module of the inventory the operation changes, or
// an empty string when the operation changes no picture the panel keeps. An
// operation that changes nothing on the host never does: a read leaves the
// inventory exactly as it found it.
func (a ActionType) InventoryModule() string {
	if !a.Mutating() {
		return ""
	}
	prefix, _, found := strings.Cut(string(a), ".")
	if !found {
		return ""
	}
	return inventoryModuleOfAction[prefix]
}

// The table's values are the names of the refresh scope, and a value that is not
// one would order a collection of nothing. The test holds it; this note says why
// the two lists must agree.
