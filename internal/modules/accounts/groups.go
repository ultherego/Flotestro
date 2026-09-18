package accounts

import (
	"os"
	"sort"
	"strings"
	"sync"
)

// DefaultPrivilegedGroups lists the groups whose membership is root by
// another name on the distributions the fleet runs: sudo and wheel give
// root directly, docker and lxd give it through the engine socket. The
// list is a setting of the installation (FLOTESTRO_ACCOUNTS_PRIVILEGED_GROUPS);
// this is what it says when nobody set it.
var DefaultPrivilegedGroups = []string{"sudo", "wheel", "docker", "lxd"}

// PrivilegedGroupsEnv names the setting of the installation. It is read
// here rather than by each binary's configuration: the control plane
// judges an order by this list and the host reports memberships against
// it, and a list that differed between the two would mean the panel
// calling privileged what the host does not, or worse the other way
// round.
const PrivilegedGroupsEnv = "FLOTESTRO_ACCOUNTS_PRIVILEGED_GROUPS"

func init() {
	LoadPrivilegedGroups(os.Getenv(PrivilegedGroupsEnv))
}

// LoadPrivilegedGroups takes the list from one setting value: group names
// separated by commas or whitespace. An empty value leaves the default,
// because an installation that set nothing did not mean "no group is
// privileged".
func LoadPrivilegedGroups(value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	SetPrivilegedGroups(strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	}))
}

var (
	privilegedMu     sync.RWMutex
	privilegedGroups = append([]string(nil), DefaultPrivilegedGroups...)
)

// PrivilegedGroups returns the groups the installation treats as root by
// another name, sorted.
func PrivilegedGroups() []string {
	privilegedMu.RLock()
	defer privilegedMu.RUnlock()
	return append([]string(nil), privilegedGroups...)
}

// SetPrivilegedGroups replaces the list. Names are trimmed and lowered,
// empty entries dropped, duplicates folded; an empty list means the
// default, because an installation with no privileged group at all is not
// a configuration anybody means.
func SetPrivilegedGroups(groups []string) {
	seen := map[string]bool{}
	var cleaned []string
	for _, group := range groups {
		group = strings.ToLower(strings.TrimSpace(group))
		if group == "" || seen[group] {
			continue
		}
		seen[group] = true
		cleaned = append(cleaned, group)
	}
	if len(cleaned) == 0 {
		cleaned = append([]string(nil), DefaultPrivilegedGroups...)
	}
	sort.Strings(cleaned)
	privilegedMu.Lock()
	privilegedGroups = cleaned
	privilegedMu.Unlock()
}

// PrivilegedGroupsIn returns the privileged groups the list names, in the
// order of the list.
func PrivilegedGroupsIn(groups []string) []string {
	privileged := PrivilegedGroups()
	var found []string
	for _, group := range groups {
		for _, name := range privileged {
			if group == name {
				found = append(found, group)
				break
			}
		}
	}
	return found
}
