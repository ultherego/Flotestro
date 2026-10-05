package helpercap

import (
	"slices"
	"strings"

	"github.com/ultherego/flotestro/internal/opspec"
)

// The grants a capability may carry beyond the permission of the action.
const (
	// GrantScheduleRootExec allows a schedule entry that runs as root.
	GrantScheduleRootExec = "schedule.root.exec"
)

// GrantsFor derives the grants of a capability from what the creator of the
// task holds: the permission of the action itself, every permission of the
// creator in the same family (schedule.
func GrantsFor(action opspec.ActionType, payload opspec.Payload, permissions []string, approved bool) []string {
	grants := []string{}
	if permission := action.Permission(); permission != "" {
		grants = append(grants, permission)
	}
	family := familyOf(action.Permission())
	for _, permission := range permissions {
		if family != "" && familyOf(permission) == family && !slices.Contains(grants, permission) {
			grants = append(grants, permission)
		}
	}
	// The entry of a run_now that names no account may be root's, and the host
	// is the one that knows. The grant travels whenever the creator holds it,
	// so an order that turns out to be root's is carried out rather than
	// refused on the host for a grant the panel could have attached.
	mayBeRoot := payload.Schedule != nil &&
		(payload.Schedule.User == "root" ||
			(action == opspec.ActionScheduleRunNow && strings.TrimSpace(payload.Schedule.User) == ""))
	if mayBeRoot &&
		(approved || slices.Contains(permissions, GrantScheduleRootExec)) &&
		!slices.Contains(grants, GrantScheduleRootExec) {
		grants = append(grants, GrantScheduleRootExec)
	}
	slices.Sort(grants)
	return grants
}

func familyOf(permission string) string {
	family, _, _ := strings.Cut(permission, ".")
	return family
}
