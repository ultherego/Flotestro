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

// GrantsFor derives the grants of a capability from what the creator of
// the task holds: the permission of the action itself, every permission of
// the creator in the same family (schedule.* for a schedule operation,
// localuser.* for an account operation), and the root grant for a schedule
// entry that runs as root - held by a creator who has it, or earned by
// the approval the policy demanded for such an entry. The list is what
// the helper's own checks read; it never widens what the creator had.
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
	if payload.Schedule != nil && payload.Schedule.User == "root" &&
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
