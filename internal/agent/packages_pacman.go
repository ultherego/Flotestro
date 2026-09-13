package agent

import (
	"context"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/packages"
)

// pacmanSummary counts the packages and the pending updates on Arch.
//
// The updates come from checkupdates, which syncs a copy of the database in
// a directory of its own; the inventory must not sync the system database,
// because on Arch a synced database without an upgrade is the state the
// distribution warns against. Without checkupdates the count is
// undetermined rather than zero, and the security count is always
// undetermined: the Arch repositories carry no security metadata.
func pacmanSummary(ctx context.Context) Packages {
	summary := Packages{Manager: packages.PacmanName}

	if result := runCommand(ctx, 30*time.Second, "/usr/bin/pacman", "-Q"); result.Ran && result.ExitCode == 0 {
		installed := uint32(len(strings.Split(strings.TrimSpace(result.Stdout), "\n")))
		if strings.TrimSpace(result.Stdout) == "" {
			installed = 0
		}
		summary.Installed = &installed
	}

	countCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	count, reason := (&packages.Pacman{}).PendingUpdates(countCtx)
	if reason != "" {
		summary.UnavailableReason = reason
		return summary
	}
	upgradable := uint32(count)
	summary.Upgradable = &upgradable
	return summary
}
