package agent

import (
	"context"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/packages"
)

// pacmanSummary counts the packages and the pending updates on Arch.
func pacmanSummary(ctx context.Context) Packages {
	summary := Packages{Manager: packages.PacmanName}

	// The listing is counted as it arrives: only the counter is kept, never the
	// list of every package of the host.
	var installed uint32
	if result := runCommandLines(ctx, 30*time.Second, func(line string) {
		if strings.TrimSpace(line) != "" {
			installed++
		}
	}, "/usr/bin/pacman", "-Q"); result.Complete() {
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
