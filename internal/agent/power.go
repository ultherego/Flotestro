package agent

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/modules/power"
)

// recentBoots limits the list of boots. The operator asks whether the host came
// back after the last restart - not about the whole history of the machine.
const recentBoots = 5

// CollectPower reads the boot state and the shutdown inhibitors.
//
// The read needs no root: /proc is readable by everyone, logind answers the
// question about inhibitors over the bus, and the journal is read by the same
// process that reads it for the log tab.
func CollectPower(ctx context.Context, bootID string, rebootRequired *bool) power.Snapshot {
	now := time.Now().UTC()
	snapshot := power.Snapshot{
		BootID:         bootID,
		RebootRequired: rebootRequired,
		ObservedAt:     now,
	}

	if content, err := os.ReadFile(power.SciezkaUptime); err == nil {
		snapshot.UptimeSeconds = power.ParsujUptime(string(content))
		if snapshot.UptimeSeconds != nil {
			snapshot.BootedAt = now.Add(-time.Duration(*snapshot.UptimeSeconds * float64(time.Second)))
		}
	} else {
		snapshot.UnavailableReason = "uptime: " + err.Error()
	}

	if kernel, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		snapshot.RunningKernel = strings.TrimSpace(string(kernel))
	}

	// The reasons for a restart are the names of the packages that asked for it.
	// A host that needs a restart "just because" tells the operator nothing.
	for _, path := range []string{power.PlikPakietow, power.PlikPakietowRun} {
		if content, err := os.ReadFile(path); err == nil {
			snapshot.RebootReasons = power.ParsujPowodyRestartu(string(content))
			break
		}
	}

	if exists(power.SciezkaInhibit) {
		output, _, _ := outputWithError(ctx, power.SciezkaInhibit, "--list", "--no-pager")
		snapshot.Inhibitors, snapshot.InhibitorsKnown = power.ParsujInhibitory(output)
	}

	if exists(power.SciezkaJournalctl) {
		if output, err := commandOutput(ctx, power.SciezkaJournalctl, "--list-boots", "--no-pager"); err == nil {
			boots := power.ParsujListeStartow(output)
			if len(boots) > recentBoots {
				boots = boots[len(boots)-recentBoots:]
			}
			snapshot.LastBoots = boots
		}
	}

	if content, err := os.ReadFile(power.PlikZaplanowanego); err == nil {
		snapshot.Scheduled = power.ParsujZaplanowane(string(content))
	}
	return snapshot
}
