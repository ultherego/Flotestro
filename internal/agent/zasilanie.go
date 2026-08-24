package agent

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/modules/power"
)

// ostatnieStarty ogranicza liste startow. Operator pyta, czy host wrocil po
// ostatnim restarcie - a nie o cala historie maszyny.
const ostatnieStarty = 5

// ZbierzZasilanie czyta stan startu i blokad wylaczenia.
//
// Odczyt nie wymaga roota: /proc jest czytelny dla wszystkich, logind
// odpowiada na pytanie o inhibitory przez magistrale, a dziennik czyta ten
// sam proces, ktory czyta go dla zakladki logow.
func ZbierzZasilanie(ctx context.Context, bootID string, restartWymagany *bool) power.Snapshot {
	teraz := time.Now().UTC()
	snapshot := power.Snapshot{
		BootID:         bootID,
		RebootRequired: restartWymagany,
		ObservedAt:     teraz,
	}

	if tresc, err := os.ReadFile(power.SciezkaUptime); err == nil {
		snapshot.UptimeSeconds = power.ParsujUptime(string(tresc))
		if snapshot.UptimeSeconds != nil {
			snapshot.BootedAt = teraz.Add(-time.Duration(*snapshot.UptimeSeconds * float64(time.Second)))
		}
	} else {
		snapshot.UnavailableReason = "uptime: " + err.Error()
	}

	if jadro, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		snapshot.RunningKernel = strings.TrimSpace(string(jadro))
	}

	// Powody restartu sa nazwami pakietow, ktore o niego poprosily. Host,
	// ktory wymaga restartu "bo tak", nie mowi operatorowi nic.
	for _, sciezka := range []string{power.PlikPakietow, power.PlikPakietowRun} {
		if tresc, err := os.ReadFile(sciezka); err == nil {
			snapshot.RebootReasons = power.ParsujPowodyRestartu(string(tresc))
			break
		}
	}

	if exists(power.SciezkaInhibit) {
		wyjscie, _, _ := wyjscieZBledem(ctx, power.SciezkaInhibit, "--list", "--no-pager")
		snapshot.Inhibitors, snapshot.InhibitorsKnown = power.ParsujInhibitory(wyjscie)
	}

	if exists(power.SciezkaJournalctl) {
		if wyjscie, err := wyjsciePolecenia(ctx, power.SciezkaJournalctl, "--list-boots", "--no-pager"); err == nil {
			starty := power.ParsujListeStartow(wyjscie)
			if len(starty) > ostatnieStarty {
				starty = starty[len(starty)-ostatnieStarty:]
			}
			snapshot.LastBoots = starty
		}
	}

	if tresc, err := os.ReadFile(power.PlikZaplanowanego); err == nil {
		snapshot.Scheduled = power.ParsujZaplanowane(string(tresc))
	}
	return snapshot
}
