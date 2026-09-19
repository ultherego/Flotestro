// Package schedules manages the recurring jobs of a host independently of the
// mechanism: cron and systemd timers are two adapters of the same model.
package schedules

import "time"

// Mechanism kinds.
const (
	KindCron  = "cron"
	KindTimer = "timer"
	// KindAny is not a mechanism but an order: the host writes the entry with
	// whichever mechanism it has, cron first.
	KindAny = "any"
)

// Entry origin.
const (
	// SourceManaged marks an entry created by the panel: it has a file of
	// its own and a stable identifier.
	SourceManaged = "managed"
	// SourceManual marks an entry found on the host.
	SourceManual = "manual"
)

// Schedule describes one recurring job.
type Schedule struct {
	// ID is stable only for managed entries.
	ID   string `json:"id"`
	Kind string `json:"kind"`
	// Source distinguishes a panel entry from a host administrator entry.
	Source string `json:"source"`
	// Enabled says whether the entry is active. A disabled entry stays on
	// the host together with its content: disabling is not removal.
	Enabled bool `json:"enabled"`
	// Expression is the cron expression or the timer's OnCalendar.
	Expression string `json:"expression"`
	// Calendar is the OnCalendar expression a timer really runs by.
	Calendar string `json:"calendar,omitempty"`
	// Command is an argument array. Filled only for managed entries: there
	// the panel decides every argument and no shell takes part in the run.
	Command []string `json:"command,omitempty"`
	// CommandLine is the text cron passes to /bin/sh.
	CommandLine string `json:"command_line,omitempty"`
	User        string `json:"user,omitempty"`
	// Path points at the file the entry lives in. The operator needs to
	// know where to look when the panel cannot do something.
	Path string `json:"path,omitempty"`
	Line int    `json:"line,omitempty"`
	// NextRun is computed on the host and sent as a fact: the panel knows
	// neither the host's time zone nor its calendar.
	NextRun *time.Time `json:"next_run,omitempty"`
	// NextRuns are the following dates, the first of them NextRun again.
	NextRuns []time.Time `json:"next_runs,omitempty"`
	// Timezone of the host. Without it "03:00" means nothing specific.
	Timezone string `json:"timezone,omitempty"`
	// LastResult describes the last known run; empty means no knowledge,
	// not no runs.
	LastResult string `json:"last_result,omitempty"`
	Comment    string `json:"comment,omitempty"`
}

// Snapshot is the result of reading the host schedules.
type Snapshot struct {
	Schedules []Schedule `json:"schedules"`
	Timezone  string     `json:"timezone,omitempty"`
	// UnavailableReason says why the state could not be determined. A host
	// without cron and without timers is not the same as a host not asked.
	UnavailableReason string `json:"unavailable_reason,omitempty"`
}
