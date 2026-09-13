// Package power describes the power, boot and maintenance window state of the
// host.
//
// A restart does not end with sending the command: it ends when the host comes
// back with a new boot identifier and healthy units. That is why the module
// carries the boot_id, the uptime and what holds the restart back - not just
// the button.
package power

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// The paths the state is read from.
const (
	UptimePath = "/proc/uptime"
	BootIDPath = "/proc/sys/kernel/random/boot_id"
	// RebootRequiredFile appears when a package needs a restart; next to it lies
	// the list of the packages that asked for it.
	RebootRequiredFile    = "/var/run/reboot-required"
	RebootRequiredFileRun = "/run/reboot-required"
	PackagesFile          = "/var/run/reboot-required.pkgs"
	PackagesFileRun       = "/run/reboot-required.pkgs"
	ScheduledFile         = "/run/systemd/shutdown/scheduled"
	InhibitPath           = "/usr/bin/systemd-inhibit"
	JournalctlPath        = "/usr/bin/journalctl"
	SystemctlPath         = "/usr/bin/systemctl"
	RecentBootCount       = 5
)

// The shutdown modes the panel tells apart.
const (
	ModeReboot   = "reboot"
	ModePoweroff = "poweroff"
	ModeHalt     = "halt"
)

// Inhibitor is a logind inhibitor: a process that asks for a delay or blocks
// the shutdown of the host.
//
// Telling the modes apart matters here: "delay" postpones the shutdown by a
// given time, "block" does not allow it at all. A panel that does not tell them
// apart promises the operator a restart that will not happen.
type Inhibitor struct {
	Who  string `json:"who"`
	User string `json:"user,omitempty"`
	PID  uint32 `json:"pid,omitempty"`
	What string `json:"what,omitempty"`
	Why  string `json:"why,omitempty"`
	Mode string `json:"mode,omitempty"`
}

// Blocks says whether the inhibitor does not allow a shutdown at all.
func (b Inhibitor) Blocks() bool { return b.Mode == "block" }

// Boot is one entry of the boot list of the host.
type Boot struct {
	Index      int       `json:"index"`
	BootID     string    `json:"boot_id"`
	FirstEntry time.Time `json:"first_entry"`
	LastEntry  time.Time `json:"last_entry"`
}

// Shutdown describes a shutdown already scheduled on the host.
type Shutdown struct {
	Mode string    `json:"mode"`
	At   time.Time `json:"at"`
	// Owner says who scheduled it: the panel creates its own unit, so it can
	// tell its own shutdown from somebody else's.
	Owner string `json:"owner,omitempty"`
}

// Snapshot is the picture of the boot and the power of the host.
type Snapshot struct {
	BootID   string    `json:"boot_id,omitempty"`
	BootedAt time.Time `json:"booted_at,omitempty"`
	// UptimeSeconds is empty when /proc/uptime could not be read - a host
	// running for zero seconds does not exist.
	UptimeSeconds  *float64 `json:"uptime_seconds"`
	RunningKernel  string   `json:"running_kernel,omitempty"`
	RebootRequired *bool    `json:"reboot_required"`
	// RebootReasons lists the packages or reasons that asked for the restart.
	RebootReasons     []string    `json:"reboot_reasons,omitempty"`
	Inhibitors        []Inhibitor `json:"inhibitors,omitempty"`
	InhibitorsKnown   bool        `json:"inhibitors_known"`
	LastBoots         []Boot      `json:"last_boots,omitempty"`
	Scheduled         *Shutdown   `json:"scheduled_shutdown,omitempty"`
	ObservedAt        time.Time   `json:"observed_at"`
	UnavailableReason string      `json:"unavailable_reason,omitempty"`
}

// Blocking lists the inhibitors that do not allow a shutdown.
func (s Snapshot) Blocking() []Inhibitor {
	var inhibitors []Inhibitor
	for _, inhibitor := range s.Inhibitors {
		if inhibitor.Blocks() {
			inhibitors = append(inhibitors, inhibitor)
		}
	}
	return inhibitors
}

// DelayLimit bounds the delay of a shutdown. An order that is to run in a day
// is not an operation - it is a schedule.
const DelayLimit = 3600

// ReasonLength bounds the justification. The reason is a sentence for the
// human who will read the audit trail, not a place for an attachment.
const ReasonLength = 500

// ValidateShutdownReason checks the justification of a host shutdown.
//
// Shutting a remote host down needs an explicit reason: nobody will power it on
// remotely afterwards, so the audit trail is the only thing that stays.
func ValidateShutdownReason(reason string) error {
	reason = strings.TrimSpace(reason)
	if len(reason) < 10 {
		return fmt.Errorf("shutting the host down needs a reason; nobody will power it on remotely afterwards")
	}
	if len(reason) > ReasonLength {
		return fmt.Errorf("the reason is longer than %d characters", ReasonLength)
	}
	if strings.ContainsAny(reason, "\n\r") {
		return fmt.Errorf("the reason must not contain a newline")
	}
	return nil
}

// ValidateDelay checks the delay of the operation.
func ValidateDelay(seconds uint32) error {
	if seconds > DelayLimit {
		return fmt.Errorf("the delay exceeds an hour")
	}
	return nil
}

// ParseUptime reads the first number from /proc/uptime.
func ParseUptime(content string) *float64 {
	fields := strings.Fields(content)
	if len(fields) == 0 {
		return nil
	}
	seconds, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return nil
	}
	return &seconds
}

// ParseRebootReasons reads the list of the packages that asked for a restart.
func ParseRebootReasons(content string) []string {
	var reasons []string
	seen := map[string]bool{}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || seen[line] {
			continue
		}
		seen[line] = true
		reasons = append(reasons, line)
	}
	return reasons
}

// ParseInhibitors reads the table of "systemd-inhibit --list".
//
// The table is aligned to the width of the longest value in a column, so the
// positions of the headers mark the boundaries of the fields. Splitting on
// whitespace would not work: the column with the justification contains
// spaces.
func ParseInhibitors(output string) ([]Inhibitor, bool) {
	lines := strings.Split(strings.ReplaceAll(output, "\r\n", "\n"), "\n")
	header := -1
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "WHO") {
			header = i
			break
		}
	}
	if header < 0 {
		// "No inhibitors." is an answer, not the absence of one.
		return nil, strings.Contains(output, "No inhibitors")
	}

	boundaries := fieldBoundaries(lines[header], []string{"WHO", "UID", "USER", "PID", "COMM", "WHAT", "WHY", "MODE"})
	if boundaries == nil {
		return nil, false
	}

	var inhibitors []Inhibitor
	for _, line := range lines[header+1:] {
		if strings.TrimSpace(line) == "" || strings.Contains(line, "inhibitors listed") {
			continue
		}
		fields := cutFields(line, boundaries)
		if len(fields) < 8 || fields[0] == "" {
			continue
		}
		inhibitor := Inhibitor{Who: fields[0], User: fields[2], What: fields[5], Why: fields[6], Mode: fields[7]}
		if pid, err := strconv.ParseUint(fields[3], 10, 32); err == nil {
			inhibitor.PID = uint32(pid)
		}
		inhibitors = append(inhibitors, inhibitor)
	}
	return inhibitors, true
}

// fieldBoundaries determines the positions of the columns from the header
// line.
func fieldBoundaries(header string, columns []string) []int {
	boundaries := make([]int, 0, len(columns))
	searchFrom := 0
	for _, column := range columns {
		position := strings.Index(header[searchFrom:], column)
		if position < 0 {
			return nil
		}
		boundaries = append(boundaries, searchFrom+position)
		searchFrom += position + len(column)
	}
	return boundaries
}

func cutFields(line string, boundaries []int) []string {
	fields := make([]string, 0, len(boundaries))
	for i, start := range boundaries {
		if start > len(line) {
			fields = append(fields, "")
			continue
		}
		end := len(line)
		if i+1 < len(boundaries) && boundaries[i+1] < end {
			end = boundaries[i+1]
		}
		fields = append(fields, strings.TrimSpace(line[start:end]))
	}
	return fields
}

var bootLine = regexp.MustCompile(
	`^\s*(-?\d+)\s+([0-9a-f]{32})\s+(\S+ \S+ \S+ \S+)\s+(\S+ \S+ \S+ \S+)\s*$`)

// JournalTimeLayout is the form in which journalctl writes dates.
const JournalTimeLayout = "Mon 2006-01-02 15:04:05 MST"

// ParseBootList reads the output of "journalctl --list-boots".
func ParseBootList(output string) []Boot {
	var boots []Boot
	for _, line := range strings.Split(output, "\n") {
		match := bootLine.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		index, err := strconv.Atoi(match[1])
		if err != nil {
			continue
		}
		start := Boot{Index: index, BootID: match[2]}
		if moment, err := time.Parse(JournalTimeLayout, match[3]); err == nil {
			start.FirstEntry = moment.UTC()
		}
		if moment, err := time.Parse(JournalTimeLayout, match[4]); err == nil {
			start.LastEntry = moment.UTC()
		}
		boots = append(boots, start)
	}
	return boots
}

// ParseScheduled reads /run/systemd/shutdown/scheduled.
//
// The file says the host is going to shut down even though nobody from the
// panel asked for it. The operator is to see that before ordering anything
// else.
func ParseScheduled(content string) *Shutdown {
	shutdown := Shutdown{}
	for _, line := range strings.Split(content, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch key {
		case "USEC":
			micro, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return nil
			}
			shutdown.At = time.UnixMicro(micro).UTC()
		case "MODE":
			shutdown.Mode = value
		}
	}
	if shutdown.At.IsZero() {
		return nil
	}
	return &shutdown
}
