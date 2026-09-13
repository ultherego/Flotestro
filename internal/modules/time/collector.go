package hosttime

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Runner runs a host tool and returns its output.
//
// State collection lives here, not in the agent, because two sides need
// it: the agent at every inventory cycle and the helper right after a
// change, to say whether the change took effect. The injected runner keeps
// the package testable without running anything.
type Runner func(ctx context.Context, path string, args ...string) (string, error)

const systemctlPath = "/usr/bin/systemctl"

// timeUnits lists the time daemon units in the order of checking. Debian
// calls chrony chrony.service, Fedora chronyd.service.
var timeUnits = []string{"chronyd.service", "chrony.service", "systemd-timesyncd.service"}

// Collect reads the host time state.
//
// The read needs no root: timedatectl asks the services over the bus,
// chronyc talks to the daemon over the loopback, and the time
// configuration files are readable by everyone.
func Collect(ctx context.Context, run Runner) Snapshot {
	now := time.Now()
	_, offset := now.Zone()
	snapshot := Snapshot{
		Now:              now,
		UTCOffsetSeconds: &offset,
		ObservedAt:       now.UTC(),
	}

	if output, err := run(ctx, TimedatectlPath, "show"); err == nil {
		fromTimedatectl := ParseTimedatectl(output)
		snapshot.Timezone = fromTimedatectl.Timezone
		snapshot.RTCInLocalTime = fromTimedatectl.RTCInLocalTime
		snapshot.NTPEnabled = fromTimedatectl.NTPEnabled
		snapshot.Synchronized = fromTimedatectl.Synchronized
	} else {
		snapshot.Timezone = zoneFromFiles()
		snapshot.UnavailableReason = "timedatectl: " + err.Error()
	}

	snapshot.Unit, snapshot.ServiceActive = daemonUnit(ctx, run)

	// Chrony is asked whenever its client is present: it has the offset
	// measurement timesyncd does not compute at all.
	if exists(ChronycPath) {
		if output, err := run(ctx, ChronycPath, "-c", "tracking"); err == nil {
			fromChrony := ParseTracking(output)
			copyChrony(&snapshot, fromChrony)
			if sources, err := run(ctx, ChronycPath, "-c", "sources"); err == nil {
				snapshot.Sources = ParseSources(sources)
			}
			readChronyConfiguration(&snapshot)
			return snapshot
		}
	}

	if output, err := run(ctx, TimedatectlPath, "show-timesync", "--all"); err == nil {
		snapshot.Service = DaemonTimesyncd
		state := ParseTimesync(output, "timesyncd.conf")
		copyTimesyncd(&snapshot, state)
		readTimesyncdConfiguration(&snapshot)
		return snapshot
	}

	// A host without a time daemon is not a host synchronised with an
	// unknown source - it is a host whose clock nobody watches.
	snapshot.WriteReason = "this host runs neither chrony nor systemd-timesyncd"
	if snapshot.UnavailableReason == "" && snapshot.Service == "" {
		snapshot.UnavailableReason = snapshot.WriteReason
	}
	return snapshot
}

// copyChrony moves the chrony measurement into the host picture.
func copyChrony(snapshot *Snapshot, fromChrony Snapshot) {
	snapshot.Service = DaemonChrony
	snapshot.ReferenceName = fromChrony.ReferenceName
	snapshot.Stratum = fromChrony.Stratum
	snapshot.OffsetSeconds = fromChrony.OffsetSeconds
	snapshot.FrequencyPPM = fromChrony.FrequencyPPM
	snapshot.RootDelaySeconds = fromChrony.RootDelaySeconds
	snapshot.RootDispersionSeconds = fromChrony.RootDispersionSeconds
	snapshot.LeapStatus = fromChrony.LeapStatus
	snapshot.LastSyncAt = fromChrony.LastSyncAt
	// The daemon's answer is closer to the truth than the timedatectl one:
	// timedated says whether any service reports synchronisation, and
	// chrony knows whether it selected a source.
	if fromChrony.Synchronized != nil {
		snapshot.Synchronized = fromChrony.Synchronized
	}
}

func copyTimesyncd(snapshot *Snapshot, state TimesyncdState) {
	snapshot.ReferenceName = state.ServerName
	if snapshot.ReferenceName == "" {
		snapshot.ReferenceName = state.ServerAddress
	}
	snapshot.Stratum = state.Stratum
	snapshot.RootDelaySeconds = state.RootDelay
	snapshot.RootDispersionSeconds = state.RootDispersion
	snapshot.LeapStatus = state.LeapStatus
	snapshot.FrequencyPPM = state.FrequencyPPM
	snapshot.Configured = append(snapshot.Configured, state.Servers...)
}

// daemonUnit points at the time daemon unit and its state.
//
// The load state is asked for, not "is-active": systemd answers "inactive"
// also about a unit the host does not have, so that state alone would make
// the panel name chrony on a host without chrony. One call covers all the
// candidates, because the inventory is meant to be light.
func daemonUnit(ctx context.Context, run Runner) (string, *bool) {
	args := append([]string{"show", "-p", "Id", "-p", "LoadState", "-p", "ActiveState"}, timeUnits...)
	output, err := run(ctx, systemctlPath, args...)
	if err != nil && strings.TrimSpace(output) == "" {
		return "", nil
	}

	// Records are separated by an empty line, and the property order in a
	// record is not guaranteed - so records are read, not lines.
	var firstLoaded string
	for _, record := range strings.Split(strings.ReplaceAll(output, "\r\n", "\n"), "\n\n") {
		name, loaded, active := readUnitRecord(record)
		if name == "" || !loaded {
			continue
		}
		if active {
			yes := true
			return name, &yes
		}
		if firstLoaded == "" {
			firstLoaded = name
		}
	}
	if firstLoaded == "" {
		return "", nil
	}
	no := false
	return firstLoaded, &no
}

func readUnitRecord(record string) (name string, loaded, active bool) {
	for _, line := range strings.Split(record, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch key {
		case "Id":
			name = value
		case "LoadState":
			loaded = value != "not-found" && value != "masked"
		case "ActiveState":
			active = value == "active" || value == "activating"
		}
	}
	return name, loaded, active
}

// readChronyConfiguration points at the panel file and lists the servers
// from the files.
func readChronyConfiguration(snapshot *Snapshot) {
	main, content := chronyMainConfiguration()
	if main == "" {
		snapshot.WriteReason = "this host has no chrony configuration file"
		return
	}
	snapshot.ConfigPath = main
	snapshot.Configured = append(snapshot.Configured, ParseServers(content, filepath.Base(main), false)...)

	dir, kind := DropInDir(content)
	if dir == "" {
		// The panel does not rewrite the main chrony file, so a host
		// without an included directory is read-only for the panel - and
		// says so directly instead of writing a file the daemon never
		// reads.
		snapshot.WriteReason = "chrony on this host includes no drop-in directory; " +
			"the panel does not rewrite " + main + " unless you let it add its own sources directory"
		snapshot.CanAddSourceDir = true
		return
	}
	snapshot.ManagedPath = filepath.Join(dir, ChronyFileName(kind))
	if managed, err := os.ReadFile(snapshot.ManagedPath); err == nil {
		snapshot.Managed = string(managed)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		path := filepath.Join(dir, name)
		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		snapshot.Configured = append(snapshot.Configured,
			ParseServers(string(content), name, path == snapshot.ManagedPath)...)
	}
}

// readTimesyncdConfiguration marks the panel entries on the daemon's list.
//
// The list timesyncd reports is the list in effect; the panel file only
// says who wrote it. Appending the same addresses a second time would show
// every server twice. An entry written by the panel that the daemon does
// not list is added separately - it means the write did not take effect.
func readTimesyncdConfiguration(snapshot *Snapshot) {
	snapshot.ManagedPath = TimesyncdFile
	managed, err := os.ReadFile(TimesyncdFile)
	if err != nil {
		return
	}
	snapshot.Managed = string(managed)
	ours := map[string]bool{}
	for _, server := range ParseTimesyncdNTP(snapshot.Managed, filepath.Base(TimesyncdFile), true) {
		ours[server.Address] = true
	}
	for i := range snapshot.Configured {
		if ours[snapshot.Configured[i].Address] {
			snapshot.Configured[i].Managed = true
			delete(ours, snapshot.Configured[i].Address)
		}
	}
	for _, server := range ParseTimesyncdNTP(snapshot.Managed, filepath.Base(TimesyncdFile), true) {
		if ours[server.Address] {
			snapshot.Configured = append(snapshot.Configured, server)
		}
	}
}

// chronyMainConfiguration returns the first existing main file and its
// content.
func chronyMainConfiguration() (string, string) {
	for _, path := range ChronyMainConfigurations {
		content, err := os.ReadFile(path)
		if err == nil {
			return path, string(content)
		}
	}
	return "", ""
}

// zoneFromFiles reads the zone from the host configuration when there is
// no timedatectl.
func zoneFromFiles() string {
	if content, err := os.ReadFile("/etc/timezone"); err == nil {
		if zone := strings.TrimSpace(string(content)); zone != "" {
			return zone
		}
	}
	target, err := filepath.EvalSymlinks("/etc/localtime")
	if err != nil {
		return ""
	}
	if _, zone, ok := strings.Cut(target, ZoneDir+"/"); ok {
		return zone
	}
	return ""
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
