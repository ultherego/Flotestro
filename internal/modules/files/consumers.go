package files

import (
	"os"
	"path/filepath"
	"strings"
)

// Consumer is a service that reads a configuration file and therefore has to
// be told when the file changes.
type Consumer struct {
	// Unit is the systemd unit; "systemd" itself stands for the manager,
	// which re-reads unit files only on a daemon reload.
	Unit string `json:"unit"`
	// Action is reload, restart or daemon-reload.
	Action string `json:"action"`
	// Installed says whether the unit file is on this host.
	Installed bool `json:"installed"`
}

// Consumer actions.
const (
	ConsumerReload       = "reload"
	ConsumerRestart      = "restart"
	ConsumerDaemonReload = "daemon-reload"
)

// unitDirectories are the places a unit file lives.
var unitDirectories = []string{
	"/etc/systemd/system", "/run/systemd/system",
	"/usr/lib/systemd/system", "/lib/systemd/system",
}

// Consumers says which services read the file at the given path, and what they
// need after a change.
func Consumers(path string) ([]Consumer, string) {
	switch {
	case strings.HasPrefix(path, "/etc/nginx/"):
		return installed([]Consumer{{Unit: "nginx.service", Action: ConsumerReload}}), ""

	case strings.HasPrefix(path, "/etc/systemd/system/") &&
		(strings.HasSuffix(path, ".service") || strings.HasSuffix(path, ".timer")):
		// The manager has to re-read the unit file, and the unit itself has to be
		// restarted: a daemon reload alone leaves the running instance on the
		// settings it started with.
		return installed([]Consumer{
			{Unit: "systemd", Action: ConsumerDaemonReload},
			{Unit: filepath.Base(path), Action: ConsumerRestart},
		}), ""

	case strings.HasPrefix(path, "/etc/systemd/system/") && strings.HasSuffix(path, ".conf"):
		// A drop-in belongs to the unit named by the directory above it.
		unit := strings.TrimSuffix(filepath.Base(filepath.Dir(path)), ".d")
		consumers := []Consumer{{Unit: "systemd", Action: ConsumerDaemonReload}}
		if strings.Contains(unit, ".") {
			consumers = append(consumers, Consumer{Unit: unit, Action: ConsumerRestart})
		}
		return installed(consumers), ""

	case strings.HasPrefix(filepath.Base(path), "chrony"), strings.HasPrefix(path, "/etc/chrony"):
		// The name of the time service differs between the families, so both
		// are named and the host says which one it has.
		return installed([]Consumer{
			{Unit: "chronyd.service", Action: ConsumerRestart},
			{Unit: "chrony.service", Action: ConsumerRestart},
		}), ""

	case strings.HasPrefix(path, "/etc/sysctl.d/"), path == "/etc/sysctl.conf":
		return installed([]Consumer{
			{Unit: "systemd-sysctl.service", Action: ConsumerRestart},
		}), ""

	case strings.HasPrefix(path, "/etc/security/limits.d/"):
		return nil, "the limits are read when a session is opened, so they apply to new logins and not to the processes already running"

	case strings.HasPrefix(path, "/etc/logrotate.d/"):
		return nil, "logrotate reads its configuration at every run, so nothing has to be reloaded"

	case path == "/etc/hosts", path == "/etc/motd", path == "/etc/issue":
		return nil, "the file is read at every use, so nothing has to be reloaded"
	}
	return nil, "the panel knows of no service that reads this path; a configuration that includes it may still need a reload"
}

// installed fills in, for each consumer, whether this host has the unit at
// all.
func installed(consumers []Consumer) []Consumer {
	for i := range consumers {
		if consumers[i].Unit == "systemd" {
			consumers[i].Installed = true
			continue
		}
		consumers[i].Installed = unitExists(consumers[i].Unit)
	}
	return consumers
}

// unitExists says whether a unit file of that name lies in one of the places
// systemd reads.
func unitExists(unit string) bool {
	if unit == "" || strings.ContainsRune(unit, '/') {
		return false
	}
	for _, directory := range unitDirectories {
		if _, err := os.Lstat(filepath.Join(directory, unit)); err == nil {
			return true
		}
	}
	return false
}
