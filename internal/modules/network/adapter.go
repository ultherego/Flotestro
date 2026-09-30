package network

import (
	"os"
	"path/filepath"
)

// Write adapter names.
const (
	AdapterNetworkManager = "networkmanager"
	AdapterNmstate        = "nmstate"
	AdapterNetplan        = "netplan"
)

// SystemdUnitDir holds the administrator's units, and is where systemd records
// a mask.
const SystemdUnitDir = "/etc/systemd/system"

// NetworkdUnit is the renderer netplan hands a configuration to where
// NetworkManager is not the one running.
const NetworkdUnit = "systemd-networkd.service"

// The directories a distribution ships its units in.
var unitDirs = []string{"/usr/lib/systemd/system", "/lib/systemd/system", SystemdUnitDir}

// DetectAdapter names the mechanism the network configuration can be changed
// with.
func DetectAdapter(exists func(string) bool, masked func(string) bool) string {
	switch {
	case exists("/usr/bin/nmstatectl") || exists("/usr/sbin/nmstatectl"):
		return AdapterNmstate
	case exists("/usr/bin/nmcli") && exists("/run/NetworkManager"):
		return AdapterNetworkManager
	case netplanInstalled(exists) && NetplanRenders(exists, masked):
		return AdapterNetplan
	}
	return ""
}

// netplanInstalled says whether the host has netplan and its configuration
// directory at all.
func netplanInstalled(exists func(string) bool) bool {
	return exists(NetplanPath) && exists(NetplanDir)
}

// NetplanRenders says whether netplan has a renderer that can carry a change
// here. netplan configures nothing itself: it renders to systemd-networkd or to
// NetworkManager, and with neither able to run the change is written, applied to
// nothing and reverted at the end of the trial.
func NetplanRenders(exists func(string) bool, masked func(string) bool) bool {
	if exists("/run/NetworkManager") {
		return true
	}
	return unitInstalled(exists, NetworkdUnit) && !masked(NetworkdUnit)
}

// unitInstalled says whether a systemd unit file is on the host.
func unitInstalled(exists func(string) bool, unit string) bool {
	for _, dir := range unitDirs {
		if exists(filepath.Join(dir, unit)) {
			return true
		}
	}
	return false
}

// MaskedUnit says whether a systemd unit is masked. systemd records a mask as a
// symlink to /dev/null, so the answer is on disk and needs no query to systemd -
// which matters here: the helper decides this before it starts anything.
func MaskedUnit(unit string) bool { return unitMaskedIn(SystemdUnitDir, unit) }

// unitMaskedIn reads the mask out of one directory of units.
func unitMaskedIn(dir, unit string) bool {
	target, err := os.Readlink(filepath.Join(dir, unit))
	return err == nil && target == os.DevNull
}

// Exists checks the presence of a path in the filesystem.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// ReadOnlyReason explains why the panel will not change the configuration
// here.
func ReadOnlyReason(adapter string, exists func(string) bool, masked func(string) bool) string {
	if adapter != "" {
		return ""
	}
	if netplanInstalled(exists) && !NetplanRenders(exists, masked) {
		return "netplan is installed here but has no renderer that can apply it: " +
			"systemd-networkd is masked or absent and NetworkManager is not running, " +
			"so a change would be written and never take effect; network configuration is read-only here"
	}
	return "this host has no NetworkManager, nmstate or netplan; network configuration is read-only here"
}
