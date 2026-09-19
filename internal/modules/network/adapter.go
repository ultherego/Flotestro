package network

import "os"

// Write adapter names.
const (
	AdapterNetworkManager = "networkmanager"
	AdapterNmstate        = "nmstate"
	AdapterNetplan        = "netplan"
)

// DetectAdapter names the mechanism the network configuration can be changed
// with.
func DetectAdapter(exists func(string) bool) string {
	switch {
	case exists("/usr/bin/nmstatectl") || exists("/usr/sbin/nmstatectl"):
		return AdapterNmstate
	case exists("/usr/bin/nmcli") && exists("/run/NetworkManager"):
		return AdapterNetworkManager
	case exists("/usr/sbin/netplan") && exists("/etc/netplan"):
		return AdapterNetplan
	}
	return ""
}

// Exists checks the presence of a path in the filesystem.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// ReadOnlyReason explains why the panel will not change the configuration
// here.
func ReadOnlyReason(adapter string) string {
	if adapter != "" {
		return ""
	}
	return "this host has no NetworkManager, nmstate or netplan; network configuration is read-only here"
}
