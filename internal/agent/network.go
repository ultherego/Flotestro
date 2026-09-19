package agent

import (
	"context"
	"os/exec"
	"time"

	"github.com/ultherego/flotestro/internal/modules/network"
)

// ipPaths lists the places where the iproute2 tool sits. The path is fixed and
// not looked up in PATH: the agent runs only known binaries.
var ipPaths = []string{"/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip"}

// CollectNetwork reads the interfaces and the routes of the host. The read
// needs no root: the kernel tables are readable by everyone.
func CollectNetwork(ctx context.Context, managementAddress string) network.Snapshot {
	snapshot := network.Snapshot{ObservedAt: time.Now().UTC()}

	path := ipPath()
	if path == "" {
		snapshot.UnavailableReason = "this host has no iproute2 (ip) binary"
		return snapshot
	}

	// The -d flag adds linkinfo, and with it the kind of the interface.
	output, err := ipOutput(ctx, path, "-j", "-d", "addr", "show")
	if err != nil {
		snapshot.UnavailableReason = "ip addr: " + err.Error()
		return snapshot
	}
	interfaces, err := network.ParseInterfaces(output)
	if err != nil {
		snapshot.UnavailableReason = err.Error()
		return snapshot
	}
	network.SupplementFromSys("/sys/class/net", interfaces)
	snapshot.Interfaces = interfaces

	// The layering is read on top of the addresses: "ip addr" names an interface
	// a bond and says nothing about what it is made of, and the operator asking
	// about a bond is asking exactly that.
	network.ReadLayering(&snapshot, func(arguments []string) (string, error) {
		return ipOutput(ctx, arguments[0], arguments[1:]...)
	})
	network.ReadIPv6(&snapshot)

	// Both families are read separately, because "ip route show" shows only IPv4
	// by default.
	for _, family := range []struct {
		flag   string
		family string
	}{{"-4", network.FamilyIPv4}, {"-6", network.FamilyIPv6}} {
		output, err := ipOutput(ctx, path, "-j", family.flag, "route", "show")
		if err != nil {
			continue
		}
		if routes, err := network.ParseRoutes(output, family.family); err == nil {
			snapshot.Routes = append(snapshot.Routes, routes...)
		}
	}

	network.MarkManagementChannel(&snapshot, managementAddress)
	snapshot.WriteAdapter = network.DetectAdapter(network.Exists)
	return snapshot
}

func ipPath() string {
	for _, path := range ipPaths {
		if network.Exists(path) {
			return path
		}
	}
	return ""
}

func ipOutput(ctx context.Context, path string, arguments ...string) (string, error) {
	callCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(callCtx, path, arguments...)
	cmd.Env = []string{"LC_ALL=C", "LANG=C"}
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(output), nil
}
