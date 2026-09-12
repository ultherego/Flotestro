package agent

import (
	"context"
	"os"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"strings"
	"time"
)

// privilegedIdentity is an optional source of data that needs root. Without it
// the inventory is still built, but without the keytab and the SSSD state.
var privilegedIdentity func(context.Context, string) (PrivilegedIdentity, error)

// SetPrivilegedIdentityProbe points at the function that reads the privileged
// part of the domain state. The agent uses the root helper for that.
func SetPrivilegedIdentityProbe(probe func(context.Context, string) (PrivilegedIdentity, error)) {
	privilegedIdentity = probe
}

// privilegedAccounts fills the accounts in with the lock state and the SSH
// keys. Reading /etc/shadow and the home directories belongs to root.
var privilegedAccounts func(context.Context, []string) (*helperv1.LocalAccountsResult, error)

// SetPrivilegedAccountProbe points at the function that reads the privileged
// part of the account data.
func SetPrivilegedAccountProbe(probe func(context.Context, []string) (*helperv1.LocalAccountsResult, error)) {
	privilegedAccounts = probe
}

// Collect gathers the full inventory. This function can start child processes,
// which is why it is called in the inventory cycle and never in the heartbeat.
func Collect(ctx context.Context) (Facts, error) {
	return CollectFrom(ctx, "")
}

// CollectFrom gathers the inventory knowing the address the host talks to the
// panel through. Without that address the network module cannot point at the
// management interface, and guessing it from the first entry of the list ends
// with a change to the configuration of the interface the command just came
// through.
func CollectFrom(ctx context.Context, managementAddress string) (Facts, error) {
	return CollectModules(ctx, managementAddress, Facts{}, nil)
}

// CollectModules gathers the inventory limited to the given modules.
//
// An empty list means the whole inventory. A non-empty list means a partial
// refresh: only the given modules are collected and the rest is carried over
// from the previous picture. Otherwise the inventory after refreshing one
// module would be a picture of a host without all the rest - and that is not
// the same as a host that does not have that rest.
//
// The basic facts - the identity of the machine, the system, the hardware, the
// capabilities - are always collected. They are cheap and they are what decides
// which modules make sense.
func CollectModules(ctx context.Context, managementAddress string,
	previous Facts, modules []string) (Facts, error) {
	machineID, err := MachineID()
	if err != nil {
		return Facts{}, err
	}
	hostname, _ := os.Hostname()
	caps := DetectCapabilities()

	facts := Facts{
		Hostname:     hostname,
		MachineID:    machineID,
		BootID:       BootID(),
		OS:           ReadOSInfo(),
		Hardware:     ReadHardware(),
		Capabilities: caps,
		Interfaces:   networkInterfaces(),
		CollectedAt:  time.Now().UTC(),
	}
	facts.RebootRequired = rebootRequired(ctx, caps)

	selected := moduleSet(modules)
	for _, name := range ModuleOrder {
		collector := moduleCollectors[name]
		if len(selected) > 0 && !selected[name] {
			// A module outside the scope of the refresh stays as it was. The
			// carry-over is deliberate: missing data would mean the host does
			// not have it, and it simply was not asked in this cycle.
			collector.carry(&facts, previous)
			continue
		}
		collector.collect(ctx, &facts, managementAddress)
	}
	return facts, nil
}

// moduleSet turns a list of names into a set. An empty input gives an empty
// set, which means "everything".
func moduleSet(modules []string) map[string]bool {
	if len(modules) == 0 {
		return nil
	}
	set := make(map[string]bool, len(modules))
	for _, name := range modules {
		name = strings.ToLower(strings.TrimSpace(name))
		if name != "" {
			set[name] = true
		}
	}
	return set
}

// failedUnits returns the names of the units in the failed state together with
// whether they could be determined at all. A failed query must not look like
// zero units in error.
func failedUnits(ctx context.Context) ([]string, bool) {
	result := runCommand(ctx, 15*time.Second,
		"/usr/bin/systemctl", "list-units", "--failed", "--no-legend", "--plain", "--no-pager")
	if !result.Ran || result.ExitCode != 0 {
		return nil, false
	}
	var units []string
	for _, line := range strings.Split(result.Stdout, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && strings.Contains(fields[0], ".") {
			units = append(units, fields[0])
		}
	}
	return units, true
}

// aptSummary counts the packages to upgrade through a simulation that changes
// no system state and needs no dpkg lock.
func aptSummary(ctx context.Context) Packages {
	summary := Packages{Manager: "apt"}

	if result := runCommand(ctx, 30*time.Second,
		"/usr/bin/dpkg-query", "-f", "${binary:Package}\n", "-W"); result.Ran && result.ExitCode == 0 {
		installed := uint32(len(strings.Fields(result.Stdout)))
		summary.Installed = &installed
	}

	result := runCommand(ctx, 120*time.Second,
		"/usr/bin/apt-get", "--simulate", "--quiet", "-o", "Debug::NoLocking=true", "upgrade")
	if !result.Ran || result.ExitCode != 0 {
		summary.UnavailableReason = result.Reason()
		return summary
	}

	var upgradable, security uint32
	for _, line := range strings.Split(result.Stdout, "\n") {
		if !strings.HasPrefix(line, "Inst ") {
			continue
		}
		upgradable++
		// The origin is in brackets at the end of the line; the security
		// repository of Debian and Ubuntu carries "-security" in its name.
		if strings.Contains(line, "-security") || strings.Contains(line, "Debian-Security") {
			security++
		}
	}
	summary.Upgradable = &upgradable
	summary.SecurityUpgradable = &security
	return summary
}

// dnfSummary counts the updates without refreshing the metadata. check-update
// returns 0 when there are no updates and 100 when there are some. Every other
// code is an execution error, not the number zero.
func dnfSummary(ctx context.Context) Packages {
	summary := Packages{Manager: "dnf"}

	if result := runCommand(ctx, 30*time.Second,
		"/usr/bin/rpm", "-qa", "--qf", "%{NAME}\n"); result.Ran && result.ExitCode == 0 {
		installed := uint32(len(strings.Fields(result.Stdout)))
		summary.Installed = &installed
	}

	result := runCommand(ctx, 180*time.Second,
		"/usr/bin/dnf", "--quiet", "--cacheonly", "check-update")
	if !result.Ran || (result.ExitCode != 0 && result.ExitCode != 100) {
		summary.UnavailableReason = result.Reason()
		return summary
	}

	var upgradable uint32
	for _, line := range strings.Split(result.Stdout, "\n") {
		fields := strings.Fields(line)
		// An update line is: name.arch  version  repository.
		if len(fields) == 3 && strings.Contains(fields[0], ".") && !strings.HasPrefix(line, " ") {
			upgradable++
		}
	}
	summary.Upgradable = &upgradable
	// Fedora does not publish consistent security metadata for all repositories,
	// so the security counter stays undetermined instead of a false zero.
	return summary
}

// rebootRequired checks the restart marker proper to the distribution. It
// returns nil when the state cannot be determined.
func rebootRequired(ctx context.Context, caps Capabilities) *bool {
	if exists("/var/run/reboot-required") || exists("/run/reboot-required") {
		return boolPtr(true)
	}
	if caps.Available(CapAPT) {
		// On Debian a missing file is an unambiguous answer.
		return boolPtr(false)
	}
	if caps.Available(CapDNF) {
		return interpretNeedsRestarting(
			runCommand(ctx, 60*time.Second, "/usr/bin/dnf", "needs-restarting", "-r"))
	}
	return nil
}

// interpretNeedsRestarting translates the result of "dnf needs-restarting -r"
// into an answer about a restart. The tool returns 0 when none is needed and 1
// when a restart is required - but an execution error, for example a HOME that
// is not writable, ends with the same code. Code 1 is therefore trusted only
// when the tool printed something on stdout; on an error it stays silent there
// and writes to stderr.
func interpretNeedsRestarting(result commandResult) *bool {
	switch {
	case !result.Ran:
		return nil
	case result.ExitCode == 0:
		return boolPtr(false)
	case result.ExitCode == 1 && strings.TrimSpace(result.Stdout) != "":
		return boolPtr(true)
	default:
		return nil
	}
}

func boolPtr(value bool) *bool { return &value }
