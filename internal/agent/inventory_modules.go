package agent

import (
	"context"

	"github.com/ultherego/flotestro/internal/modules/certificates"
	"github.com/ultherego/flotestro/internal/modules/docker"
	"github.com/ultherego/flotestro/internal/modules/files"
	"github.com/ultherego/flotestro/internal/modules/firewall"
	"github.com/ultherego/flotestro/internal/modules/kernel"
	"github.com/ultherego/flotestro/internal/modules/schedules"
	"github.com/ultherego/flotestro/internal/modules/security"
	sshmodule "github.com/ultherego/flotestro/internal/modules/ssh"
)

// ModuleOrder fixes the order of the collection.
//
// The order is explicit, because a map has none and the inventory is to be
// built the same way in every cycle: a revision computed from facts collected
// in a different order is still the same, but the collection time and the load
// on the host are not.
//
// The names are the same ones the inventory is split into fragments by - the
// operator asks to refresh what they are looking at, not an internal field of
// the facts. ModuleSystem has no entry here: the basic facts are always
// collected, because they are what decides which of the other modules make
// sense.
var ModuleOrder = []string{
	ModuleServices, ModulePackages, ModuleIdentity, ModuleAccounts, ModuleContainers,
	ModuleSchedules, ModuleNetwork, ModuleDNS, ModuleStorage, ModuleFiles,
	ModuleKernel, ModuleSecurity, ModuleBackups, ModuleCerts, ModulePower,
	ModuleTime, ModuleSSH, ModuleFirewall,
}

// InventoryModule knows one module: it can collect it and it can carry over the
// previous result when a refresh does not cover it.
type InventoryModule struct {
	collect func(ctx context.Context, facts *Facts, managementAddress string)
	carry   func(facts *Facts, previous Facts)
}

var moduleCollectors = map[string]InventoryModule{
	ModuleServices: {
		collect: func(ctx context.Context, facts *Facts, _ string) {
			if facts.Capabilities.Available(CapSystemd) {
				facts.FailedUnits, facts.FailedUnitsKnown = failedUnits(ctx)
			}
		},
		carry: func(facts *Facts, previous Facts) {
			facts.FailedUnits, facts.FailedUnitsKnown = previous.FailedUnits, previous.FailedUnitsKnown
		},
	},

	ModulePackages: {
		collect: func(ctx context.Context, facts *Facts, _ string) {
			switch {
			case facts.Capabilities.Available(CapAPT):
				facts.Packages = aptSummary(ctx)
			case facts.Capabilities.Available(CapDNF):
				facts.Packages = dnfSummary(ctx)
			}
			// The digest of the full package list: the list itself is too big to
			// travel in every cycle, but the panel has to know when its copy
			// stops describing the host.
			if facts.Packages.Manager != "" {
				digest, count, reason := packageDigest(ctx, facts.Packages.Manager)
				facts.Packages.InstalledDigest = digest
				facts.Packages.InstalledReason = reason
				if reason == "" {
					number := uint32(count)
					facts.Packages.InstalledCount = &number
				}
				// The package sources are read together with the summary: it is
				// one tab and one answer to the question of where the host takes
				// its software from. The read goes without root, because the
				// files are public.
				snapshot := CollectRepositories(facts.Packages.Manager)
				facts.Repositories = &snapshot
			}
		},
		carry: func(facts *Facts, previous Facts) {
			facts.Packages = previous.Packages
			facts.Repositories = previous.Repositories
		},
	},

	ModuleIdentity: {
		collect: func(ctx context.Context, facts *Facts, _ string) {
			// The domain state is part of the inventory, so it is collected once
			// per cycle and not at every heartbeat.
			facts.Identity = ReadIdentityState(ctx)
			if facts.Identity.Enrolled && privilegedIdentity != nil {
				privileged, err := privilegedIdentity(ctx, facts.Identity.Domain)
				if err != nil {
					// Missing privileged data does not invalidate the rest of
					// the inventory, but it has to show as a reason and not as
					// silence.
					facts.Identity.UnavailableReason = "helper: " + err.Error()
					return
				}
				facts.Identity = facts.Identity.Merge(privileged)
			}
		},
		carry: func(facts *Facts, previous Facts) { facts.Identity = previous.Identity },
	},

	ModuleAccounts: {
		collect: func(ctx context.Context, facts *Facts, _ string) {
			// The local accounts are read from the file; the lock state and the
			// SSH keys need root and are filled in by the helper.
			facts.LocalAccounts = ReadLocalAccounts()
			if privilegedAccounts == nil {
				return
			}
			names := make([]string, 0, len(facts.LocalAccounts))
			for _, account := range facts.LocalAccounts {
				if account.Source == SourceLocal {
					names = append(names, account.Name)
				}
			}
			if len(names) == 0 {
				return
			}
			if result, err := privilegedAccounts(ctx, names); err == nil {
				facts.LocalAccounts = mergePrivilegedAccounts(facts.LocalAccounts, result)
			}
		},
		carry: func(facts *Facts, previous Facts) { facts.LocalAccounts = previous.LocalAccounts },
	},

	ModuleContainers: {
		collect: func(ctx context.Context, facts *Facts, _ string) {
			// The container engine is queried once per inventory cycle and only
			// for the summary. The full lists are fetched by the operator when
			// they open the tab - querying the engine in every cycle would load
			// the host for no reason.
			if !facts.Capabilities.Available(CapDocker) || dockerProbe == nil {
				return
			}
			snapshot, err := dockerProbe(ctx, false)
			if err != nil {
				// An engine that was not read must not look like a host without
				// containers.
				facts.Containers = &docker.Summary{UnavailableReason: "helper: " + err.Error()}
				return
			}
			summary := snapshot.Summary
			facts.Containers = &summary
		},
		carry: func(facts *Facts, previous Facts) { facts.Containers = previous.Containers },
	},

	ModuleSchedules: {
		collect: func(ctx context.Context, facts *Facts, _ string) {
			// Schedules change rarely, so they travel in the inventory cycle and
			// not on request: the full list of recurring jobs of a host is a
			// dozen or so entries, not hundreds as with packages.
			if !facts.Capabilities.Available(CapSchedules) || scheduleProbe == nil {
				return
			}
			snapshot, err := scheduleProbe(ctx)
			if err != nil {
				facts.Schedules = &schedules.Snapshot{UnavailableReason: "helper: " + err.Error()}
				return
			}
			facts.Schedules = &snapshot
		},
		carry: func(facts *Facts, previous Facts) { facts.Schedules = previous.Schedules },
	},

	ModuleNetwork: {
		collect: func(ctx context.Context, facts *Facts, managementAddress string) {
			// The network is read from the kernel in every cycle: the read is
			// cheap and the state can change without the panel (DHCP, a cable, a
			// container).
			network := CollectNetwork(ctx, managementAddress)
			facts.Network = &network
		},
		carry: func(facts *Facts, previous Facts) { facts.Network = previous.Network },
	},

	ModuleDNS: {
		collect: func(ctx context.Context, facts *Facts, _ string) {
			// The resolver is read together with the network: it is one decision
			// of the host about where its questions go and by which route.
			resolver := CollectDNS(ctx)
			facts.DNS = &resolver
		},
		carry: func(facts *Facts, previous Facts) { facts.DNS = previous.DNS },
	},

	ModuleStorage: {
		collect: func(ctx context.Context, facts *Facts, _ string) {
			// The disk topology changes rarely, but the space usage does not -
			// that is why the whole thing is read once per inventory cycle.
			storage := CollectStorage(ctx)
			facts.Storage = &storage
		},
		carry: func(facts *Facts, previous Facts) { facts.Storage = previous.Storage },
	},

	ModuleFiles: {
		collect: func(ctx context.Context, facts *Facts, _ string) {
			// The state of the managed files: the host itself knows which files
			// the panel has written, so a drift shows without asking the panel
			// for a list.
			if fileProbe == nil {
				return
			}
			snapshot, err := fileProbe(ctx)
			if err != nil {
				facts.Files = &files.Snapshot{UnavailableReason: "helper: " + err.Error()}
				return
			}
			facts.Files = &snapshot
		},
		carry: func(facts *Facts, previous Facts) { facts.Files = previous.Files },
	},

	ModuleKernel: {
		collect: func(ctx context.Context, facts *Facts, _ string) {
			// The kernel settings are read by the helper: some /proc/sys keys are
			// readable only by root, and the module list needs its eyes anyway.
			if kernelProbe == nil {
				return
			}
			snapshot, err := kernelProbe(ctx)
			if err != nil {
				facts.Kernel = &kernel.Snapshot{UnavailableReason: "helper: " + err.Error()}
				return
			}
			facts.Kernel = &snapshot
		},
		carry: func(facts *Facts, previous Facts) { facts.Kernel = previous.Kernel },
	},

	ModuleSecurity: {
		collect: func(ctx context.Context, facts *Facts, _ string) {
			// The protection state is assembled by the agent: most facts are
			// readable without root, and those that are not it orders from the
			// helper by name.
			if securityProbe == nil {
				return
			}
			snapshot, err := securityProbe(ctx)
			if err != nil {
				facts.Security = &security.Snapshot{UnavailableReason: err.Error()}
				return
			}
			facts.Security = &snapshot
		},
		carry: func(facts *Facts, previous Facts) { facts.Security = previous.Security },
	},

	ModuleBackups: {
		collect: func(ctx context.Context, facts *Facts, _ string) {
			// The backup tools are read by the agent without root: the presence
			// of the binary and its version are public. The state of the
			// repository is not here - that one needs credentials.
			backupState := CollectBackup(ctx)
			facts.Backup = &backupState
		},
		carry: func(facts *Facts, previous Facts) { facts.Backup = previous.Backup },
	},

	ModuleCerts: {
		collect: func(ctx context.Context, facts *Facts, _ string) {
			// The certificates are read by the agent, and the helper adds what
			// cannot be seen without root. The scope is enumerated: the registry
			// of panel targets and the certmonger requests, not a search of the
			// file system.
			if certificateProbe == nil {
				return
			}
			snapshot, err := certificateProbe(ctx)
			if err != nil {
				facts.Certificates = &certificates.Snapshot{UnavailableReason: err.Error()}
				return
			}
			facts.Certificates = &snapshot
		},
		carry: func(facts *Facts, previous Facts) { facts.Certificates = previous.Certificates },
	},

	ModulePower: {
		collect: func(ctx context.Context, facts *Facts, _ string) {
			// The boot state and the shutdown inhibitors. A restart does not end
			// with sending the command, so the panel needs the boot_id and what
			// holds the restart back.
			powerState := CollectPower(ctx, facts.BootID, facts.RebootRequired)
			facts.Power = &powerState
		},
		carry: func(facts *Facts, previous Facts) { facts.Power = previous.Power },
	},

	ModuleTime: {
		collect: func(ctx context.Context, facts *Facts, _ string) {
			// The time is read by the agent and not by the helper: timedatectl
			// and chronyc answer everyone, and every trip through root has to be
			// justified.
			clock := CollectTime(ctx)
			facts.Time = &clock
		},
		carry: func(facts *Facts, previous Facts) { facts.Time = previous.Time },
	},

	ModuleSSH: {
		collect: func(ctx context.Context, facts *Facts, _ string) {
			// The sshd configuration is read by the helper: "sshd -T" needs root,
			// because the server reads the host keys along the way.
			if !facts.Capabilities.Available(CapSSHD) || sshProbe == nil {
				return
			}
			snapshot, err := sshProbe(ctx)
			if err != nil {
				facts.SSH = &sshmodule.Snapshot{UnavailableReason: "helper: " + err.Error()}
				return
			}
			facts.SSH = &snapshot
		},
		carry: func(facts *Facts, previous Facts) { facts.SSH = previous.SSH },
	},

	ModuleFirewall: {
		collect: func(ctx context.Context, facts *Facts, _ string) {
			// The firewall is read by the helper: the nftables tables are visible
			// only to root. The read is cheap, but the counters grow on their
			// own, so it is not turned into a source of metrics - monitoring is
			// there for that.
			if !facts.Capabilities.Available(CapFirewall) || firewallProbe == nil {
				return
			}
			snapshot, err := firewallProbe(ctx)
			if err != nil {
				facts.Firewall = &firewall.Snapshot{UnavailableReason: "helper: " + err.Error()}
				return
			}
			facts.Firewall = &snapshot
		},
		carry: func(facts *Facts, previous Facts) { facts.Firewall = previous.Firewall },
	},
}
