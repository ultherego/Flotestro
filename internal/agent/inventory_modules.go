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
var ModuleOrder = []string{
	ModuleSystem, ModuleServices, ModulePackages, ModuleIdentity, ModuleAccounts,
	ModuleContainers, ModuleSchedules, ModuleNetwork, ModuleDNS, ModuleStorage,
	ModuleFiles, ModuleKernel, ModuleSecurity, ModuleBackups, ModuleCerts,
	ModulePower, ModuleTime, ModuleSSH, ModuleFirewall, ModuleSudoers,
}

// InventoryModule knows one module: it can collect it and it can carry over the
// previous result when a refresh does not cover it.
type InventoryModule struct {
	collect func(ctx context.Context, facts *Facts, managementAddress string)
	carry   func(facts *Facts, previous Facts)
}

var moduleCollectors = map[string]InventoryModule{
	ModuleSystem: {
		collect: func(ctx context.Context, facts *Facts, _ string) {
			// The platform picture: what the machine is, as far as procfs, sysfs and
			// the DMI tables say.
			platform := CollectSystem(ctx)
			facts.System = &platform
		},
		carry: func(facts *Facts, previous Facts) { facts.System = previous.System },
	},

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
			case facts.Capabilities.Available(CapPacman):
				facts.Packages = pacmanSummary(ctx)
			}
			// The digest of the full package list: the list itself is too big to travel
			// in every cycle, but the panel has to know when its copy stops describing
			// the host.
			if facts.Packages.Manager != "" {
				digest, count, reason := packageDigest(ctx, facts.Packages.Manager)
				facts.Packages.InstalledDigest = digest
				facts.Packages.InstalledReason = reason
				if reason == "" {
					number := uint32(count)
					facts.Packages.InstalledCount = &number
				}
				// The holds travel with the counters: the tab that shows how many packages
				// wait for an upgrade is to show how many will not take one, and the read
				// is a cheap one without root.
				facts.Packages.Holds, facts.Packages.HoldsReason = packageHolds(ctx)
				facts.Packages.HoldsKnown = facts.Packages.HoldsReason == ""
				// The package sources are read together with the summary: it is one tab
				// and one answer to the question of where the host takes its software
				// from.
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
					// Missing privileged data does not invalidate the rest of the inventory,
					// but it has to show as a reason and not as silence.
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
			result, err := privilegedAccounts(ctx, names)
			if err != nil {
				// An account list the helper could not read must not look like
				// a host whose accounts hold no keys and belong to no group.
				for i := range facts.LocalAccounts {
					if facts.LocalAccounts[i].Source == SourceLocal &&
						facts.LocalAccounts[i].UnavailableReason == "" {
						facts.LocalAccounts[i].UnavailableReason = "helper: " + err.Error()
					}
				}
				return
			}
			facts.LocalAccounts = mergePrivilegedAccounts(facts.LocalAccounts, result)
		},
		carry: func(facts *Facts, previous Facts) { facts.LocalAccounts = previous.LocalAccounts },
	},

	ModuleContainers: {
		collect: func(ctx context.Context, facts *Facts, _ string) {
			// The container engine is queried once per inventory cycle and only for the
			// summary.
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
			// Schedules change rarely, so they travel in the inventory cycle and not on
			// request: the full list of recurring jobs of a host is a dozen or so
			// entries, not hundreds as with packages.
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
			// The network is read from the kernel in every cycle: the read is cheap and
			// the state can change without the panel (DHCP, a cable, a container).
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
			// The state of the managed files: the host itself knows which files the
			// panel has written, so a drift shows without asking the panel for a list.
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
			// The protection state is assembled by the agent: most facts are readable
			// without root, and those that are not it orders from the helper by name.
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
			// The backup tools are read by the agent without root: the presence of the
			// binary and its version are public.
			backupState := CollectBackup(ctx)
			facts.Backup = &backupState
		},
		carry: func(facts *Facts, previous Facts) { facts.Backup = previous.Backup },
	},

	ModuleCerts: {
		collect: func(ctx context.Context, facts *Facts, _ string) {
			// The certificates are read by the agent, and the helper adds what cannot
			// be seen without root.
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
			// The boot state and the shutdown inhibitors.
			powerState := CollectPower(ctx, facts.BootID, facts.RebootRequired)
			facts.Power = &powerState
		},
		carry: func(facts *Facts, previous Facts) { facts.Power = previous.Power },
	},

	ModuleTime: {
		collect: func(ctx context.Context, facts *Facts, _ string) {
			// The time is read by the agent and not by the helper: timedatectl and
			// chronyc answer everyone, and every trip through root has to be justified.
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

	ModuleSudoers: {
		collect: func(ctx context.Context, facts *Facts, _ string) {
			// The sudo policy is read by the helper: /etc/sudoers and its drop-ins are
			// root's files.
			policy := CollectSudoers(ctx)
			facts.Sudoers = &policy
		},
		carry: func(facts *Facts, previous Facts) { facts.Sudoers = previous.Sudoers },
	},

	ModuleFirewall: {
		collect: func(ctx context.Context, facts *Facts, _ string) {
			// The firewall is read by the helper: the nftables tables are visible only
			// to root.
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
