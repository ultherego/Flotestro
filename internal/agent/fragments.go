package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/ultherego/flotestro/internal/packages"
)

// The names of the inventory modules. A module matches a tab of the host, so
// the interface fetches exactly what it shows and not the whole report.
const (
	ModuleSystem     = "system"
	ModulePackages   = "packages"
	ModuleServices   = "services"
	ModuleIdentity   = "identity"
	ModuleAccounts   = "accounts"
	ModuleNetwork    = "network"
	ModuleDNS        = "dns"
	ModuleFirewall   = "firewall"
	ModuleStorage    = "storage"
	ModuleSSH        = "ssh"
	ModuleKernel     = "kernel"
	ModuleTime       = "time"
	ModulePower      = "power"
	ModuleSecurity   = "security"
	ModuleCerts      = "certificates"
	ModuleBackups    = "backups"
	ModuleFiles      = "files"
	ModuleContainers = "containers"
	ModuleSchedules  = "schedules"
)

// Fragment is the state of one module of the host together with its own
// revision.
//
// A revision computed separately for every module has two effects. A change in
// one module does not rewrite the whole inventory, and the interface knows how
// fresh the very tab the operator is looking at is - until now all the tabs
// shared one marker and one date.
type Fragment struct {
	Module            string          `json:"module"`
	Revision          string          `json:"revision"`
	Source            string          `json:"source"`
	Payload           json.RawMessage `json:"payload"`
	UnavailableReason string          `json:"unavailable_reason,omitempty"`
	ObservedAt        time.Time       `json:"observed_at"`
}

// Fragments splits the report into modules.
func (f Facts) Fragments() ([]Fragment, error) {
	manager := "agent/packages"
	if f.Packages.Manager != "" {
		manager = "agent/" + f.Packages.Manager
	}

	// A unit state that was not read must not look like an empty list of units
	// in error, so a lack of knowledge is a reason here and not silence.
	servicesReason := ""
	if !f.FailedUnitsKnown {
		servicesReason = "unit states could not be read from systemd"
	}

	descriptions := []struct {
		module  string
		source  string
		reason  string
		content any
	}{
		{ModuleSystem, "agent/os-release+procfs", "", struct {
			OS       OSInfo   `json:"os"`
			Hardware Hardware `json:"hardware"`
			Hostname string   `json:"hostname"`
			BootID   string   `json:"boot_id"`
		}{f.OS, f.Hardware, f.Hostname, f.BootID}},

		// The package tab asks about two things at once: what is installed and
		// where it came from. The sources therefore travel in the same fragment
		// and not in a separate module.
		{ModulePackages, manager, f.Packages.UnavailableReason, struct {
			Packages
			Repositories *packages.RepositoryImage `json:"repositories,omitempty"`
		}{f.Packages, f.Repositories}},

		{ModuleServices, "agent/systemctl", servicesReason, struct {
			FailedUnits []string `json:"failed_units"`
			Known       bool     `json:"failed_units_known"`
		}{f.FailedUnits, f.FailedUnitsKnown}},

		{ModuleIdentity, "agent/sssd", f.Identity.UnavailableReason, f.Identity},

		{ModuleAccounts, "agent/passwd", "", struct {
			Accounts []LocalAccount `json:"accounts"`
		}{f.LocalAccounts}},

		{ModuleContainers, "agent/docker-engine", containersReason(f), containersSummary(f)},

		{ModuleSchedules, "agent/cron+systemd", schedulesReason(f), hostSchedules(f)},

		// The network module replaced the bare list of interface names: a name
		// without an address, a state and routes answered no question of the
		// operator.
		{ModuleNetwork, "agent/iproute2", networkReason(f), networkState(f)},

		{ModuleDNS, "agent/resolvectl+resolv.conf", resolverReason(f), resolverState(f)},

		{ModuleFirewall, "agent/nftables", firewallReason(f), firewallState(f)},

		{ModuleStorage, "agent/lsblk+mountinfo", storageReason(f), storageState(f)},

		{ModuleSSH, "agent/sshd", sshReason(f), sshConfiguration(f)},

		{ModuleKernel, "agent/procfs+sysctl", kernelReason(f), kernelState(f)},

		{ModuleTime, "agent/timedatectl+chronyc", timeReason(f), hostTime(f)},

		{ModulePower, "agent/procfs+logind", powerReason(f), powerState(f)},

		{ModuleSecurity, "agent/selinux+audit+ss", securityReason(f), securityState(f)},

		{ModuleBackups, "agent/backup-tools", backupReason(f), backupState(f)},

		{ModuleCerts, "agent/certificates+certmonger", certificatesReason(f), hostCertificates(f)},

		{ModuleFiles, "agent/managed-files", filesReason(f), managedFiles(f)},
	}

	fragments := make([]Fragment, 0, len(descriptions))
	for _, description := range descriptions {
		payload, err := json.Marshal(description.content)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(payload)
		fragments = append(fragments, Fragment{
			Module:            description.module,
			Revision:          hex.EncodeToString(sum[:16]),
			Source:            description.source,
			Payload:           payload,
			UnavailableReason: description.reason,
			ObservedAt:        f.CollectedAt,
		})
	}
	return fragments, nil
}

// containersReason returns the reason why the state of the engine was not
// determined.
func containersReason(f Facts) string {
	if f.Containers == nil {
		return "this host does not run a container engine"
	}
	return f.Containers.UnavailableReason
}

// containersSummary returns the state of the engine or an empty one when there
// is no engine. A missing engine and an engine that was not queried are told
// apart by the reason, not by the content.
func containersSummary(f Facts) any {
	if f.Containers == nil {
		return struct{}{}
	}
	return f.Containers
}

// schedulesReason returns the reason why the recurring jobs were not
// determined.
func schedulesReason(f Facts) string {
	if f.Schedules == nil {
		return "this host has no cron directory"
	}
	return f.Schedules.UnavailableReason
}

// hostSchedules returns the recurring jobs or an empty state.
func hostSchedules(f Facts) any {
	if f.Schedules == nil {
		return struct{}{}
	}
	return f.Schedules
}

// networkReason returns the reason why the network state was not determined.
func networkReason(f Facts) string {
	if f.Network == nil {
		return "this host did not report its network state"
	}
	return f.Network.UnavailableReason
}

// networkState returns the network state or an empty picture.
func networkState(f Facts) any {
	if f.Network == nil {
		return struct{}{}
	}
	return f.Network
}

// resolverReason returns the reason why the resolverState state was not determined.
func resolverReason(f Facts) string {
	if f.DNS == nil {
		return "this host did not report its resolverState state"
	}
	return f.DNS.UnavailableReason
}

// resolverState returns the resolverState state or an empty picture.
func resolverState(f Facts) any {
	if f.DNS == nil {
		return struct{}{}
	}
	return f.DNS
}

// firewallReason returns the reason why the firewall state was not determined.
func firewallReason(f Facts) string {
	if f.Firewall == nil {
		return "this host did not report its firewall state"
	}
	return f.Firewall.UnavailableReason
}

// firewallState returns the firewall state or an empty picture.
func firewallState(f Facts) any {
	if f.Firewall == nil {
		return struct{}{}
	}
	return f.Firewall
}

// storageReason returns the reason why the layout was not determined.
func storageReason(f Facts) string {
	if f.Storage == nil {
		return "this host did not report its storage layout"
	}
	return f.Storage.UnavailableReason
}

// storageState returns the picture of the disk space or an empty state.
func storageState(f Facts) any {
	if f.Storage == nil {
		return struct{}{}
	}
	return f.Storage
}

// sshReason returns the reason why the sshd configuration was not determined.
func sshReason(f Facts) string {
	if f.SSH == nil {
		return "this host has no sshd"
	}
	return f.SSH.UnavailableReason
}

// sshConfiguration returns the configuration of the server or an empty state.
func sshConfiguration(f Facts) any {
	if f.SSH == nil {
		return struct{}{}
	}
	return f.SSH
}

// kernelReason returns the reason why the kernel settings were not determined.
func kernelReason(f Facts) string {
	if f.Kernel == nil {
		return "this host did not report its kernel settings"
	}
	return f.Kernel.UnavailableReason
}

// kernelState returns the kernel settings or an empty state.
func kernelState(f Facts) any {
	if f.Kernel == nil {
		return struct{}{}
	}
	return f.Kernel
}

// timeReason returns the reason why the time state was not determined.
func timeReason(f Facts) string {
	if f.Time == nil {
		return "this host did not report its clock"
	}
	return f.Time.UnavailableReason
}

// hostTime returns the time state or an empty picture.
func hostTime(f Facts) any {
	if f.Time == nil {
		return struct{}{}
	}
	return f.Time
}

// securityReason returns the reason why the protection state was not
// determined.
func securityReason(f Facts) string {
	if f.Security == nil {
		return "this host did not report its security state"
	}
	return f.Security.UnavailableReason
}

// securityState returns the protection state or an empty picture.
func securityState(f Facts) any {
	if f.Security == nil {
		return struct{}{}
	}
	return f.Security
}

// powerReason returns the reason why the boot state was not determined.
func powerReason(f Facts) string {
	if f.Power == nil {
		return "this host did not report its boot state"
	}
	return f.Power.UnavailableReason
}

// powerState returns the boot state or an empty picture.
func powerState(f Facts) any {
	if f.Power == nil {
		return struct{}{}
	}
	return f.Power
}

// filesReason returns the reason why the state of the files was not
// determined.
func filesReason(f Facts) string {
	if f.Files == nil {
		return "this host did not report its managed files"
	}
	return f.Files.UnavailableReason
}

// managedFiles returns the state of the files or an empty picture.
func managedFiles(f Facts) any {
	if f.Files == nil {
		return struct{}{}
	}
	return f.Files
}

// certificatesReason returns the reason why there is no picture of the
// certificates.
func certificatesReason(f Facts) string {
	if f.Certificates == nil {
		return "the agent did not read certificates on this host"
	}
	return f.Certificates.UnavailableReason
}

// hostCertificates returns the picture of the certificates of the host.
func hostCertificates(f Facts) any {
	if f.Certificates == nil {
		return struct{}{}
	}
	return f.Certificates
}

// backupReason returns the reason why there is no state of the backup tools.
func backupReason(f Facts) string {
	if f.Backup == nil {
		return "the agent did not read backup tools on this host"
	}
	return ""
}

// backupState returns the state of the backup tools.
func backupState(f Facts) any {
	if f.Backup == nil {
		return struct{}{}
	}
	return f.Backup
}
