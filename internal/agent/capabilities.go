package agent

import (
	"github.com/ultherego/flotestro/internal/modules/backup"
	"github.com/ultherego/flotestro/internal/modules/certificates"
	"github.com/ultherego/flotestro/internal/modules/network"
	"github.com/ultherego/flotestro/internal/modules/security"
	hosttime "github.com/ultherego/flotestro/internal/modules/time"
)

// The names of the adapters. A name says what the host has and not what an
// operation wants: the operation asks about "packages", the host answers
// "packages.apt".
const (
	CapSystemd  = "systemd"
	CapAPT      = "packages.apt"
	CapDNF      = "packages.dnf"
	CapJournald = "journald"
	CapDocker   = "docker"
	// Compose is a separate adapter: a container engine is sometimes without it,
	// and without the compose plugin a project can neither be planned nor
	// deployed.
	CapCompose = "docker.compose"
	// Recurring jobs. Cron and systemd timers are two mechanisms for the same
	// thing, so one capability covers both.
	CapSchedules = "schedules"
	// The network. The read works everywhere iproute2 is; the write needs a
	// mechanism that can roll a change back.
	CapNetwork = "network"
	// The resolver of the host. The read works everywhere resolv.conf is; the
	// write needs a mechanism that makes the change stick.
	CapDNS = "dns"
	// The firewall. The adapter says who holds the rules on this host.
	CapFirewall = "firewall"
	// The disk space. The read needs lsblk; LVM and the arrays are separate
	// features, because a host is sometimes without them.
	CapStorage = "storage"
	// Serwer sshd. Konfiguracja idzie do wlasnego pliku w sshd_config.d.
	CapSSHD = "sshd"
	// Jadro: ustawienia sysctl i moduly.
	CapKernel = "kernel"
	// The time of the host. The read works everywhere timedatectl is; the write
	// needs a daemon the panel has somewhere to add servers to.
	CapTime = "time"
	// The protection state of the host. The read works everywhere; switching the
	// MAC mode
	// is a separate capability, because a host without SELinux has nothing to
	// switch.
	CapSecurity    = "security"
	CapSecurityMAC = "security.mac"
	// The audit is a separate capability: a host without auditd has nothing to
	// reload, and the reload goes through augenrules, not through a restart of
	// the unit.
	CapSecurityAudit = "security.audit"
	// Certyfikaty na hostach. Modul dziala wszedzie, bo oglada wskazane pliki
	// and deploys new ones. The renewal is a separate capability: it is done by
	// the daemon of the host, and a host without certmonger has nothing to renew
	// with.
	CapCertificates      = "certificates"
	CapCertificatesRenew = "certificates.renew"
	// The configuration files. The scope of the paths is set by the
	// administrator of the host.
	CapFiles = "files.managed"
	// A probe from the host. It works everywhere: it is an ordinary connection,
	// without root and without an extra tool.
	CapMonitoring = "monitoring"
	// Backup. The module drives a tool the host already has: without the tool
	// and without runbooks there is nothing to make a copy with.
	CapBackup = "backup"
)

// The requirements of operations. A logical name does not point at an
// adapter, because an operation is not to know the host's system family.
const (
	NeedPackages      = "packages"
	NeedPackageRepair = "packages.repair"
	// Writing the network configuration. Reading works everywhere iproute2
	// is, so the module alone does not yet say that anything can be changed
	// here.
	NeedNetworkWrite  = "network.write"
	NeedDNSWrite      = "dns.write"
	NeedFirewallWrite = "firewall.write"
	NeedFirewallZones = "firewall.zones"
	NeedLVM           = "storage.lvm"
)

// The version of the adapter contract. It goes up when the meaning of an
// adapter operation changes, not when the version of a tool on the host does.
const adapterVersion = 1

// Capability describes one adapter detected on the host.
type Capability struct {
	Name      string          `json:"name"`
	Version   uint32          `json:"version"`
	Available bool            `json:"available"`
	ReadOnly  bool            `json:"read_only"`
	Reason    string          `json:"reason,omitempty"`
	Features  map[string]bool `json:"features,omitempty"`
}

// Capabilities is the registry of the adapters of the host.
type Capabilities []Capability

// Available says whether the adapter with this name works on the host.
func (c Capabilities) Available(name string) bool {
	for _, cap := range c {
		if cap.Name == name {
			return cap.Available
		}
	}
	return false
}

// Feature mowi, czy adapter ma dana czesc.
func (c Capabilities) Feature(name, feature string) bool {
	value, _ := c.FeatureState(name, feature)
	return value
}

// FeatureState separates "it does not have this part" from "it is not known
// whether it has it".
//
// An agent from before the registry sends no features at all, and its
// registry is reconstructed from logical fields. Treating silence as a
// refusal would take away from such a host an operation that works on it - an
// unknown feature is not an absent feature.
func (c Capabilities) FeatureState(name, feature string) (value bool, known bool) {
	for _, capability := range c {
		if capability.Name != name {
			continue
		}
		if !capability.Available {
			// An adapter that is not there certainly has no parts.
			return false, true
		}
		value, ok := capability.Features[feature]
		return value, ok
	}
	// The adapter is not in the registry - that is an answer too, not ignorance.
	return false, true
}

// Satisfies checks an operation's requirement. Requirements are logical names
// rather than adapter names: an upgrade operation is not to know whether the
// host uses apt or dnf, and repairing the package database is to know that it
// works for apt only.
func (c Capabilities) Satisfies(requirement string) bool {
	switch requirement {
	case "":
		return true
	case NeedPackages:
		return c.Available(CapAPT) || c.Available(CapDNF)
	case NeedPackageRepair:
		for _, adapter := range []string{CapAPT, CapDNF} {
			value, known := c.FeatureState(adapter, "repair")
			if value {
				return true
			}
			// The adapter is present but silent about its features: the host
			// decides at execution time, as it did before the registry was
			// introduced.
			if !known && c.Available(adapter) {
				return true
			}
		}
		return false
	case NeedFirewallWrite:
		value, known := c.FeatureState(CapFirewall, "write")
		if value {
			return true
		}
		return !known && c.Available(CapFirewall)
	case NeedLVM:
		value, _ := c.FeatureState(CapStorage, "lvm")
		return value
	case NeedFirewallZones:
		// Zones exist only where firewalld runs. A host with nftables alone
		// has nothing to show and nothing to change.
		value, _ := c.FeatureState(CapFirewall, "zones")
		return value
	case NeedDNSWrite:
		value, known := c.FeatureState(CapDNS, "write")
		if value {
			return true
		}
		return !known && c.Available(CapDNS)
	case NeedNetworkWrite:
		// Writing the network requires a mechanism that persists the change
		// and allows rolling it back. A host without one is to learn about it
		// when the operation is ordered, not after the task is delivered.
		value, known := c.FeatureState(CapNetwork, "write")
		if value {
			return true
		}
		// The adapter is present but silent about its features: the host
		// decides at execution time, as it did before the registry was
		// introduced.
		return !known && c.Available(CapNetwork)
	default:
		return c.Available(requirement)
	}
}

// DetectCapabilities checks the presence of the adapters without starting any
// process.
//
// An unavailable adapter carries a reason. Without it the interface would have
// to guess why a tab is missing - and it would guess in the code of the
// browser, so badly: the cause is a fact about the host and the host is to give
// it.
func DetectCapabilities() Capabilities {
	systemd := isDir("/run/systemd/system")
	apt := isExecutable("/usr/bin/apt-get")
	dnf := isExecutable("/usr/bin/dnf") || isExecutable("/usr/bin/dnf5")
	docker := exists("/var/run/docker.sock") || exists("/run/docker.sock")
	compose := docker && composePlugin() != ""
	journald := exists("/run/systemd/journal/socket")
	// The managed entries go to /etc/cron.d, so without that directory the
	// module has nowhere to create them - even when the systemd timers work.
	schedules := isDir("/etc/cron.d")
	networkRead := exists("/usr/sbin/ip") || exists("/sbin/ip") || exists("/usr/bin/ip")
	networkWrite := network.DetectAdapter(network.Exists)
	resolver := exists("/etc/resolv.conf")
	resolved := exists("/usr/bin/resolvectl") && exists("/run/systemd/resolve")
	nft := exists("/usr/sbin/nft")
	lsblk := exists("/usr/bin/lsblk")
	sshd := exists("/usr/sbin/sshd")
	sysctl := exists("/usr/sbin/sysctl") || exists("/sbin/sysctl")
	modprobe := exists("/usr/sbin/modprobe") || exists("/sbin/modprobe")
	// The panel writes only to its own file, so without an include directory it
	// could only read: sshd_config belongs to the distribution.
	dropIn := isDir("/etc/ssh/sshd_config.d")
	lvm := exists("/usr/sbin/vgs") && exists("/usr/sbin/lvs")
	fsck := exists("/usr/sbin/fsck")
	firewalld := exists("/usr/bin/firewall-cmd") && isDir("/run/firewalld")
	timedatectl := exists(hosttime.TimedatectlPath)
	selinux := isDir(security.SELinuxDir) && exists(security.SetenforcePath)
	audit := exists(security.AuditctlPath) && exists(security.AugenrulesPath)
	apparmor := exists(security.AppArmorFile)
	certmonger := exists(certificates.GetcertPath) || exists(certificates.GetcertPathAlt)
	restic := exists("/usr/bin/restic") || exists("/usr/local/bin/restic")
	borg := exists("/usr/bin/borg") || exists("/usr/local/bin/borg")
	runbooks, _ := backup.ListRunbooks()
	chrony := exists(hosttime.ChronycPath)
	// Timesyncd is sometimes installed and masked when the host has chrony. The
	// presence of the unit says only that there is something to write with -
	// which daemon really keeps the clock is decided by the state read.
	timesyncd := exists("/usr/lib/systemd/systemd-timesyncd") ||
		exists("/lib/systemd/systemd-timesyncd")

	return Capabilities{
		{
			Name:      CapSystemd,
			Version:   adapterVersion,
			Available: systemd,
			Reason:    reason(systemd, "this host does not run systemd"),
		},
		{
			Name:      CapAPT,
			Version:   adapterVersion,
			Available: apt,
			Reason:    reason(apt, "apt-get is not installed on this host"),
			// Repairing the package database means answering the questions of
			// debconf. Without its tools the operation would only break on the
			// host, after the approval.
			Features: map[string]bool{
				"repair": apt &&
					isExecutable("/usr/bin/debconf-show") &&
					isExecutable("/usr/bin/debconf-set-selections"),
			},
		},
		{
			Name:      CapDNF,
			Version:   adapterVersion,
			Available: dnf,
			Reason:    reason(dnf, "dnf is not installed on this host"),
			// Blokada bazy rpm wyglada inaczej niz pytanie debconfa i naprawa
			// would look different too, so the adapter does not have it.
			Features: map[string]bool{"repair": false},
		},
		{
			Name:      CapNetwork,
			Version:   adapterVersion,
			Available: networkRead,
			// A host without a write mechanism is not a host without a network:
			// the module works, only in read mode - and it says why.
			ReadOnly: networkWrite == "",
			Features: map[string]bool{
				"routes":                      networkRead,
				"write":                       networkWrite != "",
				network.AdapterNetworkManager: networkWrite == network.AdapterNetworkManager,
				network.AdapterNmstate:        networkWrite == network.AdapterNmstate,
				network.AdapterNetplan:        networkWrite == network.AdapterNetplan,
			},
			Reason: networkAdapterReason(networkRead, networkWrite),
		},
		{
			Name:    CapFiles,
			Version: adapterVersion,
			// The module works everywhere: the scope comes from the allowlist,
			// and its absence means the default list, not a missing module.
			Available: true,
			Features:  map[string]bool{"allowlist": exists("/etc/flotestro/files.allow")},
		},
		{
			Name:      CapTime,
			Version:   adapterVersion,
			Available: timedatectl,
			// A host on which there is nothing to configure still shows the time
			// and the offset - the module is read-only then.
			ReadOnly: !chrony && !timesyncd,
			Features: map[string]bool{
				"chrony":    chrony,
				"timesyncd": timesyncd,
				"write":     chrony || timesyncd,
				"timezone":  timedatectl,
			},
			Reason: reason(timedatectl, "this host has no timedatectl"),
		},
		{
			Name:    CapSecurity,
			Version: adapterVersion,
			// The module works everywhere: a missing SELinux or audit is a fact
			// about the host and not a missing module.
			Available: true,
			Features: map[string]bool{
				"selinux":    selinux,
				"apparmor":   apparmor,
				"auditd":     exists(security.AuditctlPath),
				"augenrules": exists(security.AugenrulesPath),
				"sockets":    exists(security.SSPath) || exists(security.SSPathAlt),
			},
		},
		{
			Name:    CapCertificates,
			Version: adapterVersion,
			// The module works everywhere: missing certificates are a fact about
			// the host and not a missing module.
			Available: true,
			Features: map[string]bool{
				"certmonger": certmonger,
				"deploy":     true,
			},
		},
		{
			Name:    CapMonitoring,
			Version: adapterVersion,
			// A probe needs nothing beyond the network, so the module works
			// wszedzie. Metryki i alerty czyta panel z systemow centralnych,
			// and not the agent - the host gets not a single
			// dodatkowego collectora.
			Available: true,
			Features:  map[string]bool{"probe.http": true, "probe.tcp": true},
		},
		{
			Name:      CapBackup,
			Version:   adapterVersion,
			Available: restic || borg || len(runbooks) > 0,
			Features: map[string]bool{
				"restic": restic, "borg": borg, "runbook": len(runbooks) > 0,
			},
			Reason: reason(restic || borg || len(runbooks) > 0,
				"this host has no backup tool the panel can drive"),
		},
		{
			Name:      CapCertificatesRenew,
			Version:   adapterVersion,
			Available: certmonger,
			Reason:    reason(certmonger, "this host does not run certmonger"),
		},
		{
			Name:      CapSecurityAudit,
			Version:   adapterVersion,
			Available: audit,
			Reason:    reason(audit, "this host has no auditd rule tooling"),
		},
		{
			Name:      CapSecurityMAC,
			Version:   adapterVersion,
			Available: selinux,
			Reason:    reason(selinux, "this host has no SELinux to switch"),
		},
		{
			Name:      CapKernel,
			Version:   adapterVersion,
			Available: sysctl,
			Features:  map[string]bool{"sysctl": sysctl, "modules": modprobe},
			Reason:    reason(sysctl, "this host has no sysctl binary"),
		},
		{
			Name:      CapSSHD,
			Version:   adapterVersion,
			Available: sshd,
			ReadOnly:  !dropIn,
			Features:  map[string]bool{"dropin": dropIn, "hostkeys": exists("/usr/bin/ssh-keygen")},
			Reason:    sshdReason(sshd, dropIn),
		},
		{
			Name:      CapStorage,
			Version:   adapterVersion,
			Available: lsblk,
			Features: map[string]bool{
				"lvm":  lvm,
				"fsck": fsck,
				"raid": exists("/proc/mdstat"),
			},
			Reason: reason(lsblk, "this host has no lsblk binary"),
		},
		{
			Name:      CapFirewall,
			Version:   adapterVersion,
			Available: nft || firewalld,
			ReadOnly:  !nft && !firewalld,
			Features: map[string]bool{
				"nftables":  nft,
				"firewalld": firewalld,
				"write":     nft,
				"zones":     firewalld,
			},
			Reason: reason(nft || firewalld, "this host has neither nftables nor firewalld"),
		},
		{
			Name:      CapDNS,
			Version:   adapterVersion,
			Available: resolver,
			ReadOnly:  networkWrite != network.AdapterNetworkManager,
			Features: map[string]bool{
				"resolved": resolved,
				"write":    networkWrite == network.AdapterNetworkManager,
			},
			Reason: resolverAdapterReason(resolver, networkWrite),
		},
		{
			Name:      CapSchedules,
			Version:   adapterVersion,
			Available: schedules,
			Features:  map[string]bool{"cron": schedules, "timers": systemd},
			Reason:    reason(schedules, "this host has no /etc/cron.d directory"),
		},
		{
			Name:      CapJournald,
			Version:   adapterVersion,
			Available: journald,
			Reason:    reason(journald, "this host has no journald socket"),
		},
		{
			Name:      CapCompose,
			Version:   adapterVersion,
			Available: compose,
			Reason: reason(compose,
				"this host has no Docker Compose plugin"),
		},
		{
			Name:      CapDocker,
			Version:   adapterVersion,
			Available: docker,
			// Adapter czyta stan silnika i wykonuje operacje na kontenerach.
			// Compose projects are a separate feature: an engine is sometimes
			// without the plugin.
			Features: map[string]bool{"read": docker, "write": docker, "compose": compose},
			Reason:   reason(docker, "this host has no Docker socket"),
		},
	}
}

// composePluginPaths to miejsca, w ktorych dystrybucje instaluja wtyczke.
var composePluginPaths = []string{
	"/usr/libexec/docker/cli-plugins/docker-compose",
	"/usr/lib/docker/cli-plugins/docker-compose",
	"/usr/local/lib/docker/cli-plugins/docker-compose",
	"/root/.docker/cli-plugins/docker-compose",
}

// composePlugin returns the path of the plugin or an empty string. The presence
// of the file is checked and the tool is not started: capability detection must
// not start processes.
func composePlugin() string {
	for _, path := range composePluginPaths {
		if isExecutable(path) {
			return path
		}
	}
	return ""
}

// reason returns an explanation only for an unavailable adapter.
func reason(available bool, whenMissing string) string {
	if available {
		return ""
	}
	return whenMissing
}

// reasonWhen explains both states: an adapter that is present is sometimes
// limited, and that also needs a sentence rather than silence.
func reasonWhen(available bool, whenPresent, whenMissing string) string {
	if available {
		return whenPresent
	}
	return whenMissing
}

// networkReason explains what the network module is missing on this host. A
// missing write and a missing module are two different answers.
func networkAdapterReason(read bool, adapter string) string {
	if !read {
		return "this host has no iproute2 (ip) binary"
	}
	return network.ReadOnlyReason(adapter)
}

// resolverReason explains what the DNS module is missing.
func resolverAdapterReason(resolver bool, adapter string) string {
	if !resolver {
		return "this host has no /etc/resolv.conf"
	}
	if adapter != network.AdapterNetworkManager {
		return "resolver changes need NetworkManager; without it a write to resolv.conf " +
			"would be overwritten by whoever owns the file"
	}
	return ""
}

// sshdReason explains what the sshd module is missing.
func sshdReason(sshd, dropIn bool) string {
	if !sshd {
		return "this host has no sshd"
	}
	if !dropIn {
		return "this sshd has no sshd_config.d include; the panel would have to rewrite " +
			"the distribution's sshd_config, so it only reads here"
	}
	return ""
}
