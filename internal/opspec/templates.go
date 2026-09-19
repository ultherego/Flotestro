package opspec

import (
	"github.com/ultherego/flotestro/internal/buildinfo"
	// Under a name of its own: the template of a container lifecycle operation is
	// built by a local helper called docker, and a package under the same name
	// would be out of reach exactly where the declarations need it.
	dockermod "github.com/ultherego/flotestro/internal/modules/docker"
	"github.com/ultherego/flotestro/internal/modules/network"
)

// PayloadTemplate gives an example payload for an operation: the shape the
// wizard starts from when the operation has no form of its own.
const (
	placeholderDevice = "/dev/disk/by-id/name-the-disk"
	placeholderVolume = "/dev/name-the-group/name-the-volume"
)

// placeholderInterface stands where an interface name goes in a template.
const placeholderInterface = "the-link"

func PayloadTemplate(action ActionType) (Payload, bool) {
	unit := func() Payload { return Payload{Unit: &UnitPayload{Unit: "example.service"}} }
	pkgs := func(hold bool) Payload {
		return Payload{PackageChange: &PackageChangePayload{Packages: []string{"example-package"}, Hold: hold}}
	}
	docker := func() Payload {
		return Payload{DockerContainer: &DockerContainerPayload{
			ContainerID: "0000000000000000000000000000000000000000000000000000000000000000",
			Name:        "example", TimeoutSeconds: 10}}
	}
	switch action {
	case ActionUnitStart, ActionUnitStop, ActionUnitRestart, ActionUnitReload, ActionUnitResetFailed:
		return unit(), true
	case ActionUnitEnableSet:
		return Payload{UnitToggle: &UnitToggle{Unit: "example.service", Enabled: true}}, true
	case ActionUnitMaskSet:
		return Payload{UnitToggle: &UnitToggle{Unit: "example.service", Enabled: true}}, true

	case ActionScheduleEnsure:
		return Payload{Schedule: &SchedulePayload{
			ID: "nightly-example", Expression: "0 3 * * *",
			Command: []string{"/usr/bin/true"}, User: "root", Enabled: true,
		}}, true
	case ActionScheduleDisable:
		return Payload{Schedule: &SchedulePayload{ID: "nightly-example", Enabled: false}}, true
	case ActionScheduleRemove, ActionScheduleRunNow:
		return Payload{Schedule: &SchedulePayload{ID: "nightly-example"}}, true

	case ActionLocalUserCreate:
		return Payload{LocalUser: &LocalUserPayload{
			Name: "example", Gecos: "Example Account", Groups: []string{"adm"},
			SSHKeys:    []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyMaterialReplaceMe000000 example@host"},
			CreateHome: true,
		}}, true
	case ActionLocalUserLock, ActionLocalUserUnlock:
		return Payload{LocalUser: &LocalUserPayload{Name: "example"}}, true
	case ActionLocalSSHKeysSet:
		return Payload{LocalUser: &LocalUserPayload{Name: "example",
			SSHKeys: []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyMaterialReplaceMe000000 example@host"}}}, true
	case ActionLocalUserGroupsSet:
		return Payload{LocalUser: &LocalUserPayload{Name: "example", Groups: []string{"adm"}}}, true
	case ActionLocalUserExpirySet:
		return Payload{LocalUser: &LocalUserPayload{Name: "example", ExpiresAt: "2030-01-01"}}, true

	case ActionPackageHoldSet:
		return pkgs(true), true
	case ActionRepositorySet:
		// A source is trusted by its key, and only the supplier has it: the
		// placeholder cannot pass, the same way certificate material cannot.
		return Payload{Repository: &RepositoryPayload{
			ID: "example", Name: "Example packages", URL: "https://packages.example.test/stable",
			Enabled: true,
			GPGKey:  "-----BEGIN PGP PUBLIC KEY BLOCK-----\nREPLACE WITH THE SIGNING KEY OF THE SOURCE\n-----END PGP PUBLIC KEY BLOCK-----\n",
		}}, true
	case ActionPackageInstall:
		return pkgs(false), true
	case ActionPackageUpgrade:
		return Payload{PackageUpgrade: &PackageUpgradePayload{SecurityOnly: true}}, true
	case ActionAgentUpgrade:
		// The panel's own version is the one release every fleet can be
		// brought to; the operator replaces it with the release they ship.
		return Payload{AgentUpgrade: &AgentUpgradePayload{TargetVersion: buildinfo.Version}}, true

	case ActionDockerStart, ActionDockerStop, ActionDockerRestart:
		return docker(), true
	case ActionDockerPull:
		return Payload{DockerImage: &DockerImagePayload{Reference: "docker.io/library/nginx:1.27"}}, true
	case ActionComposeDeploy:
		return Payload{Compose: &ComposePayload{Project: "example",
			Manifest: "services:\n  web:\n    image: docker.io/library/nginx:1.27\n"}}, true

	// A declared object.
	case ActionDockerContainerEnsure:
		return Payload{DockerEnsure: &DockerEnsurePayload{
			Container: &dockermod.ContainerRequest{
				Name: "example", Image: "docker.io/library/nginx:1.27",
				Ports: []string{"8080:80/tcp"}, RestartPolicy: "unless-stopped",
			},
		}}, true
	case ActionDockerNetworkEnsure:
		return Payload{DockerEnsure: &DockerEnsurePayload{
			Network: &dockermod.NetworkSpec{
				Name: "example", Driver: "bridge",
				Subnet: "10.244.0.0/24", Gateway: "10.244.0.1",
			},
		}}, true
	case ActionDockerVolumeEnsure:
		return Payload{DockerEnsure: &DockerEnsurePayload{
			Volume: &dockermod.VolumeSpec{Name: "example", Driver: "local"},
		}}, true

	case ActionKernelModuleLoad:
		return Payload{Kernel: &KernelPayload{Module: "example_module"}}, true
	case ActionKernelModuleBlacklist:
		return Payload{Kernel: &KernelPayload{Module: "example_module", Blacklist: true}}, true
	case ActionSysctlEnsure:
		return Payload{Kernel: &KernelPayload{Settings: map[string]string{"net.ipv4.ip_forward": "0"}}}, true
	case ActionSELinuxModeSet:
		return Payload{Security: &SecurityPayload{Mode: "enforcing"}}, true
	case ActionSecurityRemediate:
		// The composite names checks, not steps; the security view fills
		// the list from the findings the operator ticked.
		return Payload{Security: &SecurityPayload{CheckIDs: []string{"ssh.password-auth"}}}, true
	case ActionTimezoneSet:
		return Payload{Time: &TimePayload{Timezone: "Etc/UTC"}}, true
	case ActionTimeConfigApply:
		return Payload{Time: &TimePayload{Servers: []string{"ntp.example.test"}}}, true

	case ActionFileEnsure:
		return Payload{File: &FilePayload{Path: "/etc/example.conf", Content: "# managed by Flotestro\n", Mode: "0644"}}, true
	case ActionFileRemove:
		return Payload{File: &FilePayload{Path: "/etc/example.conf"}}, true
	case ActionFileRollback:
		return Payload{File: &FilePayload{Path: "/etc/example.conf",
			VersionSHA256: "0000000000000000000000000000000000000000000000000000000000000000"}}, true

	case ActionBackupRun, ActionBackupVerify:
		return Payload{Backup: &BackupPayload{ID: "nightly", Tool: "restic",
			Repository: "/srv/backup/example", Paths: []string{"/etc"}, KeepLast: 7,
			PasswordSecret: &SecretRef{Name: "backup.password"}}}, true

	case ActionCertificateDeploy:
		return Payload{Certificate: &CertificatePayload{
			Path: "/etc/ssl/certs/example.crt", KeyPath: "/etc/ssl/private/example.key",
			Certificate: "-----BEGIN CERTIFICATE-----\nREPLACE WITH THE LEAF AND ITS CHAIN\n-----END CERTIFICATE-----\n",
			KeySecret:   &SecretRef{Name: "example.key"}, ReloadUnit: "nginx.service",
			ProbeTarget: "example.test:443",
		}}, true
	case ActionCertificateRenew:
		return Payload{Certificate: &CertificatePayload{Path: "/etc/pki/tls/certs/example.crt",
			ReloadUnit: "httpd.service"}}, true
	case ActionCertificateTrustEnsure:
		return Payload{Certificate: &CertificatePayload{AnchorID: "fleet-ca-2026",
			Certificate: "-----BEGIN CERTIFICATE-----\nREPLACE WITH THE AUTHORITY CERTIFICATE\n-----END CERTIFICATE-----\n"}}, true
	case ActionCertificateTrustRemove:
		return Payload{Certificate: &CertificatePayload{AnchorID: "fleet-ca-2025"}}, true

	case ActionMountEnsure:
		return Payload{Storage: &StoragePayload{Source: "UUID=00000000-0000-0000-0000-000000000000",
			Target: "/mnt/example", FSType: "ext4", Options: "defaults,nofail", Persist: true}}, true
	case ActionMountRemove:
		return Payload{Storage: &StoragePayload{Target: "/mnt/example"}}, true
	case ActionFilesystemCheck:
		return Payload{Storage: &StoragePayload{Device: placeholderDevice}}, true
	case ActionFilesystemResize:
		return Payload{Storage: &StoragePayload{Device: placeholderDevice}}, true
	case ActionLVMExtend:
		return Payload{Storage: &StoragePayload{Device: placeholderVolume, Size: "+1G"}}, true

	case ActionNetworkProfileApply:
		return Payload{Network: &NetworkPayload{Interface: placeholderInterface, Method: "manual",
			Addresses: []string{"192.0.2.10/24"}, Gateway: "192.0.2.1", RollbackSeconds: 120}}, true
	case ActionNetworkRouteEnsure:
		return Payload{Network: &NetworkPayload{Interface: placeholderInterface,
			Routes: []string{"198.51.100.0/24 192.0.2.1"}, RollbackSeconds: 120}}, true
	case ActionNetworkLinkApply:
		// A VLAN is the example: it is the one layer that needs no second interface
		// to be a sensible placeholder, and it names both of the fields a layered
		// order is about - what it stands on and what tag it carries.
		return Payload{Network: &NetworkPayload{Interface: placeholderInterface + ".100",
			Link: &network.LinkSpec{Name: placeholderInterface + ".100", Kind: "vlan",
				Parent: placeholderInterface, VLANID: 100},
			RollbackSeconds: 120}}, true
	case ActionNetworkLinkRemove:
		return Payload{Network: &NetworkPayload{Interface: placeholderInterface + ".100", RollbackSeconds: 120}}, true
	case ActionNetworkMTUSet:
		return Payload{Network: &NetworkPayload{Interface: placeholderInterface, MTU: "1500", RollbackSeconds: 120}}, true
	case ActionDNSHostApply:
		return Payload{DNS: &DNSPayload{Interface: placeholderInterface, Servers: []string{"192.0.2.53"},
			SearchDomains: []string{"example.test"}, IgnoreAutoDNS: true, RollbackSeconds: 120}}, true

	case ActionFirewallRuleEnsure:
		return Payload{Firewall: &FirewallPayload{RuleID: "allow-https", Chain: "input",
			Action: "accept", Protocol: "tcp", Ports: []string{"443"},
			Sources: []string{"192.0.2.0/24"}, RollbackSeconds: 120}}, true
	case ActionFirewallRuleRemove:
		return Payload{Firewall: &FirewallPayload{RuleID: "allow-https", RollbackSeconds: 120}}, true
	case ActionFirewallZonePort:
		return Payload{Firewall: &FirewallPayload{Zone: "public", Ports: []string{"443"},
			Protocol: "tcp", Enable: true}}, true
	case ActionFirewallZoneService:
		return Payload{Firewall: &FirewallPayload{Zone: "public", Service: "https", Enable: true}}, true

	case ActionSSHConfigApply:
		return Payload{SSH: &SSHPayload{PermitRootLogin: "no", PasswordAuthentication: "no"}}, true

	case ActionSystemReboot:
		return Payload{Reboot: &RebootPayload{DelaySeconds: 15, Reason: "planned maintenance reboot"}}, true

	case ActionSystemHostnameSet:
		// The shared part of a rename order carries no name on purpose: the names
		// live in the mapping the wizard builds host by host, and a template with a
		// name would be the one name every host must not get.
		return Payload{Hostname: &HostnamePayload{}}, true
	}
	return Payload{}, false
}

// TemplateNeedsMaterial says whether the template of an operation holds a
// placeholder for certificate material that only the operator can supply.
func TemplateNeedsMaterial(action ActionType) bool {
	switch action {
	case ActionCertificateDeploy, ActionCertificateTrustEnsure:
		return true
	case ActionRepositorySet:
		// The signing key of a package source is material of the same kind:
		// without it the host would take root-running scripts on trust.
		return true
	}
	return false
}
