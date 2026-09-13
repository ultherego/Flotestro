package opspec

// PayloadTemplate gives an example payload for an operation: the shape the
// wizard starts from when the operation has no form of its own. The panel
// is the authority on the contract, so the example lives here, next to the
// validation, and a test keeps every template valid - a template the
// server would refuse is worse than none.
//
// The values are placeholders an operator replaces; they are chosen to be
// obviously examples rather than something a hasty click would apply. A
// template that carries certificate material cannot be valid as it stands -
// TemplateNeedsMaterial names those, and the server refuses them until the
// placeholder is replaced with real PEM.
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
	case ActionUnitStart, ActionUnitStop, ActionUnitRestart, ActionUnitReload:
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

	case ActionPackageHoldSet:
		return pkgs(true), true
	case ActionPackageInstall:
		return pkgs(false), true
	case ActionPackageUpgrade:
		return Payload{PackageUpgrade: &PackageUpgradePayload{SecurityOnly: true}}, true

	case ActionDockerStart, ActionDockerStop, ActionDockerRestart:
		return docker(), true
	case ActionDockerPull:
		return Payload{DockerImage: &DockerImagePayload{Reference: "docker.io/library/nginx:1.27"}}, true
	case ActionComposeDeploy:
		return Payload{Compose: &ComposePayload{Project: "example",
			Manifest: "services:\n  web:\n    image: docker.io/library/nginx:1.27\n"}}, true

	case ActionKernelModuleLoad:
		return Payload{Kernel: &KernelPayload{Module: "example_module"}}, true
	case ActionKernelModuleBlacklist:
		return Payload{Kernel: &KernelPayload{Module: "example_module", Blacklist: true}}, true
	case ActionSysctlEnsure:
		return Payload{Kernel: &KernelPayload{Settings: map[string]string{"net.ipv4.ip_forward": "0"}}}, true
	case ActionSELinuxModeSet:
		return Payload{Security: &SecurityPayload{Mode: "enforcing"}}, true
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
		return Payload{Storage: &StoragePayload{Device: "/dev/sdb1"}}, true
	case ActionFilesystemResize:
		return Payload{Storage: &StoragePayload{Device: "/dev/sdb1"}}, true
	case ActionLVMExtend:
		return Payload{Storage: &StoragePayload{Device: "/dev/vg0/data", Size: "+1G"}}, true

	case ActionNetworkProfileApply:
		return Payload{Network: &NetworkPayload{Interface: "eth1", Method: "manual",
			Addresses: []string{"192.0.2.10/24"}, Gateway: "192.0.2.1", RollbackSeconds: 120}}, true
	case ActionNetworkRouteEnsure:
		return Payload{Network: &NetworkPayload{Interface: "eth1",
			Routes: []string{"198.51.100.0/24 192.0.2.1"}, RollbackSeconds: 120}}, true
	case ActionNetworkMTUSet:
		return Payload{Network: &NetworkPayload{Interface: "eth1", MTU: "1500", RollbackSeconds: 120}}, true
	case ActionDNSHostApply:
		return Payload{DNS: &DNSPayload{Interface: "eth1", Servers: []string{"192.0.2.53"},
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
	}
	return Payload{}, false
}

// TemplateNeedsMaterial says whether the template of an operation holds a
// placeholder for certificate material that only the operator can supply.
func TemplateNeedsMaterial(action ActionType) bool {
	switch action {
	case ActionCertificateDeploy, ActionCertificateTrustEnsure:
		return true
	}
	return false
}
