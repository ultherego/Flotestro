package adminapi

import (
	"testing"

	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/opspec"
)

// The verdicts of the action preview are the ones the order would get:
// the same permission in the same scope, the same registry, the same
// lifecycle states. The tests build the principal and the host by hand,
// so what is judged is the judgement and nothing around it.

var labScope = authz.Scope{Site: "lab", Environment: "test"}

func principalWith(role authz.Role, scope authz.Scope) authz.Principal {
	return authz.Principal{
		ID: "p1", Subject: "someone", Kind: "user",
		Bindings: []authz.Binding{{Role: role, Scope: scope}},
	}
}

func onlineHost(registry hosts.Capabilities) *hosts.Host {
	return &hosts.Host{
		ID: "h1", Hostname: "debian-1", Site: "lab", Environment: "test",
		LifecycleState: hosts.StateActive, ConnectionState: "online",
		Capabilities: registry,
	}
}

var systemdRegistry = hosts.Capabilities{
	{Name: hosts.CapSystemd, Version: 1, Available: true},
	{Name: hosts.CapJournald, Version: 1, Available: true},
	{Name: hosts.CapNetwork, Version: 1, Available: true, ReadOnly: true,
		Reason:   "no NetworkManager, nmstate or netplan; the panel only reads the network here",
		Features: map[string]bool{"write": false, "routes": true}},
}

func verdictOf(t *testing.T, items []hostAction, action string) hostAction {
	t.Helper()
	for _, item := range items {
		if item.Action == action {
			return item
		}
	}
	t.Fatalf("%s is not in the preview", action)
	return hostAction{}
}

func TestAViewerMayOrderNoChangeAndTheReasonNamesTheActionsPermission(t *testing.T) {
	items := hostActions(principalWith(authz.RoleViewer, labScope), onlineHost(systemdRegistry), labScope)
	if len(items) != len(opspec.AllActions())+len(hostLifecycleActions) {
		t.Fatalf("the preview has %d entries for %d actions", len(items), len(opspec.AllActions())+len(hostLifecycleActions))
	}

	restart := verdictOf(t, items, string(opspec.ActionUnitRestart))
	if restart.Allowed || restart.ReasonCode != ReasonPermissionDenied {
		t.Fatalf("a viewer's unit.restart: %+v", restart)
	}
	if restart.MissingPermission != "unit.restart" || restart.Permission != "unit.restart" {
		t.Errorf("the refusal names %q, not the action's permission", restart.MissingPermission)
	}
	if !restart.Mutating {
		t.Error("unit.restart is not marked mutating")
	}

	// A viewer holds unit.status and not job.create: the order would be
	// refused for the general right, and the preview names that right.
	status := verdictOf(t, items, string(opspec.ActionUnitStatus))
	if status.Allowed || status.ReasonCode != ReasonPermissionDenied || status.MissingPermission != string(authz.PermJobCreate) {
		t.Fatalf("a viewer's unit.status: %+v", status)
	}
	for _, item := range items {
		if item.Allowed {
			t.Errorf("a viewer is allowed %s", item.Action)
		}
	}
}

func TestAnAdministratorMayRestartAUnitOnAHostWithSystemd(t *testing.T) {
	admin := principalWith(authz.RolePlatformAdmin, authz.Scope{Site: authz.Wildcard, Environment: authz.Wildcard})
	items := hostActions(admin, onlineHost(systemdRegistry), labScope)

	restart := verdictOf(t, items, string(opspec.ActionUnitRestart))
	if !restart.Allowed || restart.ReasonCode != "" || restart.Reason != "" {
		t.Fatalf("an administrator's unit.restart: %+v", restart)
	}
	status := verdictOf(t, items, string(opspec.ActionUnitStatus))
	if !status.Allowed {
		t.Fatalf("an administrator's unit.status: %+v", status)
	}
	// A destructive order is allowed and says what it will ask for; a note
	// is not a refusal.
	wipe := verdictOf(t, items, string(opspec.ActionDiskWipe))
	if wipe.Allowed {
		t.Fatalf("disk.wipe is allowed on a host without a storage adapter: %+v", wipe)
	}
	shutdown := verdictOf(t, items, string(opspec.ActionSystemShutdown))
	if !shutdown.Allowed || shutdown.Note == "" {
		t.Fatalf("system.shutdown has no note about the confirmation it asks for: %+v", shutdown)
	}
}

func TestLifecycleOrdersFollowThePermissionAndTheState(t *testing.T) {
	admin := principalWith(authz.RolePlatformAdmin, labScope)
	active := hostActions(admin, onlineHost(systemdRegistry), labScope)
	if quarantine := verdictOf(t, active, "host.quarantine"); !quarantine.Allowed {
		t.Fatalf("quarantine of an active host: %+v", quarantine)
	}
	if release := verdictOf(t, active, "host.quarantine.release"); release.Allowed || release.ReasonCode != ReasonLifecycleStateMismatch {
		t.Fatalf("release of an active host: %+v", release)
	}
	if decommission := verdictOf(t, active, "host.decommission"); !decommission.Allowed {
		t.Fatalf("decommission of an active host: %+v", decommission)
	}

	quarantined := onlineHost(systemdRegistry)
	quarantined.LifecycleState = hosts.StateQuarantined
	items := hostActions(admin, quarantined, labScope)
	if release := verdictOf(t, items, "host.quarantine.release"); !release.Allowed {
		t.Fatalf("release of a quarantined host: %+v", release)
	}

	retired := onlineHost(systemdRegistry)
	retired.LifecycleState = hosts.StateRetired
	if decommission := verdictOf(t, hostActions(admin, retired, labScope), "host.decommission"); decommission.Allowed {
		t.Fatalf("decommission of a retired host: %+v", decommission)
	}

	// A viewer has none of the three, and the refusal names the permission.
	viewer := hostActions(principalWith(authz.RoleViewer, labScope), onlineHost(systemdRegistry), labScope)
	if quarantine := verdictOf(t, viewer, "host.quarantine"); quarantine.Allowed || quarantine.MissingPermission != string(authz.PermHostQuarantine) {
		t.Fatalf("a viewer's quarantine: %+v", quarantine)
	}
}

func TestTheScopeOfTheBindingIsTheScopeOfTheHost(t *testing.T) {
	elsewhere := principalWith(authz.RolePlatformAdmin, authz.Scope{Site: "other", Environment: "prod"})
	items := hostActions(elsewhere, onlineHost(systemdRegistry), labScope)
	restart := verdictOf(t, items, string(opspec.ActionUnitRestart))
	if restart.Allowed || restart.ReasonCode != ReasonPermissionDenied {
		t.Fatalf("an administrator of another site restarts a unit here: %+v", restart)
	}
}

func TestAMissingAdapterRefusesTheActionWithTheHostsOwnWords(t *testing.T) {
	admin := principalWith(authz.RolePlatformAdmin, labScope)
	registry := hosts.Capabilities{
		{Name: hosts.CapSystemd, Available: false, Reason: "this host does not run systemd"},
	}
	items := hostActions(admin, onlineHost(registry), labScope)

	restart := verdictOf(t, items, string(opspec.ActionUnitRestart))
	if restart.Allowed || restart.ReasonCode != ReasonCapabilityMissing {
		t.Fatalf("unit.restart without systemd: %+v", restart)
	}
	if restart.Reason != "the host lacks capability systemd: this host does not run systemd" {
		t.Errorf("the reason does not repeat what the host said: %q", restart.Reason)
	}
	// An adapter the registry never mentions is missing as well, and the
	// sentence then has nothing of the host's to add.
	pull := verdictOf(t, items, string(opspec.ActionDockerPull))
	if pull.Allowed || pull.ReasonCode != ReasonCapabilityMissing || pull.Reason != "the host lacks capability docker" {
		t.Fatalf("docker.image.pull without docker: %+v", pull)
	}
	// An operation without a capability requirement is not refused for one.
	signal := verdictOf(t, items, string(opspec.ActionProcessSignal))
	if !signal.Allowed {
		t.Fatalf("process.signal needs no adapter and was refused: %+v", signal)
	}
}

func TestAReadOnlyAdapterIsARefusalOfItsOwnKind(t *testing.T) {
	admin := principalWith(authz.RolePlatformAdmin, labScope)
	items := hostActions(admin, onlineHost(systemdRegistry), labScope)

	mtu := verdictOf(t, items, string(opspec.ActionNetworkMTUSet))
	if mtu.Allowed || mtu.ReasonCode != ReasonReadOnlyHost {
		t.Fatalf("network.mtu.set on a read-only network adapter: %+v", mtu)
	}
	if mtu.Reason != "the host can only read with its network adapter: no NetworkManager, nmstate or netplan; the panel only reads the network here" {
		t.Errorf("the reason does not say what the host said: %q", mtu.Reason)
	}
	// Reading through the same adapter still works.
	if plan := verdictOf(t, items, string(opspec.ActionNetworkPlan)); !plan.Allowed {
		t.Fatalf("network.plan on a read-only network adapter: %+v", plan)
	}
}

func TestLifecycleStatesRefuseEveryOrder(t *testing.T) {
	admin := principalWith(authz.RolePlatformAdmin, labScope)
	cases := []struct {
		state string
		code  string
	}{
		{hosts.StateQuarantined, ReasonHostQuarantined},
		{hosts.StateRecovery, ReasonHostRecovery},
		{hosts.StateRetiring, ReasonHostRetired},
		{hosts.StateRetired, ReasonHostRetired},
	}
	for _, tc := range cases {
		host := onlineHost(systemdRegistry)
		host.LifecycleState = tc.state
		items := hostActions(admin, host, labScope)
		for _, item := range items[:len(opspec.AllActions())] {
			if item.Allowed || item.ReasonCode != tc.code {
				t.Errorf("%s on a %s host: %+v", item.Action, tc.state, item)
				break
			}
		}
	}
}

func TestAnOfflineHostRefusesReadsAndQueuesChanges(t *testing.T) {
	admin := principalWith(authz.RolePlatformAdmin, labScope)
	host := onlineHost(systemdRegistry)
	host.ConnectionState = "offline"
	items := hostActions(admin, host, labScope)

	status := verdictOf(t, items, string(opspec.ActionUnitStatus))
	if status.Allowed || status.ReasonCode != ReasonHostOffline {
		t.Fatalf("a read from an offline host: %+v", status)
	}
	restart := verdictOf(t, items, string(opspec.ActionUnitRestart))
	if !restart.Allowed || restart.Note == "" {
		t.Fatalf("a change on an offline host is refused or has no note: %+v", restart)
	}
}

func TestAHelperThatDidNotAnswerRefusesChangesAndNotReads(t *testing.T) {
	admin := principalWith(authz.RolePlatformAdmin, labScope)
	silent := append(hosts.Capabilities{
		{Name: helperAdapter, Available: true,
			Features: map[string]bool{"observe": false, "prefer": false, "enforce": false},
			Reason:   "the helper has not reported its capability mode"},
	}, systemdRegistry...)
	items := hostActions(admin, onlineHost(silent), labScope)

	restart := verdictOf(t, items, string(opspec.ActionUnitRestart))
	if restart.Allowed || restart.ReasonCode != ReasonHelperUnavailable {
		t.Fatalf("a change with a silent helper: %+v", restart)
	}
	if status := verdictOf(t, items, string(opspec.ActionUnitStatus)); !status.Allowed {
		t.Fatalf("a read with a silent helper: %+v", status)
	}

	// A helper that answered, in any mode, takes changes; an agent from
	// before the adapter says nothing about the helper and refuses nothing.
	answered := append(hosts.Capabilities{
		{Name: helperAdapter, Available: true, Features: map[string]bool{"observe": true}},
	}, systemdRegistry...)
	if restart := verdictOf(t, hostActions(admin, onlineHost(answered), labScope), string(opspec.ActionUnitRestart)); !restart.Allowed {
		t.Fatalf("a change with an answering helper: %+v", restart)
	}
	if restart := verdictOf(t, hostActions(admin, onlineHost(systemdRegistry), labScope), string(opspec.ActionUnitRestart)); !restart.Allowed {
		t.Fatalf("a change on an agent without the helper adapter: %+v", restart)
	}
}

func TestABrokenPackageDatabaseBlocksPackageChangesButNotTheRepair(t *testing.T) {
	admin := principalWith(authz.RolePlatformAdmin, labScope)
	host := onlineHost(append(hosts.Capabilities{
		{Name: hosts.CapAPT, Available: true, Features: map[string]bool{"repair": true}},
	}, systemdRegistry...))
	host.PackageDatabaseBroken = true
	items := hostActions(admin, host, labScope)

	if upgrade := verdictOf(t, items, string(opspec.ActionPackageUpgrade)); upgrade.Allowed || upgrade.ReasonCode != ReasonPackageDatabaseBroken {
		t.Fatalf("packages.upgrade on a broken database: %+v", upgrade)
	}
	if repair := verdictOf(t, items, string(opspec.ActionPackageRepair)); !repair.Allowed {
		t.Fatalf("packages.repair on a broken database: %+v", repair)
	}
}

func TestAdapterOfResolvesLogicalRequirements(t *testing.T) {
	registry := hosts.Capabilities{{Name: hosts.CapDNF, Available: true}}
	cases := map[string]string{
		"":                      "",
		hosts.NeedPackages:      hosts.CapDNF,
		hosts.NeedPackageRepair: hosts.CapDNF,
		hosts.NeedNetworkWrite:  hosts.CapNetwork,
		hosts.NeedDNSWrite:      hosts.CapDNS,
		hosts.NeedFirewallWrite: hosts.CapFirewall,
		hosts.NeedFirewallZones: hosts.CapFirewall,
		hosts.NeedLVM:           hosts.CapStorage,
		hosts.CapSystemd:        hosts.CapSystemd,
	}
	for requirement, want := range cases {
		if got := adapterOf(registry, requirement); got != want {
			t.Errorf("adapterOf(%q) = %q, want %q", requirement, got, want)
		}
	}
	if got := adapterOf(hosts.Capabilities{}, hosts.NeedPackages); got != "" {
		t.Errorf("a host without a package adapter resolved packages to %q", got)
	}
}
