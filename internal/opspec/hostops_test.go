package opspec

import (
	"testing"

	"github.com/ultherego/flotestro/internal/modules/accounts"
)

// A container log read takes a name as well as an identifier: it is a read,
// and the name is what the operator has in front of them. The value still
// lands in the path of an Engine API request, so nothing that changes the
// path passes.
func TestContainerLogsValidation(t *testing.T) {
	for _, target := range []string{"web", "5c5b63d3119a", "shop_web-1"} {
		payload := Payload{DockerLogs: &DockerLogsPayload{ContainerID: target, Lines: 200, Since: "15m"}}
		if err := Validate(ActionDockerLogs, payload); err != nil {
			t.Errorf("%q was rejected: %v", target, err)
		}
	}
	bad := map[string]DockerLogsPayload{
		"a path":         {ContainerID: "../images/json"},
		"a query":        {ContainerID: "web?all=1"},
		"empty":          {},
		"too many lines": {ContainerID: "web", Lines: 5001},
		"a bad since":    {ContainerID: "web", Since: "yesterday"},
		"a huge window":  {ContainerID: "web", Since: "400d"},
	}
	for name, payload := range bad {
		copied := payload
		if err := Validate(ActionDockerLogs, Payload{DockerLogs: &copied}); err == nil {
			t.Errorf("%s: the payload should have been rejected", name)
		}
	}
	if err := Validate(ActionDockerLogs, Payload{}); err == nil {
		t.Error("a read without a payload was accepted")
	}
	if ActionDockerLogs.Mutating() || ActionDockerLogs.Risk() != RiskLow {
		t.Error("reading a log is a low-risk read")
	}
	if ActionDockerLogs.LockClass() != LockNone {
		t.Error("reading a log must not wait for a container restart")
	}
}

// A rename changes the identity of the host towards everything that knows
// it by name: critical, the whole host as the lock, the target name typed
// by hand, and in bulk only as a mapping that names every host by itself.
func TestHostnameSetContract(t *testing.T) {
	if err := Validate(ActionSystemHostnameSet, Payload{Hostname: &HostnamePayload{Hostname: "web02.example.internal", Pretty: "Web 02"}}); err != nil {
		t.Fatalf("a valid rename was rejected: %v", err)
	}
	for name, payload := range map[string]HostnamePayload{
		"empty":            {},
		"upper case":       {Hostname: "Web02"},
		"a space":          {Hostname: "web 02"},
		"a shell":          {Hostname: "web02;reboot"},
		"localhost":        {Hostname: "localhost"},
		"a pretty newline": {Hostname: "web02", Pretty: "Web\n02"},
	} {
		copied := payload
		if err := Validate(ActionSystemHostnameSet, Payload{Hostname: &copied}); err == nil {
			t.Errorf("%s: the payload should have been rejected", name)
		}
	}
	if ActionSystemHostnameSet.Risk() != RiskCritical || !ActionSystemHostnameSet.RequiresFreshAuth() {
		t.Error("a rename has to be critical")
	}
	if !ActionSystemHostnameSet.RequiresTargetConfirmation() {
		t.Error("a rename has to require typing the target name")
	}
	if ActionSystemHostnameSet.LockClass() != LockHost {
		t.Errorf("a rename locks %q, expected the whole host", ActionSystemHostnameSet.LockClass())
	}
	// In bulk the order is split host by host in the panel: the mode is a
	// per-host plan, and the plan comes from the mapping, not from a read
	// on the host.
	if ActionSystemHostnameSet.CampaignMode() != CampaignPerHostPlan || !PanelPlanned(ActionSystemHostnameSet) {
		t.Error("a rename in bulk is a per-host plan split from the order")
	}
	if ActionSystemHostnameSet.OfflinePolicy() != OfflineRequireOnline {
		t.Error("a rename requires the host online")
	}
	contract := ActionSystemHostnameSet.Contract()
	if contract.CancelMode != CancelImpossibleAfterStart || contract.RetryClass != RetryReadState ||
		contract.Rollback != RollbackCompensating || contract.Verification != VerifyCustom {
		t.Errorf("contract = %+v", contract)
	}
	if len(contract.ResourceClaims) != 1 || contract.ResourceClaims[0].Class != LockHost {
		t.Errorf("claims = %+v, expected the host", contract.ResourceClaims)
	}
}

// The risk of a groups change depends on its content: a membership in sudo
// or docker is root by another name, so such an order needs fresh
// authentication like every critical change of access.
func TestPrivilegedGroupsRaiseTheRisk(t *testing.T) {
	plain := Payload{LocalUser: &LocalUserPayload{Name: "smith", Groups: []string{"developers", "audio"}}}
	if err := Validate(ActionLocalUserGroupsSet, plain); err != nil {
		t.Fatalf("a valid group list was rejected: %v", err)
	}
	if risk := PayloadRisk(ActionLocalUserGroupsSet, plain); risk != RiskHigh {
		t.Errorf("plain groups have the risk %s, expected high", risk)
	}
	if PayloadRequiresFreshAuth(ActionLocalUserGroupsSet, plain) {
		t.Error("plain groups require fresh authentication")
	}
	for _, group := range accounts.PrivilegedGroups() {
		raised := Payload{LocalUser: &LocalUserPayload{Name: "smith", Groups: []string{"developers", group}}}
		if risk := PayloadRisk(ActionLocalUserGroupsSet, raised); risk != RiskCritical {
			t.Errorf("group %s gives the risk %s, expected critical", group, risk)
		}
		if !PayloadRequiresFreshAuth(ActionLocalUserGroupsSet, raised) {
			t.Errorf("group %s does not require fresh authentication", group)
		}
	}
	// An empty list takes every supplementary group away and is a valid
	// order, not missing data.
	if err := Validate(ActionLocalUserGroupsSet, Payload{LocalUser: &LocalUserPayload{Name: "smith", Groups: []string{}}}); err != nil {
		t.Errorf("taking the groups away was rejected: %v", err)
	}
	if err := Validate(ActionLocalUserGroupsSet, Payload{LocalUser: &LocalUserPayload{Name: "smith", Groups: []string{"su do"}}}); err == nil {
		t.Error("an invalid group name was accepted")
	}
	// An account created straight into a privileged group is the same
	// grant of root as moving one into it, so the create carries the
	// raised risk too; a create without such a group keeps the risk of
	// the operation.
	if risk := PayloadRisk(ActionLocalUserCreate, Payload{LocalUser: &LocalUserPayload{Name: "smith", Groups: []string{"sudo"}}}); risk != RiskCritical {
		t.Errorf("creating an account in sudo has the risk %s, expected critical", risk)
	}
	if risk := PayloadRisk(ActionLocalUserCreate, Payload{LocalUser: &LocalUserPayload{Name: "smith", Groups: []string{"developers"}}}); risk != RiskHigh {
		t.Errorf("creating an ordinary account has the risk %s, expected high", risk)
	}
}

func TestExpiryValidation(t *testing.T) {
	good := []string{"2030-01-01", "2020-02-29", ""}
	for _, date := range good {
		payload := Payload{LocalUser: &LocalUserPayload{Name: "smith", ExpiresAt: date}}
		if err := Validate(ActionLocalUserExpirySet, payload); err != nil {
			t.Errorf("%q was rejected: %v", date, err)
		}
	}
	for _, date := range []string{"tomorrow", "2030-13-01", "01/01/2030", "2030-1-1", "2030-01-01T00:00:00Z"} {
		payload := Payload{LocalUser: &LocalUserPayload{Name: "smith", ExpiresAt: date}}
		if err := Validate(ActionLocalUserExpirySet, payload); err == nil {
			t.Errorf("%q was accepted", date)
		}
	}
	// An expiry date on an operation that does not set one is an error in
	// the order, not something to silently drop.
	if err := Validate(ActionLocalUserLock, Payload{LocalUser: &LocalUserPayload{Name: "smith", ExpiresAt: "2030-01-01"}}); err == nil {
		t.Error("an expiry date on a lock was accepted")
	}
}

// Deleting an account is destructive: the operator types the account name
// and two people approve, the way every destructive operation goes. The
// accounts the panel never deletes are refused when the order is placed.
func TestAccountDeletionIsDestructive(t *testing.T) {
	payload := Payload{LocalUser: &LocalUserPayload{Name: "smith", RemoveHome: true}}
	if err := Validate(ActionLocalUserDelete, payload); err != nil {
		t.Fatalf("a valid deletion was rejected: %v", err)
	}
	if ActionLocalUserDelete.Risk() != RiskDestructive || !ActionLocalUserDelete.RequiresTargetConfirmation() {
		t.Error("deleting an account has to be destructive")
	}
	if target := ConfirmationTarget(ActionLocalUserDelete, payload, "web01"); target != "smith" {
		t.Errorf("the confirmation target is %q, expected the account name", target)
	}
	if target := ConfirmationTarget(ActionSystemShutdown, Payload{}, "web01"); target != "web01" {
		t.Errorf("the confirmation target of a shutdown is %q", target)
	}
	if ActionLocalUserDelete.CampaignMode() != CampaignNone {
		t.Error("deleting an account must not run in bulk")
	}
	for _, name := range []string{"root", "flotestro-agent", "nobody"} {
		if err := Validate(ActionLocalUserDelete, Payload{LocalUser: &LocalUserPayload{Name: name}}); err == nil {
			t.Errorf("deleting %s was accepted", name)
		}
	}
	// The other system accounts are the host's decision: it sees their
	// identifiers and refuses them with system_account.
	if err := Validate(ActionLocalUserDelete, Payload{LocalUser: &LocalUserPayload{Name: "daemon"}}); err != nil {
		t.Errorf("the order for daemon is refused by the host, not by the panel: %v", err)
	}
	// Removing the home directory belongs to deletion alone.
	if err := Validate(ActionLocalUserLock, Payload{LocalUser: &LocalUserPayload{Name: "smith", RemoveHome: true}}); err == nil {
		t.Error("remove_home on a lock was accepted")
	}
}

func TestSmartReadValidation(t *testing.T) {
	if err := Validate(ActionStorageSmartRead, Payload{Storage: &StoragePayload{Device: "/dev/sda"}}); err != nil {
		t.Fatalf("a valid device was rejected: %v", err)
	}
	if err := Validate(ActionStorageSmartRead, Payload{Storage: &StoragePayload{Device: "/dev/nvme0n1"}}); err != nil {
		t.Fatalf("an NVMe device was rejected: %v", err)
	}
	for _, device := range []string{"", "sda", "/dev/sda -x", "/dev/../etc", "/dev/SDA", "/etc/passwd"} {
		if err := Validate(ActionStorageSmartRead, Payload{Storage: &StoragePayload{Device: device}}); err == nil {
			t.Errorf("%q was accepted", device)
		}
	}
	if ActionStorageSmartRead.Mutating() || ActionStorageSmartRead.LockClass() != LockNone {
		t.Error("a SMART read changes nothing and takes no lock")
	}
	if ActionStorageSmartRead.RequiredCapability() != "storage" {
		t.Errorf("capability = %q", ActionStorageSmartRead.RequiredCapability())
	}
}

// The account operations keep separate permissions: granting a group is a
// different decision from deleting an account, and both differ from
// creating one.
func TestAccountOperationsHaveSeparatePermissions(t *testing.T) {
	seen := map[string]ActionType{}
	for _, action := range []ActionType{
		ActionLocalUserCreate, ActionLocalUserGroupsSet, ActionLocalUserExpirySet, ActionLocalUserDelete,
	} {
		if other, taken := seen[action.Permission()]; taken {
			t.Errorf("%s and %s share the permission %s", action, other, action.Permission())
		}
		seen[action.Permission()] = action
		if !action.Mutating() || action.RequiredCapability() != "" {
			t.Errorf("%s is a mutation without a host capability", action)
		}
	}
}
