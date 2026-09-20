package adminapi

import (
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/inventory"
	"github.com/ultherego/flotestro/internal/opspec"
)

// Whether an account is root by another name is read from the host's last
// report, and only a current, complete report answers; the rest are unknown.
func TestAnAccountIsClassifiedOnlyFromACurrentReport(t *testing.T) {
	now := time.Now()
	fresh := now.Add(-time.Hour)
	observed := []inventory.LocalAccount{
		{Name: "jane", Groups: []string{"jane", "wheel"}, ObservedAt: fresh},
		{Name: "deploy", Groups: []string{"deploy"}, ObservedAt: fresh},
		{Name: "stale", Groups: []string{"stale"}, ObservedAt: now.Add(-accountObservationMaxAge - time.Minute)},
		{Name: "unreadable", Groups: []string{"unreadable"}, ObservedAt: fresh, UnavailableReason: "shadow_unreadable"},
		{Name: "groupless", Groups: []string{}, ObservedAt: fresh},
		{Name: "undated", Groups: []string{"undated"}},
	}
	expected := map[string]opspec.AccountPrivilege{
		"jane":       opspec.AccountPrivilegePrivileged,
		"deploy":     opspec.AccountPrivilegeOrdinary,
		"stale":      opspec.AccountPrivilegeUnknown,
		"unreadable": opspec.AccountPrivilegeUnknown,
		"groupless":  opspec.AccountPrivilegeUnknown,
		"undated":    opspec.AccountPrivilegeUnknown,
		"absent":     opspec.AccountPrivilegeUnknown,
	}
	for name, want := range expected {
		if got := accountPrivilegeOf(observed, name, now); got != want {
			t.Errorf("%s came out %s, expected %s", name, got, want)
		}
	}
	// A host that has reported nothing at all classifies no account.
	if got := accountPrivilegeOf(nil, "jane", now); got != opspec.AccountPrivilegeUnknown {
		t.Errorf("a host without a report gave %s", got)
	}
}

// The escalation this closes: a key added to an account that already sits in
// wheel is a grant of root, and the panel must see it as one.
func TestAKeyOnAWheelAccountIsAGrantOfRoot(t *testing.T) {
	now := time.Now()
	observed := []inventory.LocalAccount{
		{Name: "backup", Groups: []string{"backup", "wheel"}, ObservedAt: now.Add(-time.Minute)},
	}
	order := opspec.Payload{LocalUser: &opspec.LocalUserPayload{
		Name: "backup",
		Keys: []opspec.SSHKeyInput{{PublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA mallory@laptop"}},
	}}
	privilege := accountPrivilegeOf(observed, "backup", now)
	if !opspec.GrantsPrivilegedAccess(opspec.ActionLocalSSHKeysAdd, order, privilege) {
		t.Fatal("a key added to a wheel account is not treated as a grant of root")
	}
}
