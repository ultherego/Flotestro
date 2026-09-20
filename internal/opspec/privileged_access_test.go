package opspec

import "testing"

func keyOrder(name string) Payload {
	return Payload{LocalUser: &LocalUserPayload{
		Name: name,
		Keys: []SSHKeyInput{{PublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA jane@laptop"}},
	}}
}

// An order that hands over an account's own access carries no group: the key
// add, the list rewrite, the unlock and the cleared expiry all do it.
func TestOrdersThatHandOverTheAccessOfAnAccount(t *testing.T) {
	handing := map[ActionType]Payload{
		ActionLocalSSHKeysAdd: keyOrder("jane"),
		ActionLocalSSHKeysReplaceAll: {LocalUser: &LocalUserPayload{
			Name: "jane", SSHKeys: []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA jane@laptop"},
			ExpectedFingerprints: []string{},
		}},
		ActionLocalSSHKeysSet: {LocalUser: &LocalUserPayload{
			Name: "jane", SSHKeys: []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA jane@laptop"},
		}},
		ActionLocalUserUnlock:    {LocalUser: &LocalUserPayload{Name: "jane"}},
		ActionLocalUserExpirySet: {LocalUser: &LocalUserPayload{Name: "jane"}},
	}
	for action, payload := range handing {
		if !HandsOverAccountAccess(action, payload) {
			t.Errorf("%s does not count as handing over the account's access", action)
		}
	}
	keeping := map[ActionType]Payload{
		// Taking a key away narrows the access rather than handing it over.
		ActionLocalSSHKeysRemove: {LocalUser: &LocalUserPayload{Name: "jane", Fingerprints: []string{"SHA256:x"}}},
		// A rewrite that leaves no key is the removal, not a way in.
		ActionLocalSSHKeysReplaceAll: {LocalUser: &LocalUserPayload{Name: "jane", ExpectedFingerprints: []string{}}},
		ActionLocalUserLock:          {LocalUser: &LocalUserPayload{Name: "jane"}},
		// An expiry with a date is a lock with a date, not a way back in.
		ActionLocalUserExpirySet: {LocalUser: &LocalUserPayload{Name: "jane", ExpiresAt: "2030-01-01"}},
		ActionUnitRestart:        {Unit: &UnitPayload{Unit: "nginx.service"}},
	}
	for action, payload := range keeping {
		if HandsOverAccountAccess(action, payload) {
			t.Errorf("%s was taken for handing over the account's access", action)
		}
	}
	if HandsOverAccountAccess(ActionLocalSSHKeysAdd, Payload{}) {
		t.Error("an order without an account was taken for handing over access")
	}
}

// The account the order names decides, and the fact is the host's: a key added
// to an account already in wheel is the grant of root the payload does not show.
func TestPrivilegedAndUnknownAccountsRaiseAKeyOrder(t *testing.T) {
	order := keyOrder("jane")
	for _, privilege := range []AccountPrivilege{AccountPrivilegePrivileged, AccountPrivilegeUnknown} {
		if !GrantsPrivilegedAccess(ActionLocalSSHKeysAdd, order, privilege) {
			t.Errorf("a key added to a %s account is not treated as a grant of root", privilege)
		}
		if risk := PayloadRiskForAccount(ActionLocalSSHKeysAdd, order, privilege); risk != RiskCritical {
			t.Errorf("a key added to a %s account has the risk %s, expected critical", privilege, risk)
		}
		if !PayloadRequiresFreshAuthForAccount(ActionLocalSSHKeysAdd, order, privilege) {
			t.Errorf("a key added to a %s account asks for no fresh authentication", privilege)
		}
	}
	if GrantsPrivilegedAccess(ActionLocalSSHKeysAdd, order, AccountPrivilegeOrdinary) {
		t.Error("a key added to an ordinary account was taken for a grant of root")
	}
	if risk := PayloadRiskForAccount(ActionLocalSSHKeysAdd, order, AccountPrivilegeOrdinary); risk != ActionLocalSSHKeysAdd.Risk() {
		t.Errorf("an ordinary account changed the risk of the operation to %s", risk)
	}
	if PayloadRequiresFreshAuthForAccount(ActionLocalSSHKeysAdd, order, AccountPrivilegeOrdinary) {
		t.Error("a key added to an ordinary account asks for fresh authentication")
	}
}

// The host's word does not reach the orders that carry the groups themselves:
// those are judged by their payload, as before.
func TestTheAccountFactDoesNotChangeTheOrdersThatNameGroups(t *testing.T) {
	plain := Payload{LocalUser: &LocalUserPayload{Name: "jane", Groups: []string{"developers"}}}
	if risk := PayloadRiskForAccount(ActionLocalUserGroupsSet, plain, AccountPrivilegeUnknown); risk != RiskHigh {
		t.Errorf("an unknown account raised a groups change to %s", risk)
	}
	raised := Payload{LocalUser: &LocalUserPayload{Name: "jane", Groups: []string{"sudo"}}}
	if risk := PayloadRiskForAccount(ActionLocalUserGroupsSet, raised, AccountPrivilegeOrdinary); risk != RiskCritical {
		t.Errorf("a move into sudo has the risk %s, expected critical", risk)
	}
	// A deletion is destructive by the registry and stays so whatever the
	// account turns out to be.
	if risk := PayloadRiskForAccount(ActionLocalUserDelete, plain, AccountPrivilegeOrdinary); risk != ActionLocalUserDelete.Risk() {
		t.Errorf("a deletion has the risk %s, expected %s", risk, ActionLocalUserDelete.Risk())
	}
}
