package authz

import "testing"

// identity_admin holds the key and unlock permissions, but an account that is
// root by another name is opened by whoever may grant root, not by this role.
func TestIdentityAdminManagesAccountsButGrantsNoRoot(t *testing.T) {
	for _, permission := range []Permission{
		PermLocalUserCreate, PermLocalUserUnlock,
		PermLocalSSHKeyAdd, PermLocalSSHKeyRemove, PermLocalSSHKeyReplace,
	} {
		if !RoleIdentityAdmin.Has(permission) {
			t.Errorf("identity_admin lost %s; local accounts are its work", permission)
		}
	}
	for _, role := range []Role{RoleIdentityAdmin, RoleOperator, RoleApprover, RoleAuditor, RoleViewer} {
		if role.Has(PermAccountsPrivilegedGroups) {
			t.Errorf("%s may grant root by another name; only the platform admin does", role)
		}
	}
	if !RolePlatformAdmin.Has(PermAccountsPrivilegedGroups) {
		t.Error("nobody may grant a privileged membership at all")
	}
}
