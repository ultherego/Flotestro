package authz

import (
	"sort"
	"testing"
)

// The roles page says what the built-in roles contain of one another, and a
// sentence that says "none contains another" went on being printed after the
// platform administrator was given everything. The page is held to the code:
// platform_admin carries every other role's permissions, and among the other
// five no role contains another.
func TestTheBuiltInRolesContainEachOtherAsThePageSays(t *testing.T) {
	contains := func(whole, part Role) bool {
		have := map[Permission]bool{}
		for _, p := range rolePermissions[whole] {
			have[p] = true
		}
		for _, p := range rolePermissions[part] {
			if !have[p] {
				return false
			}
		}
		return true
	}

	var found []string
	for a := range rolePermissions {
		for b := range rolePermissions {
			if a != b && contains(a, b) {
				found = append(found, string(a)+" contains "+string(b))
			}
		}
	}
	sort.Strings(found)

	var want []string
	for r := range rolePermissions {
		if r != RolePlatformAdmin {
			want = append(want, string(RolePlatformAdmin)+" contains "+string(r))
		}
	}
	sort.Strings(want)

	if len(found) != len(want) {
		t.Fatalf("the roles contain each other as %v; the roles page says only %v - change the page and this test together",
			found, want)
	}
	for i := range want {
		if found[i] != want[i] {
			t.Fatalf("the roles contain each other as %v; the roles page says only %v", found, want)
		}
	}
}
