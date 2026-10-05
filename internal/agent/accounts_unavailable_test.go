package agent

// A host whose accounts nobody could read says so, and the saying of it
// travels with the module.

import "testing"

// The reader of the local accounts answers with a reason when it did not
// finish: an empty list with no reason is a host with no local accounts, which
// does not happen. The reason was collected into the facts and then dropped
// where the report is built, so what reached the panel was an empty list and
// nothing else - a host nobody could ask, shown as a host with no privileged
// accounts.
func TestTheAccountsModuleCarriesWhyItCouldNotBeRead(t *testing.T) {
	facts := Facts{LocalAccountsReason: "open /etc/passwd: permission denied"}
	fragments, err := facts.Fragments()
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, fragment := range fragments {
		if fragment.Module != ModuleAccounts {
			continue
		}
		found = true
		if fragment.UnavailableReason != facts.LocalAccountsReason {
			t.Fatalf("the accounts module says %q, the reader said %q",
				fragment.UnavailableReason, facts.LocalAccountsReason)
		}
	}
	if !found {
		t.Fatalf("the report carries no %s module", ModuleAccounts)
	}
}

// And a host that was read says nothing: the reason is a reason, not a label
// every report carries.
func TestTheAccountsModuleOfAHostThatWasReadNamesNoReason(t *testing.T) {
	facts := Facts{LocalAccounts: []LocalAccount{{Name: "root", UID: 0}}}
	fragments, err := facts.Fragments()
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range fragments {
		if fragment.Module == ModuleAccounts && fragment.UnavailableReason != "" {
			t.Fatalf("the accounts of a host that was read say %q", fragment.UnavailableReason)
		}
	}
}
