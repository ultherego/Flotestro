package gateway

// What the panel does with a report whose accounts the host could not read.

import (
	"testing"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/inventory"
)

func accountsReport(reason string, accounts ...*agentv1.LocalAccount) *agentv1.InventoryReport {
	return &agentv1.InventoryReport{
		Full:          true,
		LocalAccounts: accounts,
		Fragments: []*agentv1.InventoryFragment{{
			Module: inventory.ModuleAccounts, Revision: "aaaa", Source: "agent/passwd",
			UnavailableReason: reason,
		}},
	}
}

// A full report whose accounts module names a reason carries no accounts
// because nobody could read them, not because the host has none. Turning that
// into an empty list replaced every account the panel held with nothing, and
// the operator read a host with no privileged accounts - the one reading the
// absence of data must never produce.
func TestAFailedReadOfTheAccountsDoesNotEraseThemFromThePanel(t *testing.T) {
	accounts := localAccountsFromReport(accountsReport("open /etc/passwd: permission denied"))
	if accounts != nil {
		t.Fatalf("a report nobody could fill projected %d accounts instead of saying nothing", len(accounts))
	}
}

// A host that really has no accounts in the report - the module was read and
// says so - still erases what the panel holds, because that is an observation.
func TestAnEmptyAccountsModuleThatWasReadStillReplacesWhatThePanelHolds(t *testing.T) {
	accounts := localAccountsFromReport(accountsReport(""))
	if accounts == nil {
		t.Fatal("a report that read the accounts and found none said nothing instead")
	}
	if len(accounts) != 0 {
		t.Fatalf("the report carries %d accounts", len(accounts))
	}
}

// A reason beside accounts that were read is the partial case: the helper
// could not be asked about some of them, and what was read is still stored.
func TestAccountsThatWereReadAreStoredEvenWithAReasonBesideThem(t *testing.T) {
	accounts := localAccountsFromReport(accountsReport("helper: the lock was held",
		&agentv1.LocalAccount{Name: "root", Uid: 0}))
	if len(accounts) != 1 || accounts[0].Name != "root" {
		t.Fatalf("the accounts the host did read were projected as %+v", accounts)
	}
}
