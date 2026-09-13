package opspec

import (
	"strings"
	"testing"
)

// TestARefreshWithoutAScopeIsValid guards that the most common way - "show me
// how things are now" - requires nothing from the operator.
func TestARefreshWithoutAScopeIsValid(t *testing.T) {
	if err := Validate(ActionInventoryRefresh, Payload{}); err != nil {
		t.Fatalf("a refresh without a scope was rejected: %v", err)
	}
	if err := Validate(ActionInventoryRefresh, Payload{Inventory: &InventoryPayload{}}); err != nil {
		t.Fatalf("a refresh with an empty scope was rejected: %v", err)
	}
}

// TestAnUnknownModuleIsAnError guards the rule that a typo must not end in a
// task that refreshes nothing and looks like a success.
func TestAnUnknownModuleIsAnError(t *testing.T) {
	err := Validate(ActionInventoryRefresh, Payload{
		Inventory: &InventoryPayload{Modules: []string{"nonexistent"}},
	})
	if err == nil || !strings.Contains(err.Error(), "unknown inventory module") {
		t.Fatalf("an unknown module gave %v", err)
	}
}

func TestARepeatedModuleIsAnError(t *testing.T) {
	err := Validate(ActionInventoryRefresh, Payload{
		Inventory: &InventoryPayload{Modules: []string{"packages", "packages"}},
	})
	if err == nil {
		t.Fatal("a repeated module was accepted")
	}
}

func TestAScopeOfValidModulesPasses(t *testing.T) {
	err := Validate(ActionInventoryRefresh, Payload{
		Inventory: &InventoryPayload{Modules: []string{"packages", "network", "containers"}},
	})
	if err != nil {
		t.Fatalf("a valid scope was rejected: %v", err)
	}
}

// TestARefreshTakesNoLock guards a property that follows from the operation
// changing nothing: a read may run alongside an operation that is under way -
// at worst it will see state halfway through a change, and that is the truth
// about this moment.
func TestARefreshTakesNoLock(t *testing.T) {
	spec := ActionInventoryRefresh.Describe()
	if spec.Mutating {
		t.Fatal("an inventory refresh is marked as changing the host")
	}
	if spec.LockClass != LockNone {
		t.Fatalf("lock class = %q", spec.LockClass)
	}
	if spec.Risk != RiskLow {
		t.Fatalf("risk = %v", spec.Risk)
	}
	if spec.Permission != "inventory.refresh" {
		t.Fatalf("permission = %q", spec.Permission)
	}
}
