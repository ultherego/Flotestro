package opspec

import (
	"bytes"
	"testing"
)

func TestThePayloadHashIsStable(t *testing.T) {
	payload := Payload{Unit: &UnitPayload{Unit: "nginx.service"}}

	first, err := PayloadHash(ActionUnitRestart, ActionVersion, payload)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	second, err := PayloadHash(ActionUnitRestart, ActionVersion, payload)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	// The server and the agent compute the hash independently; the same plan
	// has to give the same hash.
	if !bytes.Equal(first, second) {
		t.Fatal("the same plan gave different hashes")
	}
}

func TestThePayloadHashDetectsASwappedPlan(t *testing.T) {
	approved, _ := PayloadHash(ActionUnitRestart, ActionVersion,
		Payload{Unit: &UnitPayload{Unit: "nginx.service"}})

	cases := map[string]struct {
		action  ActionType
		version int
		payload Payload
	}{
		"swapped unit": {ActionUnitRestart, ActionVersion,
			Payload{Unit: &UnitPayload{Unit: "sshd.service"}}},
		"swapped operation": {ActionUnitStop, ActionVersion,
			Payload{Unit: &UnitPayload{Unit: "nginx.service"}}},
		"swapped contract version": {ActionUnitRestart, ActionVersion + 1,
			Payload{Unit: &UnitPayload{Unit: "nginx.service"}}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			tampered, err := PayloadHash(tc.action, tc.version, tc.payload)
			if err != nil {
				t.Fatalf("hash: %v", err)
			}
			if bytes.Equal(approved, tampered) {
				t.Fatal("swapping the plan did not change the hash")
			}
		})
	}
}

func TestValidateRequiresAPayloadMatchingTheType(t *testing.T) {
	if err := Validate(ActionUnitRestart, Payload{}); err == nil {
		t.Error("a unit operation without a payload passed validation")
	}
	if err := Validate(ActionUnitRestart, Payload{Unit: &UnitPayload{Unit: "  "}}); err == nil {
		t.Error("an empty unit name passed validation")
	}
	if err := Validate(ActionReadJournal, Payload{Unit: &UnitPayload{Unit: "nginx.service"}}); err == nil {
		t.Error("a journal read with a unit payload passed validation")
	}
	if err := Validate("unit.chmod", Payload{Unit: &UnitPayload{Unit: "x.service"}}); err == nil {
		t.Error("an unknown operation type passed validation")
	}
	if err := Validate(ActionUnitRestart, Payload{Unit: &UnitPayload{Unit: "nginx.service"}}); err != nil {
		t.Errorf("a valid operation was rejected: %v", err)
	}
}

func TestValidateBoundsAJournalRead(t *testing.T) {
	// A read without a line limit would allow pulling an arbitrarily large
	// result.
	if err := Validate(ActionReadJournal, Payload{Journal: &JournalPayload{Lines: 0}}); err == nil {
		t.Error("a read without a line limit passed validation")
	}
	if err := Validate(ActionReadJournal, Payload{Journal: &JournalPayload{Lines: 100000}}); err == nil {
		t.Error("a read above the limit passed validation")
	}
	priority := uint32(9)
	if err := Validate(ActionReadJournal,
		Payload{Journal: &JournalPayload{Lines: 100, MaxPriority: &priority}}); err == nil {
		t.Error("an invalid syslog priority passed validation")
	}
	if err := Validate(ActionReadJournal, Payload{Journal: &JournalPayload{Lines: 100}}); err != nil {
		t.Errorf("a valid read was rejected: %v", err)
	}
}

func TestMutatingOperationsAreDistinguished(t *testing.T) {
	if ActionReadJournal.Mutating() {
		t.Error("a journal read is not a mutation")
	}
	for _, action := range []ActionType{ActionUnitStart, ActionUnitStop, ActionUnitRestart, ActionUnitReload} {
		if !action.Mutating() {
			t.Errorf("%s has to be treated as a mutation", action)
		}
		if action.RequiredCapability() != "systemd" {
			t.Errorf("%s requires systemd", action)
		}
	}
	// Every operation has its own permission; there is no single broad admin
	// one.
	seen := map[string]bool{}
	for _, action := range AllActions() {
		permission := action.Permission()
		if permission == "" {
			t.Errorf("%s has no permission", action)
		}
		if seen[permission] {
			t.Errorf("the permission %s is shared by several operations", permission)
		}
		seen[permission] = true
	}
}

// A payload with an empty sub-payload describes the same operation as a
// payload without one. On a read the panel sends an empty payload, the
// envelope has nothing to carry, and the agent reconstructs a zero structure
// from it - and without a shared canonical form the hash came out different
// on the two sides.
func TestTheHashDoesNotDependOnAnEmptySubPayload(t *testing.T) {
	empty, err := PayloadHash(ActionSecurityScan, ActionVersion, Payload{})
	if err != nil {
		t.Fatal(err)
	}
	zero, err := PayloadHash(ActionSecurityScan, ActionVersion, Payload{Security: &SecurityPayload{}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(empty, zero) {
		t.Error("an empty sub-payload changed the plan hash")
	}

	// A sub-payload with content still changes the hash - otherwise swapping
	// an order would stop being detectable.
	withContent, err := PayloadHash(ActionSecurityScan, ActionVersion,
		Payload{Security: &SecurityPayload{Mode: "permissive"}})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(empty, withContent) {
		t.Error("the content of a sub-payload did not change the plan hash")
	}
}

// TestReplacingTheAgentHasItsOwnRules guards that the operation replacing the
// management mechanism itself does not accept just anything.
func TestReplacingTheAgentHasItsOwnRules(t *testing.T) {
	if err := Validate(ActionAgentUpgrade, Payload{}); err == nil {
		t.Error("replacing the agent without a payload passed")
	}
	if err := Validate(ActionAgentUpgrade, Payload{
		AgentUpgrade: &AgentUpgradePayload{TargetVersion: "0.2.0"},
	}); err != nil {
		t.Errorf("a valid version was rejected: %v", err)
	}
	// The version reaches the package manager's command line, so it must not
	// be arbitrary text.
	for _, bad := range []string{"", "0.2.0; rm -rf /", "$(id)", "version with a space"} {
		if err := Validate(ActionAgentUpgrade, Payload{
			AgentUpgrade: &AgentUpgradePayload{TargetVersion: bad},
		}); err == nil {
			t.Errorf("the version %q passed", bad)
		}
	}
	if err := Validate(ActionAgentUpgrade, Payload{
		AgentUpgrade: &AgentUpgradePayload{TargetVersion: "0.2.0", PackageSHA256: "not-a-sum"},
	}); err == nil {
		t.Error("a checksum that is not a SHA-256 passed")
	}

	// Replacing the agent has its own right: whoever may upgrade packages does
	// not thereby get the right to replace the management mechanism itself.
	if ActionAgentUpgrade.Permission() == ActionPackageUpgrade.Permission() {
		t.Error("replacing the agent shares its permission with an ordinary upgrade")
	}
	// The lock class is the same as for packages: two package transactions at
	// once mean a damaged package database.
	if ActionAgentUpgrade.LockClass() != ActionPackageUpgrade.LockClass() {
		t.Error("replacing the agent does not lock against package transactions")
	}
}
