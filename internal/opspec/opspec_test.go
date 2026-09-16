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

// A read bounded to the window of a job names both ends in UTC: the
// panel knows the job's times in UTC, and a bare timestamp would be read
// in the host's own zone. The ends take the same forms, and nothing that
// is not a time.
func TestAJournalReadTakesAWindowInUTC(t *testing.T) {
	for _, window := range []JournalPayload{
		{Lines: 100, Since: "2026-09-15 10:00:00 UTC", Until: "2026-09-15 10:05:30 UTC"},
		{Lines: 100, Until: "-5m"},
		{Lines: 100, Since: "yesterday", Until: "today"},
		{Lines: 100, Until: "2026-09-15 10:05"},
	} {
		if err := Validate(ActionReadJournal, Payload{Journal: &window}); err != nil {
			t.Errorf("%+v was refused: %v", window, err)
		}
	}
	for _, bad := range []string{"2026-09-15T10:00:00Z", "10:00 UTC", "now; rm -rf /", "2026-09-15 10:00:00 CET"} {
		window := JournalPayload{Lines: 100, Until: bad}
		if err := Validate(ActionReadJournal, Payload{Journal: &window}); err == nil {
			t.Errorf("until=%q passed validation", bad)
		}
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

// TestEveryHashSchemeIsAFunctionOfThePlan guards the switch of the scheme:
// the agent accepts a hash of any known scheme, so every scheme has to be
// as sensitive to a swapped plan as the one the panel issues, and the
// schemes have to differ from one another - otherwise the version number
// says nothing.
func TestEveryHashSchemeIsAFunctionOfThePlan(t *testing.T) {
	plan := Payload{Unit: &UnitPayload{Unit: "nginx.service"}}
	swapped := Payload{Unit: &UnitPayload{Unit: "sshd.service"}}
	seen := map[string]int{}
	for _, scheme := range PayloadHashSchemes {
		approved, err := PayloadHashOfScheme(scheme, ActionUnitRestart, ActionVersion, plan)
		if err != nil {
			t.Fatalf("scheme %d: %v", scheme, err)
		}
		again, err := PayloadHashOfScheme(scheme, ActionUnitRestart, ActionVersion, plan)
		if err != nil || !bytes.Equal(approved, again) {
			t.Fatalf("scheme %d is not stable", scheme)
		}
		tampered, err := PayloadHashOfScheme(scheme, ActionUnitRestart, ActionVersion, swapped)
		if err != nil {
			t.Fatalf("scheme %d: %v", scheme, err)
		}
		if bytes.Equal(approved, tampered) {
			t.Fatalf("scheme %d does not see a swapped plan", scheme)
		}
		if other, dup := seen[string(approved)]; dup {
			t.Fatalf("schemes %d and %d give the same hash", other, scheme)
		}
		seen[string(approved)] = scheme
	}
	issued, err := PayloadHash(ActionUnitRestart, ActionVersion, plan)
	if err != nil {
		t.Fatal(err)
	}
	if seen[string(issued)] != PayloadHashVersion {
		t.Fatalf("the panel issues a hash of scheme %d, not %d", seen[string(issued)], PayloadHashVersion)
	}
	if _, err := PayloadHashOfScheme(99, ActionUnitRestart, ActionVersion, plan); err == nil {
		t.Fatal("an unknown scheme gave a hash")
	}
}

// TestTheReverseTableNamesOnlyDeclaredWaysBack guards the table a
// compensation is checked against: every row is a mutating operation whose
// reverse is another known mutating operation with a real way back, and an
// operation without a row - a restart, a signal - has no reverse at all
// rather than a guessed one.
func TestTheReverseTableNamesOnlyDeclaredWaysBack(t *testing.T) {
	for forward, reverse := range reverseActions {
		if !forward.Known() || !forward.Mutating() {
			t.Errorf("%s is not a known change and has no business in the reverse table", forward)
		}
		if !reverse.Known() || !reverse.Mutating() {
			t.Errorf("the reverse of %s, %s, is not a known change", forward, reverse)
		}
		if forward == reverse {
			t.Errorf("%s is listed as its own reverse", forward)
		}
		// A change whose contract says there is no way back cannot have
		// one in the table: the two declarations would contradict each
		// other on the screen.
		if forward.Contract().Rollback == RollbackNone || forward.Contract().Rollback == RollbackBestEffort {
			t.Errorf("%s declares rollback %s and yet names %s as its reverse",
				forward, forward.Contract().Rollback, reverse)
		}
	}
	if reverse, ok := ReverseAction(ActionFileEnsure); !ok || reverse != ActionFileRollback {
		t.Errorf("the reverse of a file write is %s (%v), expected file.rollback", reverse, ok)
	}
	for _, action := range []ActionType{ActionUnitRestart, ActionProcessSignal, ActionSystemReboot, ActionFileRollback, "no.such"} {
		if reverse, ok := ReverseAction(action); ok {
			t.Errorf("%s has a reverse, %s, though nothing declares one", action, reverse)
		}
	}
}

func scheduleOrder(user string, command ...string) Payload {
	if len(command) == 0 {
		command = []string{"/usr/bin/true"}
	}
	return Payload{Schedule: &SchedulePayload{
		ID: "nightly", Expression: "0 3 * * *", Command: command, User: user, Enabled: true,
	}}
}

// The user of a cron line is separated from the command by whitespace
// only, and it used to reach the host unchecked, root by default. A value
// that would not stay in its field is refused at ordering time, as is an
// entry that names no account: root is a decision, not a default.
func TestAScheduleUserHasToBeAnAccountName(t *testing.T) {
	for _, user := range []string{
		"", "root; /bin/sh", "root\n* * * * * root /bin/sh", "root\t/bin/sh", "root #",
		"Root", "-root", "a.b", "user$", "0user", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	} {
		if err := Validate(ActionScheduleEnsure, scheduleOrder(user)); err == nil {
			t.Errorf("the user %q passed validation", user)
		}
	}
	for _, user := range []string{"root", "backup", "www-data", "_apt", "svc_backup-2"} {
		if err := Validate(ActionScheduleEnsure, scheduleOrder(user)); err != nil {
			t.Errorf("the user %q was refused: %v", user, err)
		}
	}
	// Disabling, removing and running name only the entry; no user is
	// involved there.
	if err := Validate(ActionScheduleRemove, Payload{Schedule: &SchedulePayload{ID: "nightly"}}); err != nil {
		t.Errorf("a removal without a user was refused: %v", err)
	}
}

// A zero byte ends the string for the tools that read the line; the shell
// character list would not see it.
func TestAScheduleCommandRefusesAZeroByte(t *testing.T) {
	for _, command := range [][]string{
		{"/usr/bin/true\x00; /bin/sh"},
		{"/usr/bin/true", "a\x00b"},
		{"true"},
		{"/usr/bin/true", ""},
	} {
		if err := Validate(ActionScheduleEnsure, scheduleOrder("root", command...)); err == nil {
			t.Errorf("the command %q passed validation", command)
		}
	}
}

// The content of an order can ask for more than the operation: an entry
// for root needs schedule.root.exec on top of schedule.write, and a write
// allowed to skip its validator needs file.write.unvalidated. Everything
// else asks for nothing beyond the registry's permission.
func TestPayloadPermissionsNameWhatTheContentAsksFor(t *testing.T) {
	if got := PayloadPermissions(ActionScheduleEnsure, scheduleOrder("root")); len(got) != 1 || got[0] != PermissionScheduleRootExec {
		t.Errorf("root entry needs %v, want [%s]", got, PermissionScheduleRootExec)
	}
	if got := PayloadPermissions(ActionScheduleEnsure, scheduleOrder("backup")); len(got) != 0 {
		t.Errorf("a service account entry needs %v, want nothing", got)
	}
	// Removing or running an entry of root is judged by the entry's own
	// permissions; the payload carries no user there.
	if got := PayloadPermissions(ActionScheduleRemove, Payload{Schedule: &SchedulePayload{ID: "nightly", User: "root"}}); len(got) != 0 {
		t.Errorf("a removal needs %v, want nothing", got)
	}
	file := &FilePayload{Path: "/etc/app.conf", Content: "x\n", AllowMissingValidator: true}
	for _, action := range []ActionType{ActionFileEnsure, ActionFileRollback} {
		if got := PayloadPermissions(action, Payload{File: file}); len(got) != 1 || got[0] != PermissionFileWriteUnvalidated {
			t.Errorf("%s allowed to skip its validator needs %v, want [%s]", action, got, PermissionFileWriteUnvalidated)
		}
	}
	checked := &FilePayload{Path: "/etc/app.conf", Content: "x\n"}
	if got := PayloadPermissions(ActionFileEnsure, Payload{File: checked}); len(got) != 0 {
		t.Errorf("a checked write needs %v, want nothing", got)
	}
	if got := PayloadPermissions(ActionFilePlan, Payload{File: file}); len(got) != 0 {
		t.Errorf("a plan needs %v, want nothing", got)
	}
	if got := PayloadPermissions(ActionUnitRestart, Payload{Unit: &UnitPayload{Unit: "nginx.service"}}); len(got) != 0 {
		t.Errorf("a unit restart needs %v, want nothing", got)
	}
}

// The order says whether it may skip the validator; the flag is part of
// the payload and so of its hash, so it cannot be added after approval.
func TestAllowMissingValidatorEntersThePayloadHash(t *testing.T) {
	checked := Payload{File: &FilePayload{Path: "/etc/app.conf", Content: "x\n"}}
	unchecked := Payload{File: &FilePayload{Path: "/etc/app.conf", Content: "x\n", AllowMissingValidator: true}}
	a, err := PayloadHash(ActionFileEnsure, ActionVersion, checked)
	if err != nil {
		t.Fatal(err)
	}
	b, err := PayloadHash(ActionFileEnsure, ActionVersion, unchecked)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) == string(b) {
		t.Error("the payload hash does not see allow_missing_validator")
	}
}
