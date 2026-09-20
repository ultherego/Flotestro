package buildinfo

import (
	"errors"
	"testing"
)

// The table of the tests: two protocol steps, so that a release between
// them, before them and after them each has an answer.
var testTable = []protocolStep{
	{Since: "0.1.0", Protocol: 1},
	{Since: "0.50.0", Protocol: 2},
}

func TestMinimumProtocolFollowsTheTable(t *testing.T) {
	cases := map[string]int{
		"0.1.0":       1,
		"0.41.0":      1,
		"0.49.9":      1,
		"0.50.0":      2,
		"0.50.0-1":    2,
		"0.50":        2,
		"0.51.3~beta": 2,
		"v1.0.0":      2,
	}
	for version, want := range cases {
		got, err := minimumProtocol(testTable, version)
		if err != nil {
			t.Errorf("%s: %v", version, err)
			continue
		}
		if got != want {
			t.Errorf("%s speaks protocol %d, expected %d", version, got, want)
		}
	}
	for _, bad := range []string{"", "abc", "0.0.1", "1.x"} {
		if _, err := minimumProtocol(testTable, bad); err == nil {
			t.Errorf("%q was given a protocol", bad)
		}
	}
}

// TestCheckProtocolRefusesANewerAgent: a panel speaking protocol 1 may order
// any release on protocol 1, and refuses one on protocol 2 with its own code.
func TestCheckProtocolRefusesANewerAgent(t *testing.T) {
	if err := checkProtocol(testTable, 1, "0.41.0"); err != nil {
		t.Fatalf("a compatible release was refused: %v", err)
	}
	err := checkProtocol(testTable, 1, "0.50.0")
	if !errors.Is(err, ErrProtocolIncompatible) {
		t.Fatalf("a newer protocol was not refused as incompatible: %v", err)
	}
	if err := checkProtocol(testTable, 2, "0.41.0"); err != nil {
		t.Fatalf("an older protocol was refused by a newer panel: %v", err)
	}
}

// TestTheRealTableIsConsistent: the shipped table is ordered, its steps are
// versions, and the newest step is the protocol this binary speaks.
func TestTheRealTableIsConsistent(t *testing.T) {
	previous := []int{}
	for _, step := range protocolByVersion {
		parsed, err := parseVersion(step.Since)
		if err != nil {
			t.Fatalf("the table names %q: %v", step.Since, err)
		}
		if compareVersions(parsed, previous) <= 0 {
			t.Fatalf("the table is not ordered at %s", step.Since)
		}
		previous = parsed
	}
	newest := protocolByVersion[len(protocolByVersion)-1].Protocol
	if newest != AgentProtocol {
		t.Fatalf("the newest step speaks protocol %d, this binary %d", newest, AgentProtocol)
	}
	if err := CheckProtocol(Version); err != nil {
		t.Fatalf("this binary's own version is refused: %v", err)
	}
}

func TestTheHashSchemeFollowsTheAgentVersion(t *testing.T) {
	cases := map[string]int{
		"0.1.0": 1, "0.42.0": 1, "0.42.9-1": 1,
		"0.43.0": 2, "0.44.0": 2, "1.0.0": 2,
		"": 1, "devel": 1,
	}
	for version, want := range cases {
		if got := PayloadHashSchemeFor(version); got != want {
			t.Errorf("PayloadHashSchemeFor(%q) = %d, want %d", version, got, want)
		}
	}
}

func TestOnlyANewAgentAcknowledgesTasks(t *testing.T) {
	for version, want := range map[string]bool{"0.46.0": false, "0.47.0": true, "1.2.0-1": true, "": false} {
		if got := AcknowledgesTasks(version); got != want {
			t.Errorf("AcknowledgesTasks(%q) = %v, want %v", version, got, want)
		}
	}
}

// TestTheAnnouncedRangeDecidesBeforeTheTable: an agent that says what it
// speaks is judged by the overlap of the ranges, not by the release table.
func TestTheAnnouncedRangeDecidesBeforeTheTable(t *testing.T) {
	// The panel of the test speaks protocols 1 to 2.
	check := func(version string, min, max int) error {
		return checkProtocolRange(testTable, 1, 2, version, min, max)
	}
	compatible := []struct {
		version  string
		min, max int
	}{
		{"0.41.0", 1, 1},
		{"0.50.0", 1, 2},
		{"9.9.9", 2, 3},
		{"devel", 1, 1},
		{"", 2, 2},
	}
	for _, c := range compatible {
		if err := check(c.version, c.min, c.max); err != nil {
			t.Errorf("%q announcing %d..%d was refused: %v", c.version, c.min, c.max, err)
		}
	}
	incompatible := []struct {
		version  string
		min, max int
	}{
		{"9.9.9", 3, 4},
		{"0.41.0", 3, 3},
		{"0.41.0", 2, 1},
		{"0.41.0", 0, 1},
	}
	for _, c := range incompatible {
		if err := check(c.version, c.min, c.max); !errors.Is(err, ErrProtocolIncompatible) {
			t.Errorf("%q announcing %d..%d was not refused as incompatible: %v", c.version, c.min, c.max, err)
		}
	}

	// Nothing announced: the table decides, with the same answers as
	// CheckProtocol, an unreadable version included.
	if err := check("0.41.0", 0, 0); err != nil {
		t.Errorf("a release the table knows was refused without an announcement: %v", err)
	}
	if err := check("0.50.0", 0, 0); errors.Is(err, ErrProtocolIncompatible) {
		t.Errorf("a release on protocol 2 was refused by a panel speaking up to 2: %v", err)
	}
	if err := checkProtocolRange(testTable, 1, 1, "0.50.0", 0, 0); !errors.Is(err, ErrProtocolIncompatible) {
		t.Errorf("a release on protocol 2 was not refused by a panel speaking up to 1: %v", err)
	}
	if err := check("devel", 0, 0); err == nil || errors.Is(err, ErrProtocolIncompatible) {
		t.Errorf("an unreadable version without an announcement is unknown, not incompatible: %v", err)
	}
}

// TestTheRealRangeIsConsistent: the floor is not above the ceiling, and
// this binary accepts its own announcement.
func TestTheRealRangeIsConsistent(t *testing.T) {
	if AgentProtocolMin < 1 || AgentProtocolMin > AgentProtocol {
		t.Fatalf("the protocol range %d..%d is not a range", AgentProtocolMin, AgentProtocol)
	}
	if err := CheckProtocolRange(Version, AgentProtocolMin, AgentProtocol); err != nil {
		t.Fatalf("this binary's own range is refused: %v", err)
	}
}

func TestOnlyANewAgentReportsItsBuild(t *testing.T) {
	for version, want := range map[string]bool{"0.46.9": false, "0.47.0": true, "0.47.0-1": true, "1.0.0": true, "": false, "test": false} {
		if got := ReportsBuild(version); got != want {
			t.Errorf("ReportsBuild(%q) = %v, want %v", version, got, want)
		}
	}
}
