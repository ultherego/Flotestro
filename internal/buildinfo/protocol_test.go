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
// any release on protocol 1, and refuses one on protocol 2 with its own
// code. The other way round is fine.
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
