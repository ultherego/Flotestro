package packages

import (
	"strings"
	"testing"
)

// The set of packages to remove is computed again right before the operation.
// A difference means the host has changed since the plan - and a different set
// would then be removed than the one the operator approved.
func TestTheComparisonOfSetsFindsEveryDifference(t *testing.T) {
	if difference := compareSets([]string{"a", "b"}, []string{"b", "a"}); difference != "" {
		t.Errorf("equal sets were called different: %q", difference)
	}

	difference := compareSets([]string{"a"}, []string{"a", "b"})
	if !strings.Contains(difference, "also cover: b") {
		t.Errorf("an extra package was not found: %q", difference)
	}

	difference = compareSets([]string{"a", "b"}, []string{"a"})
	if !strings.Contains(difference, "no longer subject") {
		t.Errorf("a missing package was not found: %q", difference)
	}

	difference = compareSets([]string{"a", "b"}, []string{"a", "c"})
	if !strings.Contains(difference, "added: c") || !strings.Contains(difference, "dropped: b") {
		t.Errorf("an incomplete description of the difference: %q", difference)
	}
}

// An irreversible operation must not go without a basis: an empty expected set
// means there is no approved plan rather than consent to everything.
func TestAMissingPlanIsADifference(t *testing.T) {
	if compareSets(nil, []string{"a"}) == "" {
		t.Error("a missing plan was treated as a match")
	}
	if compareSets(nil, nil) == "" {
		t.Error("a missing plan with an empty set was treated as a match")
	}
}

// The "Remv" line is the only source of the list of packages to remove. The
// format is stable under LC_ALL=C and does not depend on the language of the
// interface.
func TestParsingARemovalLine(t *testing.T) {
	name, ok := parseAptRemvLine("Remv libfoo [1.0-1]")
	if !ok || name != "libfoo" {
		t.Errorf("name = %q, ok = %v", name, ok)
	}
	for _, line := range []string{
		"Inst libfoo [1.0-1] (1.0-2 Debian:13 [amd64])",
		"Conf libfoo (1.0-2)",
		"",
		"Remv",
	} {
		if _, ok := parseAptRemvLine(line); ok {
			t.Errorf("the line %q was treated as a removal", line)
		}
	}
}
