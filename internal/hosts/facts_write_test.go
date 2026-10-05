package hosts

import (
	"fmt"
	"strings"
	"testing"
)

// Every write of the hand-recorded facts carries the facts it was decided on.
// Before this the handler read the host, compared the If-Match to what it read
// and then wrote unconditionally: two operators holding one version both
// passed the comparison and both wrote, and the second one's owner, notes or
// tags replaced the first one's without either being told (audit of 6c38561,
// R1).
func TestEveryFactsWriteCarriesTheFactsItWasDecidedOn(t *testing.T) {
	// The condition compares every column the entity tag of a host covers:
	// one of them left out would be a change the write could not see.
	condition := factsUnchanged(3)
	for i, column := range factsColumns {
		want := fmt.Sprintf("coalesce(%s, '') = $%d", column, 3+i)
		if !strings.Contains(condition, want) {
			t.Errorf("the condition does not carry %s: %s", want, condition)
		}
	}
	tags := fmt.Sprintf("coalesce(tags, '{}') = $%d", 3+len(factsColumns))
	if !strings.Contains(condition, tags) {
		t.Errorf("the condition does not compare the tags: %s", condition)
	}

	// The values follow in the order the condition compares them, so the
	// parameters of a write line up with its own clause.
	read := Facts{
		Owner: "platform", ManagementAddress: "10.0.0.9", ManagementAddressSource: "manual",
		FailureDomain: "rack-3", Site: "lab", Environment: "test", Notes: "do not reboot",
		Tags: []string{"db", "primary"},
	}
	args := read.args()
	if len(args) != len(factsColumns)+1 {
		t.Fatalf("the condition compares %d columns and the write carries %d values",
			len(factsColumns)+1, len(args))
	}
	want := []any{"platform", "10.0.0.9", "manual", "rack-3", "lab", "test", "do not reboot"}
	for i := range want {
		if args[i] != want[i] {
			t.Errorf("value %d of the condition is %v, expected %v (column %s)",
				i, args[i], want[i], factsColumns[i])
		}
	}
	if list, ok := args[len(want)].([]string); !ok || len(list) != 2 || list[0] != "db" {
		t.Errorf("the tags are carried as %v", args[len(want)])
	}

	// A host with no tags carries the empty list, not a missing one: the row
	// holds '{}', and a null would compare equal to nothing.
	if FactsOf(&Host{}).Tags == nil {
		t.Error("a host without tags reads as a host whose tags are unknown")
	}
}
