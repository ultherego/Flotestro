package helpercap

import (
	"strings"
	"testing"
)

// Three of the lists a capability binds are sequences, not sets: the argv of a
// scheduled command, the resolvers a host asks in turn, and the domains it
// appends in turn. Comparing them as sets let a request reorder what the panel
// had signed - the first resolver is the one that answers, the first search
// domain is the one that is tried, and the order of an argv is the command.
func TestOrderIsBoundWhereOrderIsMeaning(t *testing.T) {
	for _, what := range []string{"schedule command", "resolvers", "search domains"} {
		signed := []string{"first", "second"}
		reordered := []string{"second", "first"}

		if err := sameSequence(what, signed, signed); err != nil {
			t.Errorf("%s: the same sequence was refused: %v", what, err)
		}
		err := sameSequence(what, reordered, signed)
		if err == nil {
			t.Fatalf("%s: a reordered request satisfied a capability signed for another order", what)
		}
		if !strings.Contains(err.Error(), "another order") {
			t.Errorf("%s: the refusal does not say what is wrong: %v", what, err)
		}
		// And the set comparison, which is right for packages and images, would
		// have let it through - which is the defect this closes.
		if err := sameList(what, reordered, signed); err != nil {
			t.Errorf("%s: sameList was expected to accept the reordering: %v", what, err)
		}
	}
}
