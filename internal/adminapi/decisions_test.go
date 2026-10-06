package adminapi

import (
	"strings"
	"testing"
)

// The badge has to count what the list it leads to shows. The lists add their
// visibility clause only when the principal's scopes narrow something, and the
// counter used to turn "nothing to narrow" into
//
//	exists (select 1 from campaign_targets ... and true)
//
// which narrows after all: a campaign that has not been planned yet has no
// target row, and 28 of the 30 campaigns awaiting approval in the laboratory
// were therefore left out of a badge that said 2.
func TestNothingToNarrowAddsNoClause(t *testing.T) {
	if clause := narrowByHost("", "select 1 from hosts h where h.id = j.host_id"); clause != "" {
		t.Errorf("an unrestricted principal is narrowed by %q", clause)
	}
	clause := narrowByHost("h.site = $1", "select 1 from hosts h where h.id = j.host_id")
	if !strings.HasPrefix(clause, " and exists (") || !strings.HasSuffix(clause, ")") {
		t.Errorf("a restricted principal gets %q, which is not an existence test", clause)
	}
	if !strings.Contains(clause, "h.site = $1") {
		t.Errorf("the clause lost the condition it was given: %q", clause)
	}
	if strings.Contains(clause, "and true") {
		t.Errorf("the clause carries a condition that restricts nothing: %q", clause)
	}
}
