package hosts

import (
	"testing"

	"github.com/ultherego/flotestro/internal/authz"
)

// The coverage of a module is the arithmetic a fleet screen rests on, so it is
// checked here rather than through a screen: a host nobody has heard from must
// never fall out of the sum, because that is exactly the host a plausible

func TestModuleCoverageCountsEveryHostOnce(t *testing.T) {
	coverage := ModuleCoverage{Hosts: 1000, Observed: 700, Unavailable: 40, Stale: 100}
	if got := coverage.Missing(); got != 260 {
		t.Errorf("missing = %d, expected 260", got)
	}
	if got := coverage.Evaluated(); got != 600 {
		t.Errorf("evaluated = %d, expected 600", got)
	}
	if got := coverage.Unknown(); got != 400 {
		t.Errorf("unknown = %d, expected 400", got)
	}
	if coverage.Evaluated()+coverage.Unknown() != coverage.Hosts {
		t.Errorf("%d judged and %d unknown do not add up to %d hosts",
			coverage.Evaluated(), coverage.Unknown(), coverage.Hosts)
	}
}

// A fleet nobody has reported anything about is a fleet of unknown hosts,
// not a fleet of clean ones.
func TestModuleCoverageWithoutAnyFragment(t *testing.T) {
	coverage := ModuleCoverage{Hosts: 1001}
	if coverage.Evaluated() != 0 || coverage.Unknown() != 1001 {
		t.Errorf("evaluated = %d, unknown = %d; expected 0 and 1001",
			coverage.Evaluated(), coverage.Unknown())
	}
}

// The counts come from a left join, so a fragment of a host outside the scope
// could in principle outnumber the hosts.
func TestModuleCoverageNeverReportsNegativeMissing(t *testing.T) {
	coverage := ModuleCoverage{Hosts: 3, Observed: 3, Unavailable: 2}
	if got := coverage.Missing(); got != 0 {
		t.Errorf("missing = %d, expected 0", got)
	}
}

func TestScopeConditionNarrowsOrRefuses(t *testing.T) {
	for _, test := range []struct {
		name   string
		scopes []authz.Scope
		want   string
		args   int
	}{
		{
			name: "no scope sees no host",
			want: "false",
		},
		{
			name:   "a global scope lifts the condition",
			scopes: []authz.Scope{{Site: authz.Wildcard, Environment: authz.Wildcard}},
			want:   "true",
		},
		{
			name:   "a site scope compares the columns it was given",
			scopes: []authz.Scope{{Site: "lab", Environment: "test"}},
			want:   "((h.site = $1 and h.environment = $2))",
			args:   2,
		},
		{
			// The case the count must not read as the whole fleet: a team binding
			// carries the wildcard site and environment, so only the team column may
			// answer for it.
			name:   "a team scope compares the team column alone",
			scopes: []authz.Scope{{Site: authz.Wildcard, Environment: authz.Wildcard, Team: "1e83"}},
			want:   "(h.team_id = $1::uuid)",
			args:   1,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			condition, args := ScopeCondition(test.scopes, "h.site", "h.environment", "h.team_id", 0)
			if condition != test.want {
				t.Errorf("condition = %q, expected %q", condition, test.want)
			}
			if len(args) != test.args {
				t.Errorf("%d arguments, expected %d", len(args), test.args)
			}
		})
	}
}

// The offset is where the caller's own parameters end, so a condition
// concatenated after them numbers its placeholders from there.
func TestScopeConditionNumbersAfterTheOffset(t *testing.T) {
	condition, args := ScopeCondition([]authz.Scope{{Site: "lab", Environment: authz.Wildcard}},
		"h.site", "h.environment", "h.team_id", 4)
	if condition != "((h.site = $5))" {
		t.Errorf("condition = %q", condition)
	}
	if len(args) != 1 || args[0] != "lab" {
		t.Errorf("arguments = %v", args)
	}
}
