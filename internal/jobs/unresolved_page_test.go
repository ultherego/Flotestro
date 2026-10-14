package jobs

import (
	"fmt"
	"regexp"
	"strconv"
	"testing"
)

// The paging of the unresolved list, which was a 500 on every page after the
// first.
//
// The defect was arithmetic: the limit's placeholder was numbered after the
// offset had been appended, so both named the offset's parameter and the
// limit's was never referenced. PostgreSQL refuses a statement with an
// unreferenced parameter - "could not determine data type of parameter $1" -
// and that is what an operator pressing 2 at the foot of the table got.
//
// So what is checked here is the property the defect broke: every parameter
// the query is given is named by the query, exactly once, in order.

var placeholder = regexp.MustCompile(`\$(\d+)`)

func TestEveryParameterOfAPageIsNamedByIt(t *testing.T) {
	for _, one := range []struct {
		name          string
		before        []any
		limit, offset int
	}{
		{"the first page of an unnarrowed list", nil, 20, 0},
		{"a later page of an unnarrowed list", nil, 20, 20},
		{"the first page under one narrowing", []any{"scope"}, 5, 0},
		{"a later page under one narrowing", []any{"scope"}, 5, 10},
		{"a later page under three narrowings", []any{"a", "b", "c"}, 100, 400},
	} {
		t.Run(one.name, func(t *testing.T) {
			clause, args := pageClause(one.before, one.limit, one.offset)
			named := map[int]int{}
			for _, match := range placeholder.FindAllStringSubmatch(clause, -1) {
				n, err := strconv.Atoi(match[1])
				if err != nil {
					t.Fatalf("the clause names %q, which is not a parameter", match[0])
				}
				named[n]++
			}
			// The parameters this clause is responsible for are the ones it
			// appended: those before it belong to the conditions.
			for n := len(one.before) + 1; n <= len(args); n++ {
				if named[n] != 1 {
					t.Errorf("parameter $%d is named %d times in %q, want once (args: %v)",
						n, named[n], clause, args)
				}
			}
			// And it names none of anybody else's.
			for n := range named {
				if n <= len(one.before) || n > len(args) {
					t.Errorf("the clause %q names $%d, which is not one of its own", clause, n)
				}
			}
			// The values land in the order the placeholders promise.
			if got := args[len(one.before)]; got != one.limit {
				t.Errorf("the limit's parameter carries %v, want %d", got, one.limit)
			}
			if one.offset > 0 {
				if got := args[len(one.before)+1]; got != one.offset {
					t.Errorf("the offset's parameter carries %v, want %d", got, one.offset)
				}
				if want := fmt.Sprintf(" limit $%d offset $%d", len(one.before)+1, len(one.before)+2); clause != want {
					t.Errorf("the clause is %q, want %q", clause, want)
				}
			} else if len(args) != len(one.before)+1 {
				t.Errorf("a first page took %d parameters beyond the conditions, want one", len(args)-len(one.before))
			}
		})
	}
}

// The search box takes a string to find, not a pattern to run.
//
// Unescaped, LIKE reads _ as any character and % as anything at all, so a
// search for "agent_debian" would also find "agent-debian" and a single % would
// match the whole fleet. Both read as a search that does not work.
func TestTheSearchTakesAStringAndNotAPattern(t *testing.T) {
	for _, one := range []struct{ typed, want string }{
		{"agent-debian", `%agent-debian%`},
		{"  sysctl  ", `%sysctl%`},
		{"", ""},
		{"   ", ""},
		// The wildcards, each escaped once, with the escape character itself
		// escaped too.
		{"agent_debian", `%agent\_debian%`},
		{"100%", `%100\%%`},
		{`a\b`, `%a\\b%`},
		{"%_", `%\%\_%`},
	} {
		if got := searchNeedle(one.typed); got != one.want {
			t.Errorf("searchNeedle(%q) = %q, want %q", one.typed, got, one.want)
		}
	}
}
