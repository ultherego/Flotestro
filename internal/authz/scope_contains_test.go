package authz

import "testing"

// Contains is the question a grant asks: is this scope at least as wide as the
// one somebody is handing out? It is answered category by category, on what the
// binding reaches rather than on columns that look alike.
func TestContainsComparesEveryCategory(t *testing.T) {
	team := "1e83b0e4-0000-4000-8000-00000000000a"
	other := "1e83b0e4-0000-4000-8000-00000000000b"
	for _, test := range []struct {
		name  string
		wide  Scope
		nrrow Scope
		want  bool
	}{
		{"everything contains a site", GlobalScope, Placement("lab", "test"), true},
		{"a site does not contain every site", Placement("lab", "test"), GlobalScope, false},
		{"a site contains itself", Placement("lab", "test"), Placement("lab", "test"), true},
		{"a site is not another site", Placement("lab", "test"), Placement("dc1", "test"), false},
		{"any team contains one team", GlobalScope, OfTeam(team), true},
		{"one team does not contain any team", OfTeam(team), GlobalScope, false},
		{"one team is not another team", OfTeam(team), OfTeam(other), false},
		{
			name:  "every owner contains one owner",
			wide:  Placement("lab", "test"),
			nrrow: Scope{Site: "lab", Environment: "test", TeamAny: true, Owners: []string{"alice"}, Tags: []string{Wildcard}},
			want:  true,
		},
		{
			name:  "one owner does not contain every owner",
			wide:  Scope{Site: "lab", Environment: "test", TeamAny: true, Owners: []string{"alice"}, Tags: []string{Wildcard}},
			nrrow: Placement("lab", "test"),
			want:  false,
		},
		{
			name:  "a listed tag is contained, an unlisted one is not",
			wide:  Scope{Site: Wildcard, Environment: Wildcard, TeamAny: true, Owners: []string{Wildcard}, Tags: []string{"db", "web"}},
			nrrow: Scope{Site: Wildcard, Environment: Wildcard, TeamAny: true, Owners: []string{Wildcard}, Tags: []string{"db"}},
			want:  true,
		},
		{
			name:  "a tag outside the list is not contained",
			wide:  Scope{Site: Wildcard, Environment: Wildcard, TeamAny: true, Owners: []string{Wildcard}, Tags: []string{"db"}},
			nrrow: Scope{Site: Wildcard, Environment: Wildcard, TeamAny: true, Owners: []string{Wildcard}, Tags: []string{"db", "web"}},
			want:  false,
		},
		{
			// A category nobody filled in reaches nothing, so it is contained by
			// anything - the safe way round, and the reason an empty field never
			// widens a grant.
			name:  "a category that reaches nothing is contained",
			wide:  Placement("lab", "test"),
			nrrow: Scope{Site: "lab", Environment: "test", TeamAny: true},
			want:  true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := test.wide.Contains(test.nrrow); got != test.want {
				t.Errorf("%s contains %s = %v, expected %v",
					test.wide.String(), test.nrrow.String(), got, test.want)
			}
		})
	}
}

// Whatever a scope contains, it also lets through: a target the narrower binding
// authorises has to be one the wider binding authorises too.
func TestContainsAgreesWithMatches(t *testing.T) {
	team := "1e83b0e4-0000-4000-8000-00000000000a"
	scopes := []Scope{
		GlobalScope,
		Placement("lab", Wildcard),
		Placement("lab", "test"),
		OfTeam(team),
		{Site: "lab", Environment: "test", TeamAny: true, Owners: []string{"alice"}, Tags: []string{Wildcard}},
		{Site: Wildcard, Environment: Wildcard, TeamAny: true, Owners: []string{Wildcard}, Tags: []string{"db"}},
	}
	targets := []Scope{
		TargetOf("lab", "test", team, "alice", []string{"db"}),
		TargetOf("lab", "prod", team, "bob", []string{"web"}),
		TargetOf("dc1", "test", "", "", nil),
		TargetOf("lab", "test", "", "alice", []string{"db", "web"}),
	}
	for _, wide := range scopes {
		for _, narrow := range scopes {
			if !wide.Contains(narrow) {
				continue
			}
			for _, target := range targets {
				if narrow.Matches(target) && !wide.Matches(target) {
					t.Errorf("%s contains %s, yet only the narrower one reaches %s",
						wide.String(), narrow.String(), target.String())
				}
			}
		}
	}
}
