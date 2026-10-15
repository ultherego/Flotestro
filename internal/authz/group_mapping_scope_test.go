package authz

import (
	"slices"
	"testing"
)

// A mapping narrowed to an owner or a tag has to stay narrowed.
//
// Until 15.10 the API documented owners and tags on a group mapping, accepted
// them on the wire and threw them away: the scope was built with
// Placement(site, environment), which fills both categories with a wildcard.
// So an administrator who narrowed a role to one owner was given a rule that
// reached every owner, and nothing said so. That is a privilege widened in
// silence, which is worse than one refused.
func TestAMappingNarrowedToAnOwnerDoesNotWidenBackOut(t *testing.T) {
	scope := PlacementWithin("lab", "test", []string{"team-a"}, []string{"db"})
	if !slices.Equal(scope.Owners, []string{"team-a"}) {
		t.Errorf("the owners of the scope are %v, want the ones given", scope.Owners)
	}
	if !slices.Equal(scope.Tags, []string{"db"}) {
		t.Errorf("the tags of the scope are %v, want the ones given", scope.Tags)
	}
	if scope.Site != "lab" || scope.Environment != "test" {
		t.Errorf("the placement was lost: %+v", scope)
	}
	// Team stays open: a mapping has never narrowed by team, and an empty
	// category reaches no host, so leaving it unset would grant nothing.
	if !scope.TeamAny {
		t.Error("the team category was closed, which grants nothing at all")
	}
}

// Nothing given means every one of that category - which is what Placement
// has always handed out, and what an older mapping row holds.
func TestAMappingWithNoOwnersGivenReachesEveryOwner(t *testing.T) {
	scope := PlacementWithin("lab", "test", nil, nil)
	if !slices.Equal(scope.Owners, []string{Wildcard}) || !slices.Equal(scope.Tags, []string{Wildcard}) {
		t.Fatalf("nothing given became %v / %v, want the wildcard in both", scope.Owners, scope.Tags)
	}
	// And Placement, which the rest of the product still calls, says the same.
	if plain := Placement("lab", "test"); !slices.Equal(plain.Owners, scope.Owners) ||
		!slices.Equal(plain.Tags, scope.Tags) {
		t.Error("Placement and PlacementWithin disagree about what nothing means")
	}
}

// A list somebody emptied is not a list nobody gave. The first reaches no
// host, and a rule that reaches no host is one somebody will read as granting
// something - so it is refused where it is written, not stored.
func TestAnEmptyCategoryIsNotTheSameAsNoneGiven(t *testing.T) {
	emptied := PlacementWithin("lab", "test", []string{}, nil)
	if len(emptied.Owners) != 0 {
		t.Fatalf("an emptied list became %v; the difference from nothing given was lost", emptied.Owners)
	}
	// orWildcardList keeps that difference, and the store refuses what it
	// returns empty.
	if got := orWildcardList([]string{}); len(got) != 0 {
		t.Errorf("orWildcardList([]) = %v, want it kept empty", got)
	}
	if got := orWildcardList(nil); !slices.Equal(got, []string{Wildcard}) {
		t.Errorf("orWildcardList(nil) = %v, want the wildcard", got)
	}
	// Blank entries are not a narrowing either: a category of one empty
	// string would reach no host while looking like a rule.
	if got := orWildcardList([]string{" ", ""}); len(got) != 0 {
		t.Errorf("orWildcardList of blanks = %v, want nothing kept", got)
	}
}
