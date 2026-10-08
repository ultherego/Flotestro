package opspec

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// catalogueRow finds one row of the published catalogue: the operation in the
// first cell, and whatever that row links to as its payload.
var catalogueRow = regexp.MustCompile(`<tr><td><a href="#op-[^"]+"><code>([a-z0-9._]+)</code></a></td>(.*?)</tr>`)
var payloadLink = regexp.MustCompile(`href="#payload-([a-z0-9_-]+)"`)

// The reference page names a payload for every operation, in a column written
// by hand, and the validator refuses an operation whose payload group is
// missing. Those are two independent statements of one fact, and nothing
// compared them: a column could name the wrong group for a year, and the only
// person to find out would be whoever wrote an order against it.
//
// They agree today, on every operation where both speak. This keeps them
// agreeing, in both directions: a column that names another group fails, and so
// does a validator taught to want a different one.
func TestThePublishedPayloadColumnAgreesWithTheValidator(t *testing.T) {
	page, err := os.ReadFile(filepath.Join("..", "..", "docs", "site", "docs", "operations.html"))
	if err != nil {
		t.Fatalf("the published reference is not readable, so this guard would check nothing: %v", err)
	}
	manual := map[string]string{}
	for _, row := range catalogueRow.FindAllStringSubmatch(string(page), -1) {
		action, rest := row[1], row[2]
		links := payloadLink.FindAllStringSubmatch(rest, -1)
		if len(links) == 0 {
			continue
		}
		// The anchor spells a group with hyphens; the field spells it with
		// underscores.
		manual[action] = strings.ReplaceAll(links[len(links)-1][1], "-", "_")
	}
	if len(manual) == 0 {
		t.Fatal("no catalogue row was read; the shape of the page has changed and this guard sees nothing")
	}

	compared := 0
	for _, action := range AllActions() {
		derived := PayloadGroup(action)
		if derived == "" {
			// The validator does not require a payload for this operation, so
			// it has nothing to say about which group it reads. The column may
			// still name one, and does for 27 of them.
			continue
		}
		named, ok := manual[string(action)]
		if !ok {
			t.Errorf("the validator proves %s reads the %s payload and the catalogue names none",
				action, derived)
			continue
		}
		compared++
		if named != derived {
			t.Errorf("%s: the catalogue names the %s payload, the validator requires %s",
				action, named, derived)
		}
	}
	if compared == 0 {
		t.Fatal("no operation was compared; either the registry or the page stopped being read")
	}
	t.Logf("%d operations compared between the validator and the published catalogue", compared)
}

// PayloadGroup answers from the shape of Payload, so a group it names has to be
// a group that exists.
func TestEveryDerivedGroupIsAFieldOfPayload(t *testing.T) {
	groups := map[string]bool{}
	for _, name := range PayloadGroups() {
		groups[name] = true
	}
	if len(groups) == 0 {
		t.Fatal("Payload declares no group at all")
	}
	for _, action := range AllActions() {
		group := PayloadGroup(action)
		if group != "" && !groups[group] {
			t.Errorf("%s is said to read the %q payload, which Payload does not declare", action, group)
		}
	}
	// And an operation nobody registered has no group rather than a guess.
	if group := PayloadGroup(ActionType("no.such.operation")); group != "" {
		t.Errorf("an unknown operation was given the %q payload", group)
	}
}
