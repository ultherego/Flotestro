//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"
)

// Team scopes: the boundary the security document allows a role binding
// to be drawn on.
//
// The gap this test reproduces negatively is a scope leak. Before teams,
// a binding could only name a site, so an operator of one group of
// machines was given a whole site - or the work was done by somebody who
// has everything. A team binding narrows that, and it is worth nothing
// unless the narrowing holds in every direction at once: the fleet list
// must show exactly the team's hosts, a direct read of another team's
// host must be refused, a host nobody placed must be refused as well, and
// all three must follow a host that changes hands. The test therefore
// checks the list and the single reads against each other - a list that
// showed more than the reads allow would be the leak itself.

// teamView is a team as the register returns it.
type teamView struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Hosts       int    `json:"hosts"`
}

// teamHostRow is the part of a host this test reads: the team it belongs
// to, by identifier and by name.
type teamHostRow struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
	TeamID   string `json:"team_id"`
	TeamName string `json:"team_name"`
}

// createTeam adds a team to the register and removes it again when the
// test ends, whatever the test found.
func (h *harness) createTeam(t *testing.T, name string) teamView {
	t.Helper()
	var team teamView
	h.do(http.MethodPost, "/api/v1/teams", map[string]any{
		"name":        name,
		"description": "created by the team scope integration test",
		"reason":      "integration test of the team boundary",
	}, &team, http.StatusCreated)
	if team.ID == "" {
		t.Fatalf("the register returned a team without an identifier: %+v", team)
	}
	t.Cleanup(func() {
		// The team may already be gone; the test deletes one on purpose.
		h.do(http.MethodDelete,
			"/api/v1/teams/"+team.ID+"?reason=integration+test+finished", nil, nil, 0)
	})
	return team
}

// placeInTeam puts a host into a team or, with an empty team, takes it
// out, and expects the given status.
func (h *harness) placeInTeam(t *testing.T, hostID, teamID string, wantStatus int) {
	t.Helper()
	h.do(http.MethodPut, "/api/v1/hosts/"+hostID+"/team", map[string]any{
		"team": teamID, "reason": "integration test of the team boundary",
	}, nil, wantStatus)
}

// teamBoundPrincipal creates an identity whose only access is one role
// over one team, and returns its token. Its whole world is that team.
func (h *harness) teamBoundPrincipal(t *testing.T, subject, role, teamID string) (string, string) {
	t.Helper()
	var created struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}
	h.do(http.MethodPost, "/api/v1/principals", map[string]any{
		"subject":     subject,
		"roles":       []map[string]string{},
		"issue_token": true,
		"reason":      "identity prepared for the team scope integration test",
	}, &created, http.StatusCreated)
	if created.ID == "" || created.Token == "" {
		t.Fatalf("the identity %s was created without an identifier or a token", subject)
	}
	t.Cleanup(func() {
		h.do(http.MethodDelete,
			"/api/v1/principals/"+created.ID+"?reason=integration+test+finished", nil, nil, 0)
	})
	h.do(http.MethodPost, "/api/v1/principals/"+created.ID+"/team-roles", map[string]any{
		"role": role, "team": teamID,
		"reason": "integration test of the team boundary",
	}, nil, http.StatusCreated)
	return created.ID, created.Token
}

// visibleHostIDs is the set of hosts the fleet list shows this caller.
func visibleHostIDs(t *testing.T, h *harness) map[string]string {
	t.Helper()
	var page struct {
		Items []teamHostRow `json:"items"`
	}
	h.get("/api/v1/hosts?limit=500", &page)
	seen := map[string]string{}
	for _, item := range page.Items {
		seen[item.ID] = item.Hostname
	}
	return seen
}

// TestTeamScopeBoundsTheFleet is the whole boundary in one run: a
// principal bound only to a team sees and touches that team's hosts and
// nothing else, the boundary follows a host between teams, and deleting
// the team leaves the hosts standing and takes the access away.
func TestTeamScopeBoundsTheFleet(t *testing.T) {
	h := newHarness(t)
	fleet := h.hosts()
	if len(fleet) < 3 {
		t.Skipf("the boundary needs three hosts to tell apart; the fleet has %d", len(fleet))
	}
	mine, theirs, nobodys := fleet[0], fleet[1], fleet[2]

	stamp := time.Now().UnixNano()
	teamMine := h.createTeam(t, fmt.Sprintf("integration-team-mine-%d", stamp))
	teamTheirs := h.createTeam(t, fmt.Sprintf("integration-team-theirs-%d", stamp))

	// Every host goes back to having no team, which is where the
	// migration leaves an existing installation.
	t.Cleanup(func() {
		for _, host := range []hostView{mine, theirs, nobodys} {
			h.do(http.MethodPut, "/api/v1/hosts/"+host.ID+"/team", map[string]any{
				"team": "", "reason": "integration test finished",
			}, nil, 0)
		}
	})
	h.placeInTeam(t, mine.ID, teamMine.ID, http.StatusOK)
	h.placeInTeam(t, theirs.ID, teamTheirs.ID, http.StatusOK)
	h.placeInTeam(t, nobodys.ID, "", http.StatusOK)

	// The host carries its team by identifier and by name, because every
	// screen that shows a host shows names.
	var placed teamHostRow
	h.get("/api/v1/hosts/"+mine.ID, &placed)
	if placed.TeamID != teamMine.ID || placed.TeamName != teamMine.Name {
		t.Fatalf("the host reads back in team %q/%q, expected %q/%q",
			placed.TeamID, placed.TeamName, teamMine.ID, teamMine.Name)
	}

	// The move is its own decision and its own line in the trail.
	var trail auditPage
	h.get("/api/v1/audit?target_id="+mine.ID+"&action=host.scope.write&limit=10", &trail)
	if len(trail.Items) == 0 {
		t.Error("putting a host into a team left no host.scope.write event")
	}

	_, token := h.teamBoundPrincipal(t,
		fmt.Sprintf("integration-team-operator-%d", stamp), "operator", teamMine.ID)
	scoped := h.withToken(token)

	// The list is exactly the team, and nothing else. This is the check
	// the leak would fail: a binding whose site and environment are the
	// wildcards its constraint gives it, read with the site columns
	// alone, would show the whole fleet here.
	visible := visibleHostIDs(t, scoped)
	if _, ok := visible[mine.ID]; !ok {
		t.Errorf("the team's own host %s is not in the list", mine.Hostname)
	}
	if _, ok := visible[theirs.ID]; ok {
		t.Errorf("the list shows %s, which belongs to another team", theirs.Hostname)
	}
	if _, ok := visible[nobodys.ID]; ok {
		t.Errorf("the list shows %s, which belongs to no team", nobodys.Hostname)
	}
	if len(visible) != 1 {
		t.Errorf("the list shows %d hosts, expected the team's one: %v", len(visible), visible)
	}

	// The single reads agree with the list, in both directions.
	scoped.do(http.MethodGet, "/api/v1/hosts/"+mine.ID, nil, nil, http.StatusOK)
	scoped.do(http.MethodGet, "/api/v1/hosts/"+theirs.ID, nil, nil, http.StatusForbidden)
	scoped.do(http.MethodGet, "/api/v1/hosts/"+nobodys.ID, nil, nil, http.StatusForbidden)

	// Acting follows seeing: the same tags written back are accepted on
	// the team's host and refused on the others.
	var ownTags struct {
		Tags []string `json:"tags"`
	}
	h.get("/api/v1/hosts/"+mine.ID, &ownTags)
	scoped.do(http.MethodPut, "/api/v1/hosts/"+mine.ID+"/tags",
		map[string]any{"tags": ownTags.Tags}, nil, http.StatusOK)
	scoped.do(http.MethodPut, "/api/v1/hosts/"+theirs.ID+"/tags",
		map[string]any{"tags": []string{}}, nil, http.StatusForbidden)
	scoped.do(http.MethodPut, "/api/v1/hosts/"+nobodys.ID+"/tags",
		map[string]any{"tags": []string{}}, nil, http.StatusForbidden)

	// Moving a host between teams is not something an operator of a team
	// may do: it is the one operation that would let them widen their own
	// boundary.
	scoped.do(http.MethodPut, "/api/v1/hosts/"+theirs.ID+"/team", map[string]any{
		"team": teamMine.ID, "reason": "an operator must not widen their own scope",
	}, nil, http.StatusForbidden)

	// A host that changes hands takes the access with it.
	h.placeInTeam(t, mine.ID, teamTheirs.ID, http.StatusOK)
	h.placeInTeam(t, theirs.ID, teamMine.ID, http.StatusOK)
	visible = visibleHostIDs(t, scoped)
	if _, ok := visible[theirs.ID]; !ok {
		t.Errorf("after the move the list does not show %s, which is now in the team", theirs.Hostname)
	}
	if _, ok := visible[mine.ID]; ok {
		t.Errorf("after the move the list still shows %s, which left the team", mine.Hostname)
	}
	scoped.do(http.MethodGet, "/api/v1/hosts/"+mine.ID, nil, nil, http.StatusForbidden)
	scoped.do(http.MethodGet, "/api/v1/hosts/"+theirs.ID, nil, nil, http.StatusOK)

	// Deleting the team leaves the hosts standing and takes the access
	// away. The hosts become unassigned - the column is on delete set
	// null - and the binding that named the team goes with the team.
	var deleted struct {
		Deleted       string        `json:"deleted"`
		ReleasedHosts []teamHostRow `json:"released_hosts"`
	}
	h.do(http.MethodDelete, "/api/v1/teams/"+teamMine.ID+"?reason=the+team+is+dissolved",
		nil, &deleted, http.StatusOK)
	released := false
	for _, host := range deleted.ReleasedHosts {
		if host.ID == theirs.ID {
			released = true
		}
	}
	if !released {
		t.Errorf("deleting the team did not report %s among the released hosts: %+v",
			theirs.Hostname, deleted.ReleasedHosts)
	}
	var survivor teamHostRow
	h.get("/api/v1/hosts/"+theirs.ID, &survivor)
	if survivor.ID != theirs.ID {
		t.Fatalf("the host did not survive the deletion of its team")
	}
	if survivor.TeamID != "" || survivor.TeamName != "" {
		t.Errorf("the released host still reads team %q/%q", survivor.TeamID, survivor.TeamName)
	}
	// The identity has no binding at all now, so the fleet is refused as
	// a whole rather than answered with an empty page: no scope is no
	// host, never every host.
	scoped.do(http.MethodGet, "/api/v1/hosts?limit=500", nil, nil, http.StatusForbidden)
	scoped.do(http.MethodGet, "/api/v1/hosts/"+theirs.ID, nil, nil, http.StatusForbidden)
}

// TestTeamBindingRefusesTwoVocabularies guards the rule that keeps the
// two ways of scoping a binding readable: a binding names a team, or a
// site and an environment, and a request naming both is refused with a
// code of its own rather than silently resolved one way.
func TestTeamBindingRefusesTwoVocabularies(t *testing.T) {
	h := newHarness(t)
	stamp := time.Now().UnixNano()
	team := h.createTeam(t, fmt.Sprintf("integration-team-vocabulary-%d", stamp))

	var created struct {
		ID string `json:"id"`
	}
	h.do(http.MethodPost, "/api/v1/principals", map[string]any{
		"subject":     fmt.Sprintf("integration-team-mixed-%d", stamp),
		"roles":       []map[string]string{},
		"issue_token": false,
		"reason":      "identity prepared for the team scope integration test",
	}, &created, http.StatusCreated)
	t.Cleanup(func() {
		h.do(http.MethodDelete,
			"/api/v1/principals/"+created.ID+"?reason=integration+test+finished", nil, nil, 0)
	})

	path := "/api/v1/principals/" + created.ID + "/team-roles"
	for _, mixed := range []map[string]any{
		{"role": "operator", "team": team.ID, "site": "lab"},
		{"role": "operator", "team": team.ID, "environment": "test"},
	} {
		mixed["reason"] = "a binding may not name both vocabularies"
		response, body := h.request(http.MethodPost, path, mixed, nil)
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("a binding naming a team and a site answered %d; body: %s",
				response.StatusCode, body)
		}
		if !containsCode(body, "scope_conflict") {
			t.Errorf("the refusal does not carry scope_conflict; body: %s", body)
		}
	}

	// A team that does not exist is not a scope either: a binding over it
	// would start granting the moment somebody created a team with that
	// identifier.
	h.do(http.MethodPost, path, map[string]any{
		"role": "operator", "team": "00000000-0000-0000-0000-000000000000",
		"reason": "a binding over a team nobody created",
	}, nil, http.StatusNotFound)

	// And a team named by something that is not an identifier is the
	// request's mistake, not an empty answer.
	h.do(http.MethodPost, path, map[string]any{
		"role": "operator", "team": team.Name,
		"reason": "a team is named by its identifier, not by its name",
	}, nil, http.StatusBadRequest)
}

// containsCode says whether a problem document carries the given code.
func containsCode(body []byte, code string) bool {
	var refusal struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(body, &refusal); err != nil {
		return false
	}
	return refusal.Code == code
}
