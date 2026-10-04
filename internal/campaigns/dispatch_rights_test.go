package campaigns

import (
	"errors"
	"strings"
	"testing"

	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/hosts"
)

// Three answers are possible before a dispatch and the orchestrator does three
// different things with them: it dispatches, it closes the host as out of
// scope, or - when nobody can say - it pauses the campaign with the reason.
// Mixing the last two is the fault this guards: a directory that did not
// answer was writing hosts off as though somebody had judged them.

func hostInScope(site, environment string) *hosts.Host {
	return &hosts.Host{ID: "11111111-0000-4000-8000-000000000001",
		Site: site, Environment: environment}
}

func operatorOf(site, environment string) *authz.Principal {
	return &authz.Principal{Subject: "anna", Bindings: []authz.Binding{
		{Role: authz.RoleOperator, Scope: authz.Placement(site, environment)},
	}}
}

func TestAConfirmedRightAllowsTheDispatch(t *testing.T) {
	principal := operatorOf("lab", "test")
	verdict := judgeLookup("anna", principal, nil)
	if !verdict.Held {
		t.Fatalf("the lookup was judged %+v", verdict)
	}
	verdict = judgePermissions("anna", principal, hosts.ScopeOf(hostInScope("lab", "test")),
		"lab/test", []authz.Permission{authz.PermCampaignCreate, authz.PermUnitRestart})
	if !verdict.Held || verdict.Unknown {
		t.Fatalf("a held right was judged %+v", verdict)
	}
}

func TestAnUnconfirmedGroupMembershipPausesRatherThanClosingTheHost(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
	}{
		{"the directory did not answer", authz.ErrGroupsUnavailable},
		{"the sentinel carries the directory's reason", wrapUnavailable()},
		{"the lookup itself failed", errors.New("the connection to the database was lost")},
	} {
		t.Run(test.name, func(t *testing.T) {
			verdict := judgeLookup("anna", nil, test.err)
			if verdict.Held {
				t.Fatal("an unanswered question was taken for a right that is held")
			}
			if !verdict.Unknown {
				t.Fatal("an unanswered question was taken for a right that is gone, " +
					"which closes the host as out of scope")
			}
			if strings.TrimSpace(verdict.Reason) == "" {
				t.Fatal("the pause carries no reason")
			}
			if !strings.Contains(verdict.Reason, "anna") {
				t.Fatalf("the reason does not name the identity: %q", verdict.Reason)
			}
		})
	}
}

// An identity that is gone is an answer, not a gap: nothing is dispatched
// under its name any more and the host is closed rather than the campaign
// paused.
func TestAnIdentityThatIsGoneIsAnAnswer(t *testing.T) {
	for _, err := range []error{authz.ErrUnauthenticated, authz.ErrNotFound} {
		verdict := judgeLookup("anna", nil, err)
		if verdict.Held || verdict.Unknown {
			t.Fatalf("%v was judged %+v", err, verdict)
		}
	}
	// A lookup that answers with neither an identity nor an error says
	// nothing, and nothing is not an answer.
	if verdict := judgeLookup("anna", nil, nil); !verdict.Unknown {
		t.Fatalf("an empty answer was judged %+v", verdict)
	}
}

// A role that came from a group and was taken away stops the dispatch where
// the group reached, while the bindings granted by hand keep working. The two
// are resolved separately and only the group side follows the directory.
func TestARevokedGroupStopsTheDispatchAndLeavesDirectBindings(t *testing.T) {
	// What the identity has left is one binding granted by hand, on lab/test.
	// The operator role it held globally came from a group that is gone.
	principal := operatorOf("lab", "test")

	own := judgePermissions("anna", principal, hosts.ScopeOf(hostInScope("lab", "test")),
		"lab/test", []authz.Permission{authz.PermCampaignCreate, authz.PermUnitRestart})
	if !own.Held {
		t.Fatalf("the direct binding stopped working: %+v", own)
	}

	elsewhere := judgePermissions("anna", principal, hosts.ScopeOf(hostInScope("dc1", "prod")),
		"dc1/prod", []authz.Permission{authz.PermCampaignCreate, authz.PermUnitRestart})
	if elsewhere.Held {
		t.Fatal("the dispatch went ahead where only the revoked group reached")
	}
	if elsewhere.Unknown {
		t.Fatal("a right that is gone was taken for one nobody could confirm; " +
			"that would pause the campaign instead of closing the host")
	}
	if !strings.Contains(elsewhere.Reason, string(authz.PermCampaignCreate)) {
		t.Fatalf("the reason does not name the missing permission: %q", elsewhere.Reason)
	}
}

// A group can add a right and never take one away. Where the bindings granted
// by hand already carry the operation, an unanswered question about the groups
// changes nothing and the campaign is not paused over it - but where the
// operation needed the group, it is.
func TestAnUnconfirmedMembershipDoesNotPauseWhatDirectBindingsCarry(t *testing.T) {
	principal := operatorOf("lab", "test")
	err := wrapUnavailable()

	carried := judgeRights("anna", principal, err, hosts.ScopeOf(hostInScope("lab", "test")),
		"lab/test", []authz.Permission{authz.PermCampaignCreate, authz.PermUnitRestart})
	if !carried.Held || carried.Unknown {
		t.Fatalf("a dispatch the direct binding carries was judged %+v", carried)
	}

	needed := judgeRights("anna", principal, err, hosts.ScopeOf(hostInScope("dc1", "prod")),
		"dc1/prod", []authz.Permission{authz.PermCampaignCreate, authz.PermUnitRestart})
	if !needed.Unknown {
		t.Fatalf("a dispatch that needed the unconfirmed group was judged %+v", needed)
	}

	// An identity that is gone stays gone whatever it used to hold.
	gone := judgeRights("anna", nil, authz.ErrUnauthenticated,
		hosts.ScopeOf(hostInScope("lab", "test")), "lab/test",
		[]authz.Permission{authz.PermCampaignCreate})
	if gone.Held || gone.Unknown {
		t.Fatalf("a missing identity was judged %+v", gone)
	}
}

// wrapUnavailable builds the error the store returns: the sentinel with the
// reason the directory gave, which must still read as unavailable.
func wrapUnavailable() error {
	return errors.Join(authz.ErrGroupsUnavailable,
		errors.New("the admin API answered 503 Service Unavailable"))
}
