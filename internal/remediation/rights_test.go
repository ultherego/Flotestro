package remediation

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/hosts"
)

// A plan is approved once and its steps run for hours. Each step therefore
// asks again, and the three answers lead three ways: the step starts, the plan
// stops, or the step waits with the reason written on it.

func labHost() *hosts.Host {
	return &hosts.Host{ID: "11111111-0000-4000-8000-000000000001",
		Site: "lab", Environment: "test"}
}

func operatorOfLab() *authz.Principal {
	return &authz.Principal{Subject: "anna", Bindings: []authz.Binding{
		{Role: authz.RoleOperator, Scope: authz.Placement("lab", "test")},
	}}
}

func TestAConfirmedRightStartsTheStep(t *testing.T) {
	verdict := judgeRights("anna", operatorOfLab(), nil, authz.PermUnitRestart,
		hosts.ScopeOf(labHost()), "lab/test")
	if !verdict.held || verdict.unknown {
		t.Fatalf("a held right was judged %+v", verdict)
	}
}

func TestAnUnconfirmedMembershipHoldsTheStepWithAReason(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
	}{
		{"the directory did not answer", authz.ErrGroupsUnavailable},
		{"the sentinel carries the reason", errors.Join(authz.ErrGroupsUnavailable,
			errors.New("the directory is unreachable"))},
		{"the lookup failed", errors.New("the connection to the database was lost")},
	} {
		t.Run(test.name, func(t *testing.T) {
			verdict := judgeRights("anna", nil, test.err, authz.PermUnitRestart,
				hosts.ScopeOf(labHost()), "lab/test")
			if verdict.held {
				t.Fatal("an unanswered question started the step")
			}
			if !verdict.unknown {
				t.Fatal("an unanswered question stopped the plan, as though somebody " +
					"had taken the right away")
			}
			if !strings.Contains(verdict.reason, "anna") {
				t.Fatalf("the reason does not name the identity: %q", verdict.reason)
			}
		})
	}
}

// An unanswered question about the groups does not hold up a step a binding
// granted by hand already carries: a group adds rights, never removes them.
func TestAStepCarriedByADirectBindingDoesNotWait(t *testing.T) {
	err := errors.Join(authz.ErrGroupsUnavailable, errors.New("the directory is unreachable"))
	carried := judgeRights("anna", operatorOfLab(), err, authz.PermUnitRestart,
		hosts.ScopeOf(labHost()), "lab/test")
	if !carried.held || carried.unknown {
		t.Fatalf("a step the direct binding carries was judged %+v", carried)
	}
	elsewhere := judgeRights("anna", operatorOfLab(), err, authz.PermUnitRestart,
		hosts.ScopeOf(&hosts.Host{ID: "22222222-0000-4000-8000-000000000002",
			Site: "dc1", Environment: "prod"}), "dc1/prod")
	if !elsewhere.unknown {
		t.Fatalf("a step that needed the unconfirmed group was judged %+v", elsewhere)
	}
}

func TestARightThatIsGoneStopsThePlan(t *testing.T) {
	// The identity is there and keeps its own binding, but not on this host.
	verdict := judgeRights("anna", operatorOfLab(), nil, authz.PermUnitRestart,
		hosts.ScopeOf(&hosts.Host{ID: "22222222-0000-4000-8000-000000000002",
			Site: "dc1", Environment: "prod"}), "dc1/prod")
	if verdict.held || verdict.unknown {
		t.Fatalf("a withdrawn right was judged %+v", verdict)
	}
	if !strings.Contains(verdict.reason, string(authz.PermUnitRestart)) {
		t.Fatalf("the reason does not name the permission: %q", verdict.reason)
	}
	// An identity that is gone is equally an answer.
	for _, err := range []error{authz.ErrUnauthenticated, authz.ErrNotFound} {
		if gone := judgeRights("anna", nil, err, authz.PermUnitRestart,
			hosts.ScopeOf(labHost()), "lab/test"); gone.held || gone.unknown {
			t.Fatalf("%v was judged %+v", err, gone)
		}
	}
}

// A plan a campaign started records the campaign as its creator, so the
// identity whose rights decide has to be looked up. Where it cannot be, the
// step waits instead of running under nobody's authority.
func TestThePlanOfACampaignIsJudgedUnderTheCampaignsCreator(t *testing.T) {
	plan := Plan{ID: "plan-1", CreatedBy: CampaignCreator("campaign-1")}
	runner := &Runner{}
	subject, verdict := runner.subjectOf(context.Background(), plan)
	if verdict.held || !verdict.unknown {
		t.Fatalf("a campaign plan without a source of creators was judged %+v", verdict)
	}
	if subject != "" {
		t.Fatalf("a subject was named anyway: %q", subject)
	}

	runner.creators = fixedCreator{subject: "anna"}
	subject, verdict = runner.subjectOf(context.Background(), plan)
	if !verdict.held || subject != "anna" {
		t.Fatalf("the campaign's creator came back as %q, %+v", subject, verdict)
	}

	runner.creators = failingCreator{}
	if _, verdict := runner.subjectOf(context.Background(), plan); !verdict.unknown {
		t.Fatalf("a creator that could not be read was judged %+v", verdict)
	}

	// A plan an operator ordered by hand carries its own subject.
	own := Plan{ID: "plan-2", CreatedBy: "bob"}
	if subject, verdict := runner.subjectOf(context.Background(), own); subject != "bob" || !verdict.held {
		t.Fatalf("a hand-ordered plan came back as %q, %+v", subject, verdict)
	}
}

type fixedCreator struct{ subject string }

func (c fixedCreator) CreatorOfCampaign(_ context.Context, _ string) (string, error) {
	return c.subject, nil
}

type failingCreator struct{}

func (failingCreator) CreatorOfCampaign(_ context.Context, _ string) (string, error) {
	return "", errors.New("the campaign is gone")
}
