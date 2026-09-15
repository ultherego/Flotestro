package identity

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ultherego/flotestro/internal/freeipa"
)

// A keytab rotation is a known change of access with a permission of its
// own - the architecture document's "keytab rotation per separate
// permission" - and its payload names a service principal, never the
// host's own.
func TestKeytabRotationIsAnAccessChangeWithItsOwnPermission(t *testing.T) {
	if !ActionKeytabRotate.Known() || !ActionKeytabRotate.ChangesAccess() {
		t.Error("a keytab rotation is not a known change of access")
	}
	if ActionKeytabRotate.Permission() != "identity.keytab.rotate" {
		t.Errorf("a keytab rotation has the permission %s", ActionKeytabRotate.Permission())
	}
	for _, other := range []ActionType{ActionUserCreate, ActionGroupMembers, ActionHBACRuleEnsure, ActionDNSRecordEnsure} {
		if other.Permission() == ActionKeytabRotate.Permission() {
			t.Errorf("%s shares the rotation's permission", other)
		}
	}
	valid := Payload{Keytab: &KeytabPayload{Principal: "HTTP/web1.flotestro.test@FLOTESTRO.TEST"}}
	if err := Validate(ActionKeytabRotate, valid); err != nil {
		t.Errorf("a valid rotation is refused: %v", err)
	}
	if host := valid.Keytab.Host(); host != "web1.flotestro.test" {
		t.Errorf("the principal names the host %q", host)
	}
	if host := (KeytabPayload{Principal: "nfs/db1.flotestro.test"}).Host(); host != "db1.flotestro.test" {
		t.Errorf("a principal without a realm names the host %q", host)
	}
	for name, payload := range map[string]Payload{
		"no payload":     {},
		"the host's own": {Keytab: &KeytabPayload{Principal: "host/web1.flotestro.test@FLOTESTRO.TEST"}},
		"no host":        {Keytab: &KeytabPayload{Principal: "HTTP"}},
		"a short host":   {Keytab: &KeytabPayload{Principal: "HTTP/web1"}},
		"a shell":        {Keytab: &KeytabPayload{Principal: "HTTP/web1.flotestro.test;id"}},
	} {
		if err := Validate(ActionKeytabRotate, payload); err == nil {
			t.Errorf("%s: the rotation passes", name)
		}
	}
}

// The plan names the two halves and the gap between them, and refuses a
// principal the directory does not know or a host that could not fetch the
// new keytab - before the approval, not after the retirement.
func TestKeytabRotationPlanNamesBothHalvesAndTheGap(t *testing.T) {
	yes, no := true, false
	directory := labDirectory()
	directory.services = []freeipa.Service{
		{Principal: "HTTP/web1.flotestro.test@FLOTESTRO.TEST", Service: "HTTP", Host: "web1.flotestro.test",
			HasKeytab: &yes, ManagedBy: []string{"web1.flotestro.test"}},
		{Principal: "nfs/db1.flotestro.test@FLOTESTRO.TEST", Service: "nfs", Host: "db1.flotestro.test",
			HasKeytab: &no, ManagedBy: []string{"db1.flotestro.test"}},
		{Principal: "ldap/web2.flotestro.test@FLOTESTRO.TEST", Service: "ldap", Host: "web2.flotestro.test",
			HasKeytab: &yes, ManagedBy: []string{"ipa.flotestro.test"}},
	}
	planner := NewPlanner(directory)

	plan, err := planner.Build(context.Background(), ActionKeytabRotate,
		Payload{Keytab: &KeytabPayload{Principal: "HTTP/web1.flotestro.test"}})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Blocked() {
		t.Fatalf("a known principal is blocked: %v", plan.Conflicts)
	}
	if len(plan.Steps) != 2 || !strings.Contains(plan.Steps[0], "retiring") || !strings.Contains(plan.Steps[1], "identity.keytab.renew") {
		t.Errorf("steps = %v", plan.Steps)
	}
	if len(plan.ReachableHosts) != 1 || plan.ReachableHosts[0] != "web1.flotestro.test" {
		t.Errorf("the plan names the hosts %v", plan.ReachableHosts)
	}
	if !strings.Contains(strings.Join(plan.Warnings, "\n"), "cannot authenticate") {
		t.Errorf("the plan does not warn about the gap: %v", plan.Warnings)
	}

	// A principal without a keytab is a first fetch, said so.
	plan, err = planner.Build(context.Background(), ActionKeytabRotate,
		Payload{Keytab: &KeytabPayload{Principal: "nfs/db1.flotestro.test@FLOTESTRO.TEST"}})
	if err != nil || plan.Blocked() {
		t.Fatalf("a principal without a keytab is blocked: %v %v", err, plan.Conflicts)
	}
	if !strings.Contains(strings.Join(plan.Warnings, "\n"), "no keytab") {
		t.Errorf("the plan does not say the principal has no keytab: %v", plan.Warnings)
	}

	// Refusals: unknown principal, a host that does not manage the entry.
	plan, _ = planner.Build(context.Background(), ActionKeytabRotate,
		Payload{Keytab: &KeytabPayload{Principal: "HTTP/web9.flotestro.test"}})
	if !plan.Blocked() {
		t.Error("an unknown principal passes")
	}
	plan, _ = planner.Build(context.Background(), ActionKeytabRotate,
		Payload{Keytab: &KeytabPayload{Principal: "ldap/web2.flotestro.test"}})
	if !plan.Blocked() || !strings.Contains(plan.Conflicts[0], "does not manage") {
		t.Errorf("a host that does not manage the entry passes: %v", plan.Conflicts)
	}
}

// fakeFleet stands in for the panel's host and job tables.
type fakeFleet struct {
	hosts   map[string]FleetHost
	ordered []string
	refuse  error
}

func (f *fakeFleet) FleetHost(_ context.Context, fqdn string) (FleetHost, error) {
	host, ok := f.hosts[strings.ToLower(fqdn)]
	if !ok {
		return FleetHost{}, ErrHostNotInFleet
	}
	return host, nil
}

func (f *fakeFleet) OrderKeytabRenewal(_ context.Context, host FleetHost, principal string, _ Change) (string, error) {
	if f.refuse != nil {
		return "", f.refuse
	}
	f.ordered = append(f.ordered, host.Hostname+" "+principal)
	return "job-" + host.ID, nil
}

// The execution keeps the safe order: the host is checked before the
// keytab is retired, so a host that could not fetch a new one leaves the
// old one in place; once retired, the renewal is ordered on that host.
func TestKeytabRotationRetiresOnlyWithAHostToRenew(t *testing.T) {
	var retired []string
	fleet := &fakeFleet{hosts: map[string]FleetHost{
		"web1.flotestro.test": {ID: "h1", Hostname: "web1.flotestro.test", OSFamily: "fedora", Online: true},
		"web2.flotestro.test": {ID: "h2", Hostname: "web2.flotestro.test", OSFamily: "fedora", Online: false},
	}}
	executor := &Executor{fleet: fleet, retire: func(_ context.Context, principal string) error {
		retired = append(retired, principal)
		return nil
	}}
	change := Change{ID: "c1", ApprovedBy: "approver", CreatedBy: "admin"}

	phases := executor.rotateKeytab(context.Background(), change, &KeytabPayload{Principal: "HTTP/web1.flotestro.test"})
	if StateFor(phases) != StateSucceeded || len(phases) != 3 {
		t.Fatalf("phases = %+v", phases)
	}
	if len(retired) != 1 || retired[0] != "HTTP/web1.flotestro.test" {
		t.Errorf("retired %v", retired)
	}
	if len(fleet.ordered) != 1 || fleet.ordered[0] != "web1.flotestro.test HTTP/web1.flotestro.test" {
		t.Errorf("ordered %v", fleet.ordered)
	}
	if !strings.Contains(phases[2].Message, "job-h1") {
		t.Errorf("the ordering phase does not name the task: %q", phases[2].Message)
	}

	// Not in the fleet, and offline: nothing is retired.
	for name, principal := range map[string]string{
		"not in the fleet": "HTTP/web9.flotestro.test",
		"offline":          "HTTP/web2.flotestro.test",
	} {
		phases := executor.rotateKeytab(context.Background(), change, &KeytabPayload{Principal: principal})
		if StateFor(phases) != StateFailed || len(phases) != 1 {
			t.Errorf("%s: phases = %+v", name, phases)
		}
		if !strings.Contains(phases[0].Message, "not retired") {
			t.Errorf("%s: the refusal does not say the keytab stays: %q", name, phases[0].Message)
		}
	}
	if len(retired) != 1 {
		t.Errorf("a refused rotation retired a keytab: %v", retired)
	}

	// The task could not be placed after the retirement: a partial result
	// that says the renewal has to be ordered by hand.
	fleet.refuse = errors.New("the job store is gone")
	phases = executor.rotateKeytab(context.Background(), change, &KeytabPayload{Principal: "HTTP/web1.flotestro.test"})
	if StateFor(phases) != StatePartiallyApplied {
		t.Errorf("a retirement without a task is %s: %+v", StateFor(phases), phases)
	}
	if !strings.Contains(phases[2].Message, "by hand") {
		t.Errorf("the failure does not tell the operator what to do: %q", phases[2].Message)
	}

	// No fleet at all: refused before the directory is touched.
	phases = (&Executor{}).rotateKeytab(context.Background(), change, &KeytabPayload{Principal: "HTTP/web1.flotestro.test"})
	if StateFor(phases) != StateFailed || len(retired) != 2 {
		t.Errorf("without a fleet: %+v, retired %v", phases, retired)
	}
}
