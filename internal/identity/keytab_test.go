package identity

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ultherego/flotestro/internal/freeipa"
	"github.com/ultherego/flotestro/internal/hosts"
)

// A keytab rotation is a known change of access with a permission of its own -
// the architecture document's "keytab rotation per separate permission" - and
// its payload names a service principal, never the host's own.
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
// principal the directory does not know or a host that could not fetch the new
// keytab - before the approval, not after the retirement.
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

// The execution keeps the safe order: the host is checked before the keytab is
// retired, so a host that could not fetch a new one leaves the old one in
// place; once retired, the renewal is ordered on that host.
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

// fakeHostTable stands in for the panel's host table: the search matches a
// substring of the hostname, the way the store's filter does.
type fakeHostTable struct{ rows []hosts.Host }

func (f *fakeHostTable) List(_ context.Context, filter hosts.ListFilter) ([]hosts.Host, error) {
	var listed []hosts.Host
	for _, row := range f.rows {
		if filter.Search == "" || strings.Contains(strings.ToLower(row.Hostname), strings.ToLower(filter.Search)) {
			listed = append(listed, row)
		}
	}
	return listed, nil
}

// boundFleet is the real binding over a fake host table, with the ordering
// replaced: the identifiers it records are the ones the resolution reached.
type boundFleet struct {
	*FleetOrderer
	ordered []string
}

func (b *boundFleet) OrderKeytabRenewal(_ context.Context, host FleetHost, _ string, _ Change) (string, error) {
	b.ordered = append(b.ordered, host.ID)
	return "job-" + host.ID, nil
}

// labFleetTable is the discrepancy the binding exists for: the directory holds
// fully qualified names, the panel stores agent-debian short, and beside it a
// name that is carried twice and a host on its way out of the fleet.
func labFleetTable() *fakeHostTable {
	return &fakeHostTable{rows: []hosts.Host{
		{ID: "h-debian", Hostname: "agent-debian", OSFamily: "debian",
			LifecycleState: hosts.StateActive, ConnectionState: "online"},
		{ID: "h-arch-short", Hostname: "agent-arch", OSFamily: "arch",
			LifecycleState: hosts.StateActive, ConnectionState: "online"},
		{ID: "h-arch-full", Hostname: "agent-arch.flotestro.test", OSFamily: "arch",
			LifecycleState: hosts.StateActive, ConnectionState: "online"},
		{ID: "h-suse", Hostname: "agent-suse", OSFamily: "suse",
			LifecycleState: hosts.StateRetired, ConnectionState: "online"},
		{ID: "h-elsewhere", Hostname: "agent-elsewhere", OSFamily: "debian",
			LifecycleState: hosts.StateActive, ConnectionState: "online",
			Identity: hosts.HostIdentity{Domain: "other.test"}},
	}}
}

// labServiceDirectory holds one service per case, each on a fully qualified
// host as FreeIPA keeps it.
func labServiceDirectory() *fakeDirectory {
	keytab := true
	directory := labDirectory()
	directory.services = []freeipa.Service{
		{Principal: "HTTP/agent-debian.flotestro.test@FLOTESTRO.TEST", Service: "HTTP",
			Host: "agent-debian.flotestro.test", HasKeytab: &keytab,
			ManagedBy: []string{"agent-debian.flotestro.test"}},
		{Principal: "ldap/agent-arch.flotestro.test@FLOTESTRO.TEST", Service: "ldap",
			Host: "agent-arch.flotestro.test", HasKeytab: &keytab,
			ManagedBy: []string{"agent-arch.flotestro.test"}},
		{Principal: "nfs/stranger.flotestro.test@FLOTESTRO.TEST", Service: "nfs",
			Host: "stranger.flotestro.test", HasKeytab: &keytab,
			ManagedBy: []string{"stranger.flotestro.test"}},
		{Principal: "HTTP/agent-suse.flotestro.test@FLOTESTRO.TEST", Service: "HTTP",
			Host: "agent-suse.flotestro.test", HasKeytab: &keytab,
			ManagedBy: []string{"agent-suse.flotestro.test"}},
	}
	return directory
}

// The name the directory holds is fully qualified and the panel stores the host
// short: the binding meets them, and both outcomes that are not a single host
// stay unresolved and are told apart by the caller.
func TestFleetBindingResolvesAShortHostnameAndRefusesTheRest(t *testing.T) {
	fleet := &FleetOrderer{hosts: labFleetTable()}

	host, err := fleet.FleetHost(context.Background(), "agent-debian.flotestro.test")
	if err != nil {
		t.Fatalf("the host the panel stores short: %v", err)
	}
	if host.ID != "h-debian" || host.Hostname != "agent-debian" || !host.Online {
		t.Errorf("bound to %+v", host)
	}

	// No match and an ambiguous match are both unresolved, and neither is the
	// other: the caller has to be able to say which one it met.
	if _, err := fleet.FleetHost(context.Background(), "stranger.flotestro.test"); !errors.Is(err, ErrHostNotInFleet) ||
		errors.Is(err, ErrFleetHostAmbiguous) {
		t.Errorf("a name no host carries: %v", err)
	}
	_, err = fleet.FleetHost(context.Background(), "agent-arch.flotestro.test")
	if !errors.Is(err, ErrFleetHostAmbiguous) || errors.Is(err, ErrHostNotInFleet) {
		t.Errorf("a name two hosts carry: %v", err)
	}
	if !strings.Contains(err.Error(), "h-arch-short") || !strings.Contains(err.Error(), "h-arch-full") {
		t.Errorf("the refusal does not name the hosts it could not choose between: %v", err)
	}

	// The safeguard sits after the binding: a host on its way out is refused as
	// itself, not as a name nobody carries.
	_, err = fleet.FleetHost(context.Background(), "agent-suse.flotestro.test")
	if !errors.Is(err, ErrHostNotInFleet) || !strings.Contains(err.Error(), "agent-suse") ||
		!strings.Contains(err.Error(), hosts.StateRetired) {
		t.Errorf("a retired host: %v", err)
	}

	// A short name is a candidate, not a certainty: without a domain to qualify
	// it with, it matches nothing the directory holds.
	listed := labFleetTable().rows
	if _, err := ResolveFleetHost(listed, "agent-debian.flotestro.test", ""); !errors.Is(err, ErrHostNotInFleet) {
		t.Errorf("a short name matched without a domain: %v", err)
	}
	// A host that reported its own domain answers under that domain alone.
	if _, err := ResolveFleetHost(listed, "agent-elsewhere.flotestro.test", "flotestro.test"); !errors.Is(err, ErrHostNotInFleet) {
		t.Errorf("a host of another domain matched: %v", err)
	}
	elsewhere, err := ResolveFleetHost(listed, "agent-elsewhere.other.test", "flotestro.test")
	if err != nil || elsewhere.ID != "h-elsewhere" {
		t.Errorf("the host of another domain does not bind under its own: %+v %v", elsewhere, err)
	}
}

// The owner's criterion: the plan and the execution route the renewal to one
// and the same identifier, and neither of them guesses.
func TestKeytabRotationPlanAndExecutionReachTheSameHostID(t *testing.T) {
	table := labFleetTable()
	fleet := &boundFleet{FleetOrderer: &FleetOrderer{hosts: table}}
	planner := NewPlanner(labServiceDirectory()).WithFleet(fleet)
	spec := &KeytabPayload{Principal: "HTTP/agent-debian.flotestro.test"}

	plan, err := planner.Build(context.Background(), ActionKeytabRotate, Payload{Keytab: spec})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if plan.Blocked() {
		t.Fatalf("the rotation of a host stored short is blocked: %v", plan.Conflicts)
	}
	if plan.FleetHostID != "h-debian" {
		t.Fatalf("the plan names the fleet host %q", plan.FleetHostID)
	}
	// The plan the second person approved is the plan the execution is bound to.
	approved, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	change := Change{ID: "c1", Plan: approved, ApprovedBy: "approver", CreatedBy: "admin"}

	var retired []string
	executor := &Executor{fleet: fleet, retire: func(_ context.Context, principal string) error {
		retired = append(retired, principal)
		return nil
	}}
	phases := executor.rotateKeytab(context.Background(), change, spec)
	if StateFor(phases) != StateSucceeded || len(phases) != 3 {
		t.Fatalf("phases = %+v", phases)
	}
	if len(fleet.ordered) != 1 || fleet.ordered[0] != plan.FleetHostID {
		t.Fatalf("the plan routed to %q and the execution to %v", plan.FleetHostID, fleet.ordered)
	}
	if len(retired) != 1 || !strings.Contains(phases[2].Message, "job-"+plan.FleetHostID) {
		t.Errorf("retired %v, ordering phase %q", retired, phases[2].Message)
	}

	// A plan that named another host is not carried out: the fleet moved under
	// it, and the renewal would go to a host nobody approved.
	moved, err := json.Marshal(Plan{Steps: plan.Steps, FleetHostID: "h-somebody-else"})
	if err != nil {
		t.Fatal(err)
	}
	phases = executor.rotateKeytab(context.Background(), Change{ID: "c2", Plan: moved}, spec)
	if StateFor(phases) != StateFailed || len(phases) != 1 || !strings.Contains(phases[0].Message, "not retired") {
		t.Errorf("a plan that named another host: %+v", phases)
	}
	if len(retired) != 1 {
		t.Errorf("a refused rotation retired a keytab: %v", retired)
	}
}

// A name that resolves to no host and one that resolves to two are refused by
// name, before the approval and again before the keytab is retired.
func TestKeytabRotationRefusesAnUnresolvedBindingByName(t *testing.T) {
	table := labFleetTable()
	fleet := &boundFleet{FleetOrderer: &FleetOrderer{hosts: table}}
	planner := NewPlanner(labServiceDirectory()).WithFleet(fleet)
	executor := &Executor{fleet: fleet, retire: func(_ context.Context, principal string) error {
		t.Errorf("the keytab of %s was retired without a host to renew it", principal)
		return nil
	}}

	for name, expected := range map[string]struct{ principal, said string }{
		"no match":        {"nfs/stranger.flotestro.test", "not a host of this fleet"},
		"ambiguous match": {"ldap/agent-arch.flotestro.test", "more than one host of the fleet"},
	} {
		plan, err := planner.Build(context.Background(), ActionKeytabRotate,
			Payload{Keytab: &KeytabPayload{Principal: expected.principal}})
		if err != nil {
			t.Fatalf("%s: Build: %v", name, err)
		}
		if !plan.Blocked() || !strings.Contains(strings.Join(plan.Conflicts, "\n"), expected.said) {
			t.Errorf("%s: the conflicts are %v", name, plan.Conflicts)
		}
		if plan.FleetHostID != "" {
			t.Errorf("%s: the plan names the host %q; an unresolved binding stays absent", name, plan.FleetHostID)
		}
		phases := executor.rotateKeytab(context.Background(), Change{ID: "c1"},
			&KeytabPayload{Principal: expected.principal})
		if StateFor(phases) != StateFailed || len(phases) != 1 {
			t.Fatalf("%s: phases = %+v", name, phases)
		}
		if !strings.Contains(phases[0].Message, "not retired") {
			t.Errorf("%s: the refusal does not say the keytab stays: %q", name, phases[0].Message)
		}
	}
	if len(fleet.ordered) != 0 {
		t.Errorf("an unresolved binding ordered a renewal: %v", fleet.ordered)
	}
}
