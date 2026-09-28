package packages

import (
	"context"
	"encoding/hex"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/plan"
)

// flowPlan completes a plan the way a planner hands one over: the header, the
// direction and the flags of every element, the sorting. The manager is nil
// and the metadata revision is given, so nothing here reads the host.
func flowPlan(p Plan) Plan {
	if p.ResourceRevision == "" {
		p.ResourceRevision = p.Manager + ":fixed-metadata"
	}
	return finishPlan(context.Background(), nil, p, Options{
		Mode: p.Mode,
		Header: PlanHeader{
			HostID: "host-1", InventoryRevision: "inv-1",
			ExpiresAt: time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC),
		},
	})
}

// flowRemovalSpecs spells every removal of the plan the way its manager takes
// an exact version - the counterpart of ExactSpecs, which covers the arrivals.
func flowRemovalSpecs(p Plan) []string {
	var specs []string
	for _, change := range p.Changes {
		if change.Action == ActionRemove {
			specs = append(specs, exactSpec(p.Manager, change))
		}
	}
	sort.Strings(specs)
	return specs
}

// flowStepSpecs lists the specs the envelope carries: what the executor hands
// to the tool, so that the approved plan and the command line are one thing.
func flowStepSpecs(p Plan) []string {
	var specs []string
	for _, step := range p.Envelope().Steps {
		specs = append(specs, step.Spec)
	}
	sort.Strings(specs)
	return specs
}

func flowEqual(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// The transaction runs on the specs of the plan, so every element has to be
// named the way its manager takes an exact version: apt name:arch=version,
// dnf the whole NEVRA, pacman name=version - and a removal exactly as much as
// an arrival, because a bare name is whatever the tool resolves it to.
func TestTheSpecsOfAPlanNameEveryElementExactly(t *testing.T) {
	cases := []struct {
		name     string
		plan     Plan
		arrivals []string
		removals []string
	}{
		{
			name: "apt names the architecture apart from the version",
			plan: Plan{Manager: "apt", Mode: ModeInstall, Changes: []Change{
				{Name: "nginx", CandidateVersion: "1.26.2-1", Architecture: "amd64", Action: ActionInstall},
				{Name: "openssl", CurrentVersion: "3.0.15-1", CandidateVersion: "3.0.16-1",
					Architecture: "amd64", Action: ActionUpgrade},
				// An architecture-independent package is known under its bare name.
				{Name: "ca-certificates", CandidateVersion: "20240203", Architecture: "all", Action: ActionInstall},
				{Name: "old-tool", CurrentVersion: "1.0-3", Action: ActionRemove},
			}},
			arrivals: []string{"ca-certificates=20240203", "nginx:amd64=1.26.2-1", "openssl:amd64=3.0.16-1"},
			removals: []string{"old-tool"},
		},
		{
			// dnf keeps several versions of an installonly package: the removal of
			// the old kernel must name its version, or it takes the new one too.
			name: "dnf names the version of the kernel it takes away",
			plan: Plan{Manager: "dnf", Mode: ModeUpgrade, Changes: []Change{
				{Name: "kernel-core", CandidateVersion: "6.17.4-200.fc42",
					Architecture: "x86_64", Action: ActionInstall},
				{Name: "kernel-core", CurrentVersion: "6.15.2-200.fc42",
					Architecture: "x86_64", Action: ActionRemove},
			}},
			arrivals: []string{"kernel-core-6.17.4-200.fc42.x86_64"},
			removals: []string{"kernel-core-6.15.2-200.fc42.x86_64"},
		},
		{
			name: "pacman names the version of every arrival",
			plan: Plan{Manager: PacmanName, Mode: ModeInstall, Changes: []Change{
				{Name: "ripgrep", CandidateVersion: "14.1.1-1", Architecture: "x86_64", Action: ActionInstall},
				{Name: "obsolete-thing", CurrentVersion: "0.9-1", Action: ActionRemove},
			}},
			arrivals: []string{"ripgrep=14.1.1-1"},
			removals: []string{"obsolete-thing"},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			approved := flowPlan(testCase.plan)
			if specs := approved.ExactSpecs(); !flowEqual(specs, testCase.arrivals) {
				t.Errorf("the arrivals are spelled %v, the transaction takes %v", specs, testCase.arrivals)
			}
			if specs := flowRemovalSpecs(approved); !flowEqual(specs, testCase.removals) {
				t.Errorf("the removals are spelled %v, the transaction takes %v", specs, testCase.removals)
			}
			// What the envelope carries is what the executor hands to the tool:
			// the steps are the arrivals and the removals together, nothing else.
			want := append(append([]string(nil), testCase.arrivals...), testCase.removals...)
			sort.Strings(want)
			if steps := flowStepSpecs(approved); !flowEqual(steps, want) {
				t.Errorf("the steps of the envelope are %v, the specs of the plan are %v", steps, want)
			}
		})
	}
}

// A version cleanup - the old kernel going as the new one arrives - is one
// name in two directions. The removal must not be addressed as the arrival is,
// or it takes away the very version the transaction just installed.
func TestARemovalNeverCollidesWithAnArrivalOfTheSameName(t *testing.T) {
	cases := []struct {
		manager      string
		architecture string
		name         string
	}{
		{manager: "apt", architecture: "amd64", name: "linux-image-generic"},
		{manager: "dnf", architecture: "x86_64", name: "kernel-core"},
		{manager: PacmanName, architecture: "x86_64", name: "linux"},
	}

	for _, testCase := range cases {
		t.Run(testCase.manager, func(t *testing.T) {
			approved := flowPlan(Plan{Manager: testCase.manager, Mode: ModeUpgrade, Changes: []Change{
				{Name: testCase.name, CandidateVersion: "6.17.4", Architecture: testCase.architecture,
					Action: ActionInstall},
				{Name: testCase.name, CurrentVersion: "6.15.2", Architecture: testCase.architecture,
					Action: ActionRemove},
			}})
			arrivals := approved.ExactSpecs()
			removals := flowRemovalSpecs(approved)
			if len(arrivals) != 1 || len(removals) != 1 {
				t.Fatalf("the plan holds %d arrivals and %d removals", len(arrivals), len(removals))
			}
			if removals[0] == arrivals[0] {
				t.Errorf("the removal and the arrival are the same argument %q", removals[0])
			}
			// The old version is what goes; on dnf the spec has to say so, because
			// the bare name would match the version this transaction installed.
			if testCase.manager == "dnf" {
				if removals[0] != testCase.name+"-6.15.2."+testCase.architecture {
					t.Errorf("the removal is addressed as %q, not as the old version", removals[0])
				}
				if removals[0] == testCase.name {
					t.Errorf("the removal is addressed by the bare name %q and would take both versions", removals[0])
				}
			}
			// The package comes back at the new version, so the plan is not the
			// removal of a protected package and nothing refuses it.
			if len(approved.Protected) != 0 {
				t.Errorf("a version cleanup was counted as removing the protected %v", approved.Protected)
			}
		})
	}
}

// flowDigestPlan is the plan the digest cases start from: an upgrade, an
// install and a removal, with one package the host holds back.
func flowDigestPlan() Plan {
	return Plan{
		Manager: "dnf", Mode: ModeUpgrade,
		Changes: []Change{
			{Name: "openssl", CurrentVersion: "3.2.3-1.fc42", CandidateVersion: "3.2.4-1.fc42",
				Origin: "updates", Architecture: "x86_64", Action: ActionUpgrade},
			{Name: "kernel-core", CandidateVersion: "6.17.4-200.fc42",
				Origin: "updates", Architecture: "x86_64", Action: ActionInstall},
			{Name: "kernel-core", CurrentVersion: "6.15.2-200.fc42",
				Architecture: "x86_64", Action: ActionRemove},
		},
		Blocked: []Blocked{{Name: "podman", Status: "versionlock", Kind: BlockedHeld}},
	}
}

// The digest is what the operator approves, so everything that changes what
// the transaction does has to change it: the elements, the version a removal
// names, a package the policy protects, an obstacle the host raises.
func TestTheDigestCoversWhatTheTransactionWillDo(t *testing.T) {
	reference := hex.EncodeToString(flowPlan(flowDigestPlan()).Hash())
	if reference == "" {
		t.Fatal("the plan cannot be hashed")
	}

	cases := []struct {
		name   string
		change func(*Plan)
	}{
		{
			name: "an element is added",
			change: func(p *Plan) {
				p.Changes = append(p.Changes, Change{Name: "zlib-ng-compat",
					CurrentVersion: "2.2.2-1.fc42", CandidateVersion: "2.2.3-1.fc42",
					Origin: "updates", Architecture: "x86_64", Action: ActionUpgrade})
			},
		},
		{
			// On dnf the version a removal names is the removal: another version
			// there is another package leaving the host.
			name: "the version of a removal changes",
			change: func(p *Plan) {
				for i := range p.Changes {
					if p.Changes[i].Action == ActionRemove {
						p.Changes[i].CurrentVersion = "6.16.1-200.fc42"
					}
				}
			},
		},
		{
			name: "a protected package appears",
			change: func(p *Plan) {
				p.Protected = append(p.Protected, "sudo")
			},
		},
		{
			name: "a blocked entry appears",
			change: func(p *Plan) {
				p.Blocked = append(p.Blocked, Blocked{Name: "container-selinux", Status: "unresolved",
					Kind: BlockedUnknown})
			},
		},
		{
			// A block the resolution could not name is not the same obstacle as
			// one the host holds back on purpose.
			name: "a blocked entry changes kind",
			change: func(p *Plan) {
				p.Blocked[0].Kind = BlockedUnknown
			},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			p := flowDigestPlan()
			testCase.change(&p)
			if digest := hex.EncodeToString(flowPlan(p).Hash()); digest == reference {
				t.Error("the digest of the plan did not change")
			}
		})
	}

	// The description is the plan in words for the screen and the one part of
	// the envelope outside the digest: two ways of saying the same transaction
	// are the same transaction.
	envelope := flowPlan(flowDigestPlan()).Envelope()
	envelope.Description = "another wording of the very same plan"
	if hex.EncodeToString(envelope.Hash()) != reference {
		t.Error("the wording of the description changed the digest")
	}
}

// The plan promises a state, and the state read after the transaction settles
// it: every arrival at its candidate version, every removal gone. A package
// still installed is the one effect missed, and the rest stay achieved.
func TestTheExpectedEffectsMatchThePlanAndSettleAgainstTheStateAfter(t *testing.T) {
	cases := []struct {
		manager string
		plan    Plan
		after   map[string]string
		missing string
	}{
		{
			manager: "apt",
			plan: Plan{Manager: "apt", Mode: ModeInstall, Changes: []Change{
				{Name: "nginx", CandidateVersion: "1.26.2-1", Architecture: "amd64", Action: ActionInstall},
				{Name: "openssl", CurrentVersion: "3.0.15-1", CandidateVersion: "3.0.16-1",
					Architecture: "amd64", Action: ActionUpgrade},
				{Name: "old-tool", CurrentVersion: "1.0-3", Action: ActionRemove},
			}},
			after:   map[string]string{"nginx": "1.26.2-1", "openssl": "3.0.16-1"},
			missing: "old-tool",
		},
		{
			manager: "dnf",
			plan: Plan{Manager: "dnf", Mode: ModeUpgrade, Changes: []Change{
				{Name: "openssl", CurrentVersion: "3.2.3-1.fc42", CandidateVersion: "3.2.4-1.fc42",
					Origin: "updates", Architecture: "x86_64", Action: ActionUpgrade},
				{Name: "obsolete-lib", CurrentVersion: "1.2-1.fc42",
					Architecture: "x86_64", Action: ActionRemove},
			}},
			after:   map[string]string{"openssl": "3.2.4-1.fc42"},
			missing: "obsolete-lib",
		},
		{
			manager: PacmanName,
			plan: Plan{Manager: PacmanName, Mode: ModeInstall, Changes: []Change{
				{Name: "ripgrep", CandidateVersion: "14.1.1-1", Architecture: "x86_64", Action: ActionInstall},
				{Name: "obsolete-thing", CurrentVersion: "0.9-1", Action: ActionRemove},
			}},
			after:   map[string]string{"ripgrep": "14.1.1-1"},
			missing: "obsolete-thing",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.manager, func(t *testing.T) {
			approved := flowPlan(testCase.plan)
			expected := approved.Envelope().Effects.Expected
			if len(expected) != len(approved.Changes) {
				t.Fatalf("%d elements promise %d effects", len(approved.Changes), len(expected))
			}
			bySubject := map[string]plan.Effect{}
			for _, effect := range expected {
				bySubject[effect.Subject] = effect
			}
			for _, change := range approved.Changes {
				effect, ok := bySubject[change.Name]
				if !ok {
					t.Fatalf("%s is in the plan and promises nothing", change.Name)
				}
				if change.Action == ActionRemove {
					if effect.Kind != plan.EffectPackageAbsent {
						t.Errorf("the removal of %s promises %+v", change.Name, effect)
					}
					continue
				}
				if effect.Kind != plan.EffectPackageVersion || effect.Value != change.CandidateVersion {
					t.Errorf("the arrival of %s promises %+v, the candidate is %s",
						change.Name, effect, change.CandidateVersion)
				}
			}

			// The state of a transaction that ran as planned: everything achieved.
			var apply Apply
			if err := settleEffects(&apply, approved, testCase.after); err != nil {
				t.Errorf("the plan carried out as written settles as %v", err)
			}
			if len(apply.EffectsAchieved) != len(expected) || len(apply.EffectsMissed) != 0 {
				t.Errorf("%d effects achieved, %d missed, %d promised",
					len(apply.EffectsAchieved), len(apply.EffectsMissed), len(expected))
			}

			// The same state with one removal still installed: that one effect is
			// missed, the others stay achieved, and the answer says it is partial.
			stillThere := map[string]string{testCase.missing: "0.0-1"}
			for name, version := range testCase.after {
				stillThere[name] = version
			}
			apply = Apply{}
			err := settleEffects(&apply, approved, stillThere)
			if !errors.Is(err, plan.ErrEffectsPartial) {
				t.Errorf("a package still installed settles as %v", err)
			}
			if len(apply.EffectsMissed) != 1 || apply.EffectsMissed[0].Effect.Subject != testCase.missing {
				t.Errorf("the effects missed are %+v, expected %s alone", apply.EffectsMissed, testCase.missing)
			}
			if len(apply.EffectsAchieved) != len(expected)-1 {
				t.Errorf("%d effects achieved, expected %d", len(apply.EffectsAchieved), len(expected)-1)
			}
		})
	}
}
