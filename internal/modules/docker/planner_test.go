package docker

import (
	"errors"
	"strings"
	"testing"
)

// The plan is what the operator approves, so these tests are about one thing:
// that it says the truth about the host before anything moves.

const testDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
const otherDigest = "sha256:2222222222222222222222222222222222222222222222222222222222222222"

// sampleSpec is a container description with something in every group of
// settings the plan compares.
func sampleSpec() ContainerSpec {
	return ContainerSpec{
		Name:    "storefront",
		Image:   "nginx:1.27",
		Env:     map[string]string{"MODE": "production"},
		Ports:   []PortSpec{{HostPort: 8080, ContainerPort: 80}},
		Mounts:  []MountSpec{{Type: "volume", Source: "storefront-data", Target: "/data"}},
		Restart: RestartSpec{Policy: "unless-stopped"},
		Labels:  map[string]string{"team": "platform"},
	}
}

// running builds the container the engine would report for a specification,
// the way it would report it: the reference pinned to the digest, the module's
// own labels in place, the defaults written out.
func running(spec ContainerSpec, digest string) *ContainerDetail {
	spec.ImageDigest = digest
	normalized := spec.Normalized()
	labels := managedLabels(normalized)
	observed := normalized
	observed.Labels = labels
	observed.Image = PinReference(spec.Image, digest)
	return &ContainerDetail{
		ID:      "9f1b2c3d4e5f6071",
		Name:    spec.Name,
		Image:   observed.Image,
		ImageID: digest,
		State:   "running",
		Labels:  labels,
		Spec:    observed,
	}
}

func TestAContainerThatMatchesItsDescriptionIsNoChange(t *testing.T) {
	spec := sampleSpec()
	plan := planContainerFrom(spec, testDigest, DigestFromRegistry, running(spec, testDigest))

	if plan.Action != PlanNoChange {
		t.Fatalf("action = %s, changes = %+v", plan.Action, plan.Changes)
	}
	if len(plan.Changes) != 0 {
		t.Fatalf("a matching container is not a change list: %+v", plan.Changes)
	}
	if !plan.Exists || plan.CurrentID == "" {
		t.Errorf("the plan does not say which container it is about: %+v", plan)
	}
	if plan.Changed() {
		t.Errorf("a plan with no change says it would touch the host")
	}
	// The same plan computed twice gives the same digest, or an approval
	// could never be carried out.
	again := planContainerFrom(spec, testDigest, DigestFromLocal, running(spec, testDigest))
	if again.Digest != plan.Digest {
		t.Errorf("the digest of the same plan differs: %s and %s", plan.Digest, again.Digest)
	}
}

func TestAContainerWithAnotherImageDigestIsReplaced(t *testing.T) {
	spec := sampleSpec()
	plan := planContainerFrom(spec, otherDigest, DigestFromRegistry, running(spec, testDigest))

	if plan.Action != PlanReplace {
		t.Fatalf("action = %s, expected %s", plan.Action, PlanReplace)
	}
	if !hasChange(plan.Changes, "image") {
		t.Fatalf("the plan does not name the image among the changes: %+v", plan.Changes)
	}
	if plan.ImageDigest != otherDigest {
		t.Errorf("the plan binds %s instead of the resolved digest", plan.ImageDigest)
	}
	// A tag that can move is something the approver is meant to know
	// about before they approve the plan.
	if len(plan.Warnings) == 0 {
		t.Errorf("a plan for a mutable tag carries no warning")
	}
	// The digest has to differ from the one of the matching plan, or an
	// approval of one change would carry another one out.
	same := planContainerFrom(spec, testDigest, DigestFromRegistry, running(spec, testDigest))
	if plan.Digest == same.Digest {
		t.Errorf("two different plans share a digest")
	}
}

func TestAChangedRestartPolicyIsAReplacementAndNotAnEdit(t *testing.T) {
	spec := sampleSpec()
	current := running(spec, testDigest)

	changed := sampleSpec()
	changed.Restart = RestartSpec{Policy: "always"}
	plan := planContainerFrom(changed, testDigest, DigestFromRegistry, current)

	if plan.Action != PlanReplace {
		t.Fatalf("action = %s, expected %s", plan.Action, PlanReplace)
	}
	change := changeOf(plan.Changes, "restart_policy")
	if change == nil {
		t.Fatalf("the plan does not name the restart policy: %+v", plan.Changes)
	}
	if change.Current != "unless-stopped" || change.Desired != "always" {
		t.Errorf("the change reads %q -> %q", change.Current, change.Desired)
	}
}

func TestAContainerTheHostDoesNotHaveIsCreated(t *testing.T) {
	plan := planContainerFrom(sampleSpec(), testDigest, DigestFromRegistry, nil)
	if plan.Action != PlanCreate {
		t.Fatalf("action = %s, expected %s", plan.Action, PlanCreate)
	}
	if plan.Exists {
		t.Errorf("a container that is not there is reported as existing")
	}
	if plan.PinnedImage != "nginx@"+testDigest {
		t.Errorf("the container would be created from %q rather than from the digest", plan.PinnedImage)
	}
}

// A container made by hand has no description this panel knows, and an
// unknown description is never a matching one.
func TestAContainerNobodyDeclaredHereIsTakenOverByReplacement(t *testing.T) {
	spec := sampleSpec()
	current := running(spec, testDigest)
	delete(current.Labels, LabelSpecDigest)
	current.Spec.Labels = current.Labels

	plan := planContainerFrom(spec, testDigest, DigestFromRegistry, current)
	if plan.Action != PlanReplace {
		t.Fatalf("action = %s, expected %s", plan.Action, PlanReplace)
	}
	if !hasChange(plan.Changes, "specification") {
		t.Fatalf("the plan does not say the container was not declared here: %+v", plan.Changes)
	}
}

// A secret rotated to another version changes nothing the engine reports,
// and everything about what the container runs with.
func TestARotatedSecretIsAReplacement(t *testing.T) {
	spec := sampleSpec()
	spec.EnvSecrets = map[string]string{"DATABASE_PASSWORD": "store.db#3"}
	current := running(spec, testDigest)
	// The engine reports the value the container really runs with; the
	// description never carries it and the plan must never echo it.
	current.Spec.Env = map[string]string{
		"MODE": "production", "DATABASE_PASSWORD": "whatever the store held then",
	}

	rotated := spec
	rotated.EnvSecrets = map[string]string{"DATABASE_PASSWORD": "store.db#4"}
	plan := planContainerFrom(rotated, testDigest, DigestFromRegistry, current)

	if plan.Action != PlanReplace {
		t.Fatalf("action = %s, expected %s", plan.Action, PlanReplace)
	}
	for _, change := range plan.Changes {
		if strings.Contains(change.Current, "whatever the store held") ||
			strings.Contains(change.Desired, "whatever the store held") {
			t.Fatalf("the change list carries the value of a secret: %+v", change)
		}
	}
}

// A container that matches and is down is started rather than rebuilt: a
// replacement would throw away what is in it for no reason.
func TestAMatchingContainerThatIsDownIsStarted(t *testing.T) {
	spec := sampleSpec()
	current := running(spec, testDigest)
	current.State = "exited"
	current.Spec.Stopped = true

	plan := planContainerFrom(spec, testDigest, DigestFromRegistry, current)
	if plan.Action != PlanStart {
		t.Fatalf("action = %s, expected %s", plan.Action, PlanStart)
	}
	if len(plan.Changes) != 0 {
		t.Errorf("starting a container is not a change of its description: %+v", plan.Changes)
	}
}

func TestANetworkWithContainersAttachedRefusesToBeRecreated(t *testing.T) {
	state := Snapshot{
		Networks: []Network{{
			ID: "abc123456789", Name: "backplane", Driver: "bridge",
			Subnets:    []string{"10.8.0.0/24"},
			Containers: []NetworkMember{{ID: "1111", Name: "storefront"}},
			InUse:      true,
		}},
	}
	spec := NetworkSpec{Name: "backplane", Subnet: "10.9.0.0/24"}

	plan, err := planNetworkFrom(state, spec, false)
	if !errors.Is(err, ErrInUse) {
		t.Fatalf("error = %v, expected a refusal for an object in use", err)
	}
	if plan.Action != PlanReplace {
		t.Errorf("the refused plan does not say what it would have done: %s", plan.Action)
	}
	// The refusal names what stands in the way, or the operator cannot act
	// on it.
	if len(plan.Detaches) != 1 || plan.Detaches[0] != "storefront" {
		t.Errorf("the plan does not name the attached containers: %+v", plan.Detaches)
	}

	forced, err := planNetworkFrom(state, spec, true)
	if err != nil {
		t.Fatalf("an order that accepts the disconnection was refused: %v", err)
	}
	if forced.Action != PlanReplace || len(forced.Warnings) == 0 {
		t.Errorf("a forced replacement without a warning: %+v", forced)
	}
}

func TestARemovalOfANetworkInUseRefusesAndAnUnusedOneDoesNot(t *testing.T) {
	state := Snapshot{
		Networks: []Network{
			{ID: "aaa111222333", Name: "backplane",
				Containers: []NetworkMember{{ID: "1", Name: "storefront"}}, InUse: true},
			{ID: "bbb444555666", Name: "leftover"},
		},
	}
	if _, err := planNetworkRemovalFrom(state, "backplane", false); !errors.Is(err, ErrInUse) {
		t.Fatalf("removing a network in use was not refused: %v", err)
	}
	plan, err := planNetworkRemovalFrom(state, "leftover", false)
	if err != nil {
		t.Fatalf("removing an unused network was refused: %v", err)
	}
	if plan.Action != PlanRemove {
		t.Errorf("action = %s, expected %s", plan.Action, PlanRemove)
	}
	// A host that never had the object is not a failed removal and not a
	// successful one either.
	absent, err := planNetworkRemovalFrom(state, "never-existed", false)
	if err != nil {
		t.Fatalf("a removal of something absent failed: %v", err)
	}
	if absent.Action != PlanAbsent || absent.Changed() {
		t.Errorf("a removal of something absent reads as a change: %+v", absent)
	}
}

func TestAVolumeInUseIsNotRemovedWithoutTheOrderSayingSo(t *testing.T) {
	state := Snapshot{
		Volumes: []Volume{{
			Name: "storefront-data", Driver: "local", InUse: true,
			UsedBy: []VolumeMount{{ContainerName: "storefront", Destination: "/data"}},
		}},
	}
	if _, err := planVolumeRemovalFrom(state, "storefront-data", false); !errors.Is(err, ErrInUse) {
		t.Fatalf("removing a volume in use was not refused: %v", err)
	}
	plan, err := planVolumeRemovalFrom(state, "storefront-data", true)
	if err != nil {
		t.Fatalf("a forced removal was refused by the panel: %v", err)
	}
	// The engine still refuses; the operator is told so rather than
	// promised a removal that will not happen.
	if len(plan.Warnings) == 0 {
		t.Errorf("a forced removal of a volume in use carries no warning: %+v", plan)
	}
}

func TestAVolumeThatDiffersIsNotSilentlyRecreated(t *testing.T) {
	state := Snapshot{Volumes: []Volume{{Name: "cache", Driver: "local"}}}
	spec := VolumeSpec{Name: "cache", Driver: "local", Options: map[string]string{"type": "tmpfs"}}

	if _, err := planVolumeFrom(state, spec, false); !errors.Is(err, ErrObjectConflict) {
		t.Fatalf("a volume that differs was not refused: %v", err)
	}
	matching, err := planVolumeFrom(state, VolumeSpec{Name: "cache"}, false)
	if err != nil {
		t.Fatalf("a volume that matches was refused: %v", err)
	}
	if matching.Action != PlanNoChange {
		t.Errorf("action = %s, expected %s", matching.Action, PlanNoChange)
	}
}

// The panel refuses what the engine would refuse, and names the field: a
// refusal from the engine names an HTTP status and nothing else.
func TestTheDescriptionRefusesWhatTheEngineWouldRefuse(t *testing.T) {
	cases := []struct {
		name  string
		spec  ContainerSpec
		about string
	}{
		{"a name the engine does not take", withName(""), "container name"},
		{"an image reference with a space", withImage("nginx 1.27"), "image reference"},
		{"a retry count on a policy that has none",
			withRestart(RestartSpec{Policy: "always", MaxRetries: 5}), "on-failure"},
		{"an unknown restart policy", withRestart(RestartSpec{Policy: "sometimes"}), "restart policy"},
		{"the same host port twice", withPorts([]PortSpec{
			{HostPort: 8080, ContainerPort: 80}, {HostPort: 8080, ContainerPort: 81},
		}), "published twice"},
		{"two mounts on one mount point", withMounts([]MountSpec{
			{Type: "volume", Source: "a", Target: "/data"},
			{Type: "volume", Source: "b", Target: "/data"},
		}), "mount point"},
		{"a bind source that is not a path", withMounts([]MountSpec{
			{Type: "bind", Source: "data", Target: "/data"},
		}), "bind source"},
		{"a reservation above the limit", withResources(ResourceSpec{
			MemoryBytes: 1 << 20, MemoryReservationBytes: 1 << 30,
		}), "reservation"},
		{"a health check without a command", withHealth(&HealthSpec{Test: []string{"CMD"}}), "health check"},
		{"a health check that never finishes in time",
			withHealth(&HealthSpec{Test: []string{"CMD", "true"}, IntervalSeconds: 5, TimeoutSeconds: 30}), "timeout"},
		{"a password written into the order",
			withEnv(map[string]string{"DATABASE_PASSWORD": "hunter2"}), "credential"},
		{"a label that claims membership in a Compose project",
			withLabels(map[string]string{"com.docker.compose.project": "storefront"}), "Compose"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			err := test.spec.Validate()
			if err == nil {
				t.Fatalf("the description was accepted")
			}
			if !strings.Contains(err.Error(), test.about) {
				t.Errorf("the refusal %q does not name %q", err, test.about)
			}
		})
	}
}

func TestANetworkDescriptionRefusesARangeWithoutItsSubnet(t *testing.T) {
	spec := NetworkSpec{Name: "backplane", Gateway: "10.8.0.1"}
	if err := spec.Validate(); err == nil || !strings.Contains(err.Error(), "subnet") {
		t.Fatalf("error = %v, expected a refusal naming the subnet", err)
	}
	// The engine's own networks are not declared here: it does not allow
	// removing or recreating them, so a plan about one could never run.
	if err := (&NetworkSpec{Name: "bridge"}).Validate(); err == nil {
		t.Errorf("a description of the engine's own bridge network was accepted")
	}
	if err := (&NetworkSpec{Name: "backplane", Subnet: "10.8.0.0/24", Gateway: "10.8.0.1"}).Validate(); err != nil {
		t.Errorf("a whole description was refused: %v", err)
	}
}

// A change carries the digest of the plan it was approved from; a host
// that moved on since gets no change at all.
func TestAChangeIsRefusedWhenThePlanMovedSinceItWasApproved(t *testing.T) {
	spec := sampleSpec()
	plan := planContainerFrom(spec, testDigest, DigestFromRegistry, running(spec, testDigest))
	if err := checkApproval(plan, plan.Digest); err != nil {
		t.Fatalf("the plan it was approved from was refused: %v", err)
	}
	moved := planContainerFrom(spec, otherDigest, DigestFromRegistry, running(spec, testDigest))
	err := checkApproval(moved, plan.Digest)
	if !errors.Is(err, ErrPlanMismatch) {
		t.Fatalf("error = %v, expected a refusal of a plan that moved", err)
	}
}

func hasChange(changes []Change, field string) bool {
	return changeOf(changes, field) != nil
}

func changeOf(changes []Change, field string) *Change {
	for i := range changes {
		if changes[i].Field == field {
			return &changes[i]
		}
	}
	return nil
}

func withName(name string) ContainerSpec { s := sampleSpec(); s.Name = name; return s }

func withImage(image string) ContainerSpec { s := sampleSpec(); s.Image = image; return s }

func withRestart(restart RestartSpec) ContainerSpec {
	s := sampleSpec()
	s.Restart = restart
	return s
}

func withPorts(ports []PortSpec) ContainerSpec { s := sampleSpec(); s.Ports = ports; return s }

func withMounts(mounts []MountSpec) ContainerSpec { s := sampleSpec(); s.Mounts = mounts; return s }

func withResources(resources ResourceSpec) ContainerSpec {
	s := sampleSpec()
	s.Resources = resources
	return s
}

func withHealth(health *HealthSpec) ContainerSpec { s := sampleSpec(); s.Health = health; return s }

func withEnv(env map[string]string) ContainerSpec { s := sampleSpec(); s.Env = env; return s }

func withLabels(labels map[string]string) ContainerSpec {
	s := sampleSpec()
	s.Labels = labels
	return s
}
