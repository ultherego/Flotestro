package opspec

import (
	"strings"
	"testing"
)

// A container identifier goes into the path of an Engine API request, so it
// must not carry anything that changes that path. A container name is
// deliberately not allowed: it is a label and can be assigned to a different
// object between the plan and the execution.
func TestAContainerTargetHasToBeAnIdentifier(t *testing.T) {
	bad := []string{
		"", "my-container", "../../images/json", "abc", "ABCDEF012345",
		"5c5b63d3119a/json", "5c5b63d3119a?all=1",
	}
	for _, id := range bad {
		payload := Payload{DockerContainer: &DockerContainerPayload{ContainerID: id}}
		if err := Validate(ActionDockerStop, payload); err == nil {
			t.Errorf("the identifier %q was accepted", id)
		}
	}
	good := Payload{DockerContainer: &DockerContainerPayload{
		ContainerID: "5c5b63d3119a59ac7a7a7f2a18342dbd01f459a88ca81487ba987ddcc5c4bc00",
	}}
	if err := Validate(ActionDockerStop, good); err != nil {
		t.Errorf("a valid identifier was rejected: %v", err)
	}
}

// A volume outlives its container precisely so that the data outlives it.
// Removing volumes is allowed only when removing a container, and only
// explicitly.
func TestRemovingVolumesOnlyWhenRemovingAContainer(t *testing.T) {
	payload := Payload{DockerContainer: &DockerContainerPayload{
		ContainerID:   "5c5b63d3119a59ac7a7a7f2a18342dbd01f459a88ca81487ba987ddcc5c4bc00",
		RemoveVolumes: true,
	}}
	if err := Validate(ActionDockerStop, payload); err == nil {
		t.Error("stopping a container accepted removing volumes")
	}
	if err := Validate(ActionDockerRemove, payload); err != nil {
		t.Errorf("removing a container rejected removing volumes: %v", err)
	}
}

// Pruning removes exactly what was shown to the operator. An empty list is
// not an order to "remove everything" - it is the absence of a decision.
func TestPruningRequiresAnExplicitList(t *testing.T) {
	if err := Validate(ActionDockerPrune, Payload{DockerPrune: &DockerPrunePayload{}}); err == nil {
		t.Error("pruning without named objects was accepted")
	}

	good := Payload{DockerPrune: &DockerPrunePayload{
		ImageIDs: []string{"sha256:" + strings.Repeat("a", 64)},
	}}
	if err := Validate(ActionDockerPrune, good); err != nil {
		t.Errorf("a valid list was rejected: %v", err)
	}

	bad := Payload{DockerPrune: &DockerPrunePayload{ImageIDs: []string{"nginx:latest"}}}
	if err := Validate(ActionDockerPrune, bad); err == nil {
		t.Error("an image tag was accepted as an identifier")
	}
}

// An image reference is checked even though it does not reach a shell:
// narrower validation is cheaper than trust.
func TestAnImageReferenceIsChecked(t *testing.T) {
	good := []string{
		"nginx", "nginx:alpine", "docker.io/library/nginx:1.27",
		"registry.company.example:5000/team/application:2.1",
		"nginx@sha256:" + strings.Repeat("a", 64),
	}
	for _, reference := range good {
		payload := Payload{DockerImage: &DockerImagePayload{Reference: reference}}
		if err := Validate(ActionDockerPull, payload); err != nil {
			t.Errorf("the valid reference %q was rejected: %v", reference, err)
		}
	}
	bad := []string{"", "nginx latest", "nginx;reboot", "NGINX:latest", "-x"}
	for _, reference := range bad {
		payload := Payload{DockerImage: &DockerImagePayload{Reference: reference}}
		if err := Validate(ActionDockerPull, payload); err == nil {
			t.Errorf("the invalid reference %q was accepted", reference)
		}
	}
}

// The risk level is not a label: removing a container and pruning are
// destructive, so they require fresh authentication and typing the target
// name.
func TestDestructiveOperationsRequireTargetConfirmation(t *testing.T) {
	for _, action := range []ActionType{ActionDockerRemove, ActionDockerPrune} {
		if action.Risk() != RiskDestructive {
			t.Errorf("%s has the risk %s", action, action.Risk())
		}
		if !action.RequiresFreshAuth() || !action.RequiresTargetConfirmation() {
			t.Errorf("%s does not require target confirmation", action)
		}
	}
	if ActionDockerStart.RequiresTargetConfirmation() {
		t.Error("starting a container requires typing the target name")
	}
}
