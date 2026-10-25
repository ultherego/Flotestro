package agent

import (
	"context"
	"testing"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/modules/docker"
	"github.com/ultherego/flotestro/internal/opspec"
)

// What the order carries to name the container reaches the payload the agent verifies,
// binds and journals: the name, and for a removal the confirmation and the image.
func TestTheEnvelopeOfAContainerByNameCarriesWhatNamesIt(t *testing.T) {
	action, payload, err := dockerAction(&agentv1.DockerAction{
		Operation:     agentv1.DockerAction_OPERATION_REMOVE,
		ContainerName: "web", ConfirmName: "web", ExpectedImage: "nginx:alpine",
	})
	if err != nil || action != opspec.ActionDockerRemove {
		t.Fatalf("the envelope was not read: %v %v", action, err)
	}
	container := payload.DockerContainer
	if container.ContainerID != "" || container.Name != "web" || container.ConfirmName != "web" ||
		container.ExpectedImage != "nginx:alpine" || !container.AddressedByName() {
		t.Fatalf("the payload lost what names the container: %+v", container)
	}
}

func engineShowing(containers ...docker.Container) *hostReaders {
	return &hostReaders{docker: func(context.Context) (docker.Snapshot, error) {
		return docker.Snapshot{Containers: containers}, nil
	}}
}

// The identifier is the host's own and the order never held it, so the state after the
// change is read back by the name the order used.
func TestAContainerByNameIsVerifiedByItsName(t *testing.T) {
	byName := func(action opspec.ActionType) verifyInput {
		return verifyInput{action: action, payload: opspec.Payload{
			DockerContainer: &opspec.DockerContainerPayload{Name: "web"},
		}}
	}
	running := docker.Container{ID: "aaaaaaaaaaaa1111", Name: "web", State: "running"}
	stopped := docker.Container{ID: "aaaaaaaaaaaa1111", Name: "web", State: "exited"}
	other := docker.Container{ID: "bbbbbbbbbbbb2222", Name: "db", State: "running"}

	if got := verifyContainerState(context.Background(), engineShowing(running, other), byName(opspec.ActionDockerRestart)); !got.verified {
		t.Errorf("a restarted container that runs was not verified: %+v", got)
	}
	if got := verifyContainerState(context.Background(), engineShowing(stopped, other), byName(opspec.ActionDockerRestart)); got.verified {
		t.Errorf("a restart that left the container stopped was verified")
	}
	if got := verifyContainerState(context.Background(), engineShowing(stopped), byName(opspec.ActionDockerStop)); !got.verified {
		t.Errorf("a stopped container was not verified: %+v", got)
	}
	// Another container's state is not this one's: the db runs, the web is not listed.
	if got := verifyContainerState(context.Background(), engineShowing(other), byName(opspec.ActionDockerRestart)); got.verified {
		t.Errorf("a container that is not listed was verified by another's state")
	}
	if got := verifyContainerState(context.Background(), engineShowing(other), byName(opspec.ActionDockerRemove)); !got.verified {
		t.Errorf("a removed container that is gone was not verified: %+v", got)
	}
	if got := verifyContainerState(context.Background(), engineShowing(running), byName(opspec.ActionDockerRemove)); got.verified {
		t.Errorf("a container still listed after its removal was verified")
	}
}
