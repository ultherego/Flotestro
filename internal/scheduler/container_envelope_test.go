package scheduler

import (
	"testing"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/opspec"
)

func TestTheEnvelopeOfAContainerByNameCarriesTheConfirmationAndTheImage(t *testing.T) {
	envelope := dockerEnvelope(opspec.ActionDockerRemove, opspec.Payload{DockerContainer: &opspec.DockerContainerPayload{
		Name: "web", ConfirmName: "web", ExpectedImage: "nginx:alpine",
	}})
	if envelope.GetContainerId() != "" || envelope.GetContainerName() != "web" ||
		envelope.GetConfirmName() != "web" || envelope.GetExpectedImage() != "nginx:alpine" ||
		envelope.GetOperation() != agentv1.DockerAction_OPERATION_REMOVE {
		t.Fatalf("the envelope lost what names the container: %+v", envelope)
	}
}
