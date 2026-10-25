package opspec

import (
	"encoding/json"
	"strings"
	"testing"
)

func containerOrder(container DockerContainerPayload) Payload {
	return Payload{DockerContainer: &container}
}

// A container is named by the engine's identifier or by its exact name; an order that names
// neither, or names the identifier wrongly, is refused.
func TestAContainerIsAddressedByIdentifierOrByExactName(t *testing.T) {
	for _, action := range []ActionType{ActionDockerStart, ActionDockerStop, ActionDockerRestart} {
		accepted := []DockerContainerPayload{
			{ContainerID: "3f2a9c1b4d55"},
			{ContainerID: "3f2a9c1b4d55", Name: "web"},
			{Name: "web"},
			{Name: "web-1.blue_2", TimeoutSeconds: 30},
		}
		for _, container := range accepted {
			if err := Validate(action, containerOrder(container)); err != nil {
				t.Errorf("%s %+v was refused: %v", action, container, err)
			}
		}
		refused := map[string]DockerContainerPayload{
			"no container at all":         {},
			"a bad identifier":            {ContainerID: "web"},
			"a name with a space":         {Name: "web server"},
			"a name with a path":          {Name: "../web"},
			"a name that starts badly":    {Name: "-web"},
			"a confirmation on a restart": {Name: "web", ConfirmName: "web"},
			"an image on a restart":       {Name: "web", ExpectedImage: "nginx:alpine"},
		}
		for why, container := range refused {
			if err := Validate(action, containerOrder(container)); err == nil {
				t.Errorf("%s: %s was accepted", action, why)
			}
		}
	}
}

// A removal by name is on the word of a name alone, on every host it reaches: the name has to be typed
// again and the image named.
func TestARemovalByNameNeedsTheNameAgainAndTheImage(t *testing.T) {
	good := DockerContainerPayload{Name: "web", ConfirmName: "web", ExpectedImage: "nginx:alpine"}
	if err := Validate(ActionDockerRemove, containerOrder(good)); err != nil {
		t.Fatalf("a confirmed removal by name was refused: %v", err)
	}
	for why, container := range map[string]DockerContainerPayload{
		"no confirmation":    {Name: "web", ExpectedImage: "nginx:alpine"},
		"another name typed": {Name: "web", ConfirmName: "db", ExpectedImage: "nginx:alpine"},
		"no image":           {Name: "web", ConfirmName: "web"},
		"a malformed image":  {Name: "web", ConfirmName: "web", ExpectedImage: "NOT AN IMAGE"},
	} {
		err := Validate(ActionDockerRemove, containerOrder(container))
		if err == nil {
			t.Errorf("a removal by name with %s was accepted", why)
		}
	}
	// By identifier it is what it always was, and carries neither.
	if err := Validate(ActionDockerRemove, containerOrder(DockerContainerPayload{ContainerID: "3f2a9c1b4d55"})); err != nil {
		t.Errorf("a removal by identifier was refused: %v", err)
	}
	err := Validate(ActionDockerRemove, containerOrder(DockerContainerPayload{ContainerID: "3f2a9c1b4d55", ConfirmName: "web"}))
	if err == nil || !strings.Contains(err.Error(), "by name") {
		t.Errorf("a confirmation next to an identifier was accepted or refused for the wrong reason: %v", err)
	}
}

func TestOnlyAnOrderWithoutAnIdentifierIsAddressedByName(t *testing.T) {
	var none *DockerContainerPayload
	if none.AddressedByName() {
		t.Error("nothing was addressed by name")
	}
	if (&DockerContainerPayload{ContainerID: "3f2a9c1b4d55", Name: "web"}).AddressedByName() {
		t.Error("an order with an identifier is addressed by it, the name is a label")
	}
	if !(&DockerContainerPayload{Name: "web"}).AddressedByName() {
		t.Error("an order with only a name is addressed by it")
	}
}

// An agent that predates addressing by name hashes container_id without omitting it, so a
// payload that leaves the identifier empty must still carry it or the plan hash differs.
func TestANamedContainerPayloadHashesLikeTheOldAgentComputesIt(t *testing.T) {
	encoded, err := json.Marshal(DockerContainerPayload{Name: "web"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"container_id":""`) {
		t.Fatalf("the identifier is dropped from the payload, older agents compute another hash: %s", encoded)
	}
}
