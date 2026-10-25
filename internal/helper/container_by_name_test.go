package helper

import (
	"context"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/docker"
)

// engineWith serves the list of containers on a socket of its own, or an error.
func engineWith(t *testing.T, status int, body string) *docker.Client {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "engine.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("a socket of the test could not be opened: %v", err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !strings.HasSuffix(r.URL.Path, "/containers/json") {
			_, _ = w.Write([]byte(`{"RestartCount": 0, "State": {}}`))
			return
		}
		if status != http.StatusOK {
			http.Error(w, "the engine is unwell", status)
			return
		}
		_, _ = w.Write([]byte(body))
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return docker.NewAt(socket)
}

const runningWeb = `[{"Id": "aaaaaaaaaaaa1111", "Names": ["/web"], "Image": "nginx:alpine", "ImageID": "sha256:1", "State": "running"}]`

func order(operation helperv1.DockerActionRequest_Operation, set func(*helperv1.DockerActionRequest)) *helperv1.DockerActionRequest {
	request := &helperv1.DockerActionRequest{Operation: operation, ContainerName: "web"}
	if set != nil {
		set(request)
	}
	return request
}

func refusedWith(t *testing.T, response *helperv1.HelperResponse, code string) {
	t.Helper()
	if response == nil || response.GetAccepted() || response.GetErrorCode() != code {
		t.Fatalf("want a refusal with %q, got %+v", code, response)
	}
}

func TestTheHelperResolvesANameToTheContainerOfItsHost(t *testing.T) {
	client := engineWith(t, http.StatusOK, runningWeb)
	found, refusal := resolveContainerByName(context.Background(), client,
		order(helperv1.DockerActionRequest_OPERATION_RESTART, nil))
	if refusal != nil || found == nil || found.ID != "aaaaaaaaaaaa1111" {
		t.Fatalf("the container was not resolved: %+v, %+v", found, refusal)
	}
}

func TestAnAbsentContainerAndAnUnreadableEngineAreTwoRefusals(t *testing.T) {
	absent := engineWith(t, http.StatusOK, `[]`)
	_, refusal := resolveContainerByName(context.Background(), absent,
		order(helperv1.DockerActionRequest_OPERATION_RESTART, nil))
	refusedWith(t, refusal, ErrorContainerNotFound)

	unwell := engineWith(t, http.StatusInternalServerError, "")
	_, refusal = resolveContainerByName(context.Background(), unwell,
		order(helperv1.DockerActionRequest_OPERATION_RESTART, nil))
	refusedWith(t, refusal, ErrorDockerEngineUnreadable)
}

// A container removed by name is removed on the word of a name alone, so the name is typed
// again, the image is named, and a container that runs another image is left where it is.
func TestARemovalByNameChecksWhatItIsAboutToRemove(t *testing.T) {
	client := engineWith(t, http.StatusOK, runningWeb)
	remove := helperv1.DockerActionRequest_OPERATION_REMOVE
	confirmed := func(request *helperv1.DockerActionRequest) {
		request.ConfirmName, request.ExpectedImage = "web", "nginx:alpine"
	}

	_, refusal := resolveContainerByName(context.Background(), client, order(remove, nil))
	refusedWith(t, refusal, ErrorMalformed)
	_, refusal = resolveContainerByName(context.Background(), client,
		order(remove, func(r *helperv1.DockerActionRequest) { r.ConfirmName = "other"; r.ExpectedImage = "nginx:alpine" }))
	refusedWith(t, refusal, ErrorMalformed)
	_, refusal = resolveContainerByName(context.Background(), client,
		order(remove, func(r *helperv1.DockerActionRequest) { r.ConfirmName = "web" }))
	refusedWith(t, refusal, ErrorMalformed)

	_, refusal = resolveContainerByName(context.Background(), client,
		order(remove, func(r *helperv1.DockerActionRequest) { r.ConfirmName = "web"; r.ExpectedImage = "postgres:17" }))
	refusedWith(t, refusal, ErrorContainerIdentity)

	found, refusal := resolveContainerByName(context.Background(), client, order(remove, confirmed))
	if refusal != nil || found == nil || found.Name != "web" {
		t.Fatalf("the container the order expects was not removed: %+v, %+v", found, refusal)
	}
}

func TestAConfirmationBelongsToARemovalAndANameHasTheShapeOfOne(t *testing.T) {
	client := engineWith(t, http.StatusOK, runningWeb)
	_, refusal := resolveContainerByName(context.Background(), client,
		order(helperv1.DockerActionRequest_OPERATION_RESTART, func(r *helperv1.DockerActionRequest) { r.ConfirmName = "web" }))
	refusedWith(t, refusal, ErrorMalformed)
	for _, name := range []string{"", "web server", "../web", "-web", "web;rm"} {
		_, refusal = resolveContainerByName(context.Background(), client,
			order(helperv1.DockerActionRequest_OPERATION_RESTART, func(r *helperv1.DockerActionRequest) { r.ContainerName = name }))
		refusedWith(t, refusal, ErrorMalformed)
	}
}

func TestAnImageIsTheOneAContainerRunsByReferenceOrByDigest(t *testing.T) {
	byDigest := &docker.Container{Image: "sha256:abc", ImageDigest: "sha256:abc"}
	if !runsImage(&docker.Container{Image: "nginx:alpine"}, "nginx:alpine") {
		t.Error("the reference the container was started with was not recognised")
	}
	if !runsImage(byDigest, "nginx@sha256:abc") {
		t.Error("an image named by its digest was not recognised")
	}
	if runsImage(&docker.Container{Image: "nginx:alpine"}, "nginx:latest") || runsImage(byDigest, "nginx@sha256:def") {
		t.Error("another image was taken for the expected one")
	}
}
