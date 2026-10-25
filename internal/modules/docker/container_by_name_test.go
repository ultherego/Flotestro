package docker

import (
	"context"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

// engineAnswering serves the list of containers the way the engine does, on a socket
// of its own, and returns a client that talks to it.
func engineAnswering(t *testing.T, status int, body string) *Client {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "engine.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("a socket of the test could not be opened: %v", err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		list := strings.HasSuffix(r.URL.Path, "/containers/json")
		if status != http.StatusOK && list {
			http.Error(w, "the engine is unwell", status)
			return
		}
		if list {
			_, _ = w.Write([]byte(body))
			return
		}
		_, _ = w.Write([]byte(`{"RestartCount": 2, "State": {}}`))
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return NewAt(socket)
}

const twoContainers = `[
  {"Id": "aaaaaaaaaaaa1111", "Names": ["/web"], "Image": "nginx:alpine", "ImageID": "sha256:1", "State": "running"},
  {"Id": "bbbbbbbbbbbb2222", "Names": ["/db"], "Image": "postgres:17", "ImageID": "sha256:2", "State": "exited"}
]`

func TestAContainerIsFoundByItsExactName(t *testing.T) {
	client := engineAnswering(t, http.StatusOK, twoContainers)
	found, err := client.ContainerByName(context.Background(), "web")
	if err != nil {
		t.Fatalf("a container that is there was not found: %v", err)
	}
	if found.ID != "aaaaaaaaaaaa1111" || found.Image != "nginx:alpine" || found.RestartCount != 2 {
		t.Fatalf("the wrong container, or one with nothing read of it: %+v", found)
	}
}

// A name that is a prefix or a part of another is not a match; only the whole name is.
func TestOnlyTheWholeNameMatches(t *testing.T) {
	client := engineAnswering(t, http.StatusOK, twoContainers)
	for _, name := range []string{"we", "web2", "WEB", "aaaaaaaaaaaa"} {
		if _, err := client.ContainerByName(context.Background(), name); !errors.Is(err, ErrNotFound) {
			t.Errorf("%q: %v, want a container that is not found", name, err)
		}
	}
}

// The engine that cannot be read is not the engine that has no such container: a host
// whose engine does not answer has not been shown to lack it.
func TestAnEngineThatCannotBeReadIsNotAnAbsence(t *testing.T) {
	client := engineAnswering(t, http.StatusInternalServerError, "")
	_, err := client.ContainerByName(context.Background(), "web")
	if err == nil {
		t.Fatal("an engine that answered with an error was taken for one that has the container")
	}
	if errors.Is(err, ErrNotFound) {
		t.Fatalf("an engine that could not be read was taken for the absence of the container: %v", err)
	}

	gone := NewAt(filepath.Join(t.TempDir(), "no-engine.sock"))
	if _, err := gone.ContainerByName(context.Background(), "web"); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("an engine nobody listens to was taken for an absence: %v", err)
	}
}
