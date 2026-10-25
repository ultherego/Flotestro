package docker

import (
	"context"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// engineWithMinimum refuses any API version below its minimum, as a current engine does.
func engineWithMinimum(t *testing.T, minimum string) (*Client, func() []string) {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "engine.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("a socket of the test could not be opened: %v", err)
	}
	var mu sync.Mutex
	var seen []string
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/version" {
			_, _ = w.Write([]byte(`{"Version":"29.0.0","ApiVersion":"1.52","MinAPIVersion":"` + minimum + `"}`))
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/v"+minimum+"/") && versionLess(strings.SplitN(r.URL.Path, "/", 3)[1], "v"+minimum) {
			http.Error(w, "client version too old", http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`[]`))
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return NewAt(socket), func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
}

func TestAnEngineThatRefusesTheOldAPIIsAskedForItsOldestOne(t *testing.T) {
	client, paths := engineWithMinimum(t, "1.44")
	if _, err := client.Containers(context.Background(), true); err != nil {
		t.Fatalf("the engine refused the version the client chose: %v", err)
	}
	if got := paths(); len(got) < 2 || !strings.HasPrefix(got[len(got)-1], "/v1.44/") {
		t.Fatalf("the call did not go to the engine's oldest version: %v", got)
	}
}

func TestAnEngineThatStillAcceptsThePinnedAPIIsAskedForThePinnedOne(t *testing.T) {
	client, paths := engineWithMinimum(t, "1.24")
	if _, err := client.Containers(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if got := paths(); !strings.HasPrefix(got[len(got)-1], "/"+apiVersion+"/") {
		t.Fatalf("the pinned version was not used: %v", got)
	}
}
