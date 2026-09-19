package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/relay"
	"github.com/ultherego/flotestro/internal/relay/spool"
)

// quietLog keeps the lines of the health listener out of the output of
// the tests.
func quietLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// testHealth builds the health of a relay over a temporary spool.
func testHealth(t *testing.T) *relay.Health {
	t.Helper()
	proxy, err := relay.New(relay.Options{
		UpstreamURL: "https://centre.invalid:8443",
		SpoolDir:    t.TempDir(),
		Spool:       spool.Options{},
		Log:         quietLog(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proxy.Close() })
	return relay.NewHealth(relay.HealthOptions{
		Relay:    proxy,
		Identity: func() relay.Identity { return relay.Identity{RelayID: "relay-1"} },
		Version:  "test",
	})
}

// TestTheHealthListenerAnswersOnTheConfiguredAddress guards the wiring: what
// the configuration names is where the answers are, and they are the answers
// of this relay rather than a page of any kind.
func TestTheHealthListenerAnswersOnTheConfiguredAddress(t *testing.T) {
	// A port from the operating system, so that two runs of the tests do not
	// fight over one number.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := probe.Addr().String()
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}

	server, err := startHealthListener(address, testHealth(t), quietLog())
	if err != nil {
		t.Fatalf("the health listener did not start: %v", err)
	}
	if server == nil {
		t.Fatal("an address was configured and no listener came up")
	}
	defer stopHealthListener(server)

	client := &http.Client{Timeout: 5 * time.Second,
		Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
	response, err := client.Get("http://" + address + relay.HealthPathLive)
	if err != nil {
		t.Fatalf("the health listener did not answer: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("the liveness of a working relay answered %s", response.Status)
	}
	var answer struct {
		Status     string `json:"status"`
		InstanceID string `json:"instance_id"`
	}
	if err := json.NewDecoder(response.Body).Decode(&answer); err != nil {
		t.Fatalf("the answer did not decode: %v", err)
	}
	if answer.Status != "alive" || answer.InstanceID == "" {
		t.Fatalf("the answer was %+v", answer)
	}
}

// TestAHealthListenerTurnedOffIsNoError guards the choice of the operator: an
// installation that wants no unauthenticated listener at all writes an empty
// address, and the relay comes up all the same.
func TestAHealthListenerTurnedOffIsNoError(t *testing.T) {
	server, err := startHealthListener("", testHealth(t), quietLog())
	if err != nil {
		t.Fatalf("turning the health listener off was an error: %v", err)
	}
	if server != nil {
		t.Fatal("a listener came up although none was configured")
	}
	stopHealthListener(server)
}

// TestAHealthAddressThatCannotBeBoundStopsTheRelay guards the fail-closed
// start: an operator who asked for a health answer and would get none has a
// relay that says so at the start, rather than a container the runtime keeps
func TestAHealthAddressThatCannotBeBoundStopsTheRelay(t *testing.T) {
	// An address of the documentation range: it belongs to no interface
	// of this machine, so the bind fails without touching a network.
	_, err := startHealthListener("203.0.113.1:8454", testHealth(t), quietLog())
	if err == nil {
		t.Fatal("a health address that cannot be bound came up")
	}
	if !strings.Contains(err.Error(), "203.0.113.1:8454") {
		t.Fatalf("the error does not name the address: %v", err)
	}
}
