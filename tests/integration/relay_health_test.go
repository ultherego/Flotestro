//go:build integration

package integration

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// The containerisation document asks a relay for two answers, not one.

// defaultRelayHealth points at the health listener of the relay of the test
// fleet.
const defaultRelayHealth = "http://192.168.56.60:8454"

// relayHealthAnswer is what both endpoints answer, as far as this test
// reads them.
type relayHealthAnswer struct {
	Status        string   `json:"status"`
	Code          string   `json:"code"`
	Upstream      string   `json:"upstream"`
	InstanceID    string   `json:"instance_id"`
	SafeToRestart bool     `json:"safe_to_restart"`
	Reasons       []string `json:"reasons"`
	Checks        []struct {
		Name   string `json:"name"`
		OK     bool   `json:"ok"`
		Code   string `json:"code"`
		Detail string `json:"detail"`
	} `json:"checks"`
}

// askRelayHealth asks one endpoint of the health listener.
func askRelayHealth(t *testing.T, base, path string) (int, relayHealthAnswer) {
	t.Helper()
	client := &http.Client{Timeout: 10 * time.Second,
		Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
	response, err := client.Get(base + path)
	if err != nil {
		t.Fatalf("the health listener of the relay did not answer %s: %v\n"+
			"a relay without it cannot be told apart from a wedged one by any container runtime", path, err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		t.Fatalf("the answer of %s was not read: %v", path, err)
	}
	var answer relayHealthAnswer
	if err := json.Unmarshal(body, &answer); err != nil {
		t.Fatalf("the answer of %s is not JSON: %v (%s)", path, err, truncate(body, 200))
	}
	return response.StatusCode, answer
}

// TestTheRelayAnswersLivenessAndReadinessApart is the gap of the
// containerisation document, asked of the real relay.
func TestTheRelayAnswersLivenessAndReadinessApart(t *testing.T) {
	relayURL := envOr("FLOTESTRO_TEST_RELAY", defaultRelay)
	address := strings.TrimPrefix(relayURL, "https://")
	if conn, err := net.DialTimeout("tcp", address, 3*time.Second); err != nil {
		t.Skipf("the lab relay at %s does not answer: %v", address, err)
	} else {
		_ = conn.Close()
	}
	base := envOr("FLOTESTRO_TEST_RELAY_HEALTH", defaultRelayHealth)

	status, live := askRelayHealth(t, base, "/healthz")
	if status != http.StatusOK || live.Status != "alive" {
		t.Fatalf("liveness answered %d %+v; the relay is up and taking connections", status, live)
	}
	if live.InstanceID == "" {
		t.Fatalf("liveness named no instance of the relay: %+v", live)
	}

	readyStatus, ready := askRelayHealth(t, base, "/readyz")
	switch readyStatus {
	case http.StatusOK:
		if ready.Status != "ready" || len(ready.Reasons) != 0 {
			t.Fatalf("readiness answered 200 and said %+v", ready)
		}
	case http.StatusServiceUnavailable:
		if ready.Status != "not_ready" || len(ready.Reasons) == 0 {
			t.Fatalf("readiness refused without naming what is false: %+v", ready)
		}
		// The whole point of the two answers: whatever readiness says about the
		// link, liveness stays true.
		if status != http.StatusOK {
			t.Fatalf("liveness followed readiness down: %+v", live)
		}
	default:
		t.Fatalf("readiness answered %d: %+v", readyStatus, ready)
	}
	// Every readiness check answers with a name and a detail: the
	// operator reads them out of a container and has nothing else.
	wanted := map[string]bool{"listener": false, "upstream": false, "spool": false, "certificate": false}
	for _, check := range ready.Checks {
		if _, known := wanted[check.Name]; !known {
			t.Fatalf("readiness answered an unknown check %q", check.Name)
		}
		wanted[check.Name] = true
		if check.Detail == "" {
			t.Fatalf("the check %q answered without a detail", check.Name)
		}
		if !check.OK && check.Code == "" {
			t.Fatalf("the check %q is false and names no code", check.Name)
		}
	}
	for name, answered := range wanted {
		if !answered {
			t.Fatalf("readiness did not answer the check %q at all", name)
		}
	}
}

// TestTheHealthListenerOfTheRelayCarriesNothingElse guards what the listener
// is allowed to be.
func TestTheHealthListenerOfTheRelayCarriesNothingElse(t *testing.T) {
	relayURL := envOr("FLOTESTRO_TEST_RELAY", defaultRelay)
	address := strings.TrimPrefix(relayURL, "https://")
	if conn, err := net.DialTimeout("tcp", address, 3*time.Second); err != nil {
		t.Skipf("the lab relay at %s does not answer: %v", address, err)
	} else {
		_ = conn.Close()
	}
	base := envOr("FLOTESTRO_TEST_RELAY_HEALTH", defaultRelayHealth)
	client := &http.Client{Timeout: 10 * time.Second,
		Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}

	for _, path := range []string{"/", "/metrics", "/flotestro.agent.v1.AgentService/Connect"} {
		response, err := client.Get(base + path)
		if err != nil {
			t.Fatalf("the health listener did not answer %s: %v", path, err)
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<16))
		response.Body.Close()
		if response.StatusCode != http.StatusNotFound {
			t.Fatalf("the health listener answered %s with %s", path, response.Status)
		}
	}

	// The port of the agents answers no health question in plain HTTP: the state
	// of the site is not something the network of the site gets to read without a
	// certificate.
	response, err := client.Get("http://" + address + "/healthz")
	if err == nil {
		defer response.Body.Close()
		if response.StatusCode == http.StatusOK {
			t.Fatalf("the port of the agents answered a plain health request with %s", response.Status)
		}
	}
}
