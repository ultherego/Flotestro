//go:build integration

package integration

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/agent"
)

// TestSimulatedAgentsCarryOutDifferentOrders keeps a handful of real agents
// (the agent's own code, over a machine in memory) against the panel and orders
// each a different change: the whole path - order, consent, dispatch, lease,
// execution, verification, signed acknowledgement, result - runs without a
// host, and no two orders compete for one resource.
func TestSimulatedAgentsCarryOutDifferentOrders(t *testing.T) {
	h := newHarness(t)
	const fleet = 6

	var order struct {
		Token string `json:"token"`
	}
	h.do(http.MethodPost, "/api/v1/enrollment-requests", map[string]any{
		"description": "simulated agents", "reason": "integration test", "site": "lab",
		"environment": "test", "max_uses": fleet, "ttl_minutes": 30,
	}, &order, http.StatusCreated)

	ctx, stop := context.WithCancel(context.Background())
	t.Cleanup(stop)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	prefix := uniqueSubject("sim")

	machines := make([]*agent.SimulatedHost, fleet)
	hostnames := make([]string, fleet)
	var running sync.WaitGroup
	t.Cleanup(running.Wait)
	for i := range machines {
		hostname := fmt.Sprintf("%s-%02d", prefix, i)
		hostnames[i] = hostname
		machineID := fmt.Sprintf("%032x", time.Now().UnixNano()+int64(i))
		dir := t.TempDir()

		identity, err := agent.EnsureIdentityFor(ctx, agent.IdentityRequest{
			StateDir:        dir,
			EnrollmentURL:   envOr("FLOTESTRO_TEST_ENROLLMENT", defaultEnrollment),
			Token:           order.Token,
			BootstrapCAPath: envOr("FLOTESTRO_TEST_CA", "/var/lib/flotestro/ca.pem"),
			MachineID:       machineID, Hostname: hostname,
			OSFamily: "debian", OSVersion: "13", Architecture: "amd64",
		})
		if err != nil {
			t.Fatalf("enrolling the simulated agent %d: %v", i, err)
		}
		facts := agent.SimulatedFacts(hostname, machineID, true)
		machines[i] = &agent.SimulatedHost{}
		executor, err := agent.NewSimulatedExecutor(machines[i], dir+"/journal",
			func() agent.Facts { return facts }, log)
		if err != nil {
			t.Fatal(err)
		}
		running.Add(1)
		go func() {
			defer running.Done()
			_ = agent.Run(ctx, agent.SessionOptions{
				GatewayURLs:  []string{envOr("FLOTESTRO_TEST_GATEWAY", defaultGateway)},
				Identity:     identity,
				CollectFacts: func(context.Context) (agent.Facts, error) { return facts, nil },
				Executor:     executor, MaxConcurrentTasks: 1, Log: log,
			})
		}()
	}
	t.Cleanup(stop)

	// The hosts are in the fleet once the panel lists them online.
	ids := map[string]string{}
	deadline := time.Now().Add(2 * time.Minute)
	for len(ids) < fleet {
		for _, host := range h.hosts() {
			for _, name := range hostnames {
				if host.Hostname == name && host.ConnectionState == "online" && ids[name] == "" {
					ids[name] = host.ID
					h.forgetHostOnCleanup(host.ID)
				}
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d of %d simulated agents came online", len(ids), fleet)
		}
		time.Sleep(time.Second)
	}

	// Every host is ordered a key of its own.
	var group sync.WaitGroup
	for i, name := range hostnames {
		group.Add(1)
		go func() {
			defer group.Done()
			key := "user.sim_" + strconv.Itoa(i) + "_" + prefix[len(prefix)-6:]
			job, attempts := h.runOperation(ids[name], map[string]any{
				"action": "sysctl.ensure", "reason": "simulated agents test",
				"payload": map[string]any{"kernel": map[string]any{
					"settings": map[string]string{key: strconv.Itoa(i + 1)}}},
			}, 2*time.Minute)
			if job.State != "succeeded" {
				t.Errorf("agent %d: state = %s, %s", i, job.State, lastMessage(attempts))
			}
		}()
	}
	group.Wait()

	// A change refreshes the inventory of its module; an agent with substituted
	// facts must not report the machine it runs on, or the panel renames the host.
	time.Sleep(5 * time.Second)
	for _, host := range h.hosts() {
		for _, name := range hostnames {
			if ids[name] == host.ID && host.Hostname != name {
				t.Errorf("host %s was renamed to %q after its change", name, host.Hostname)
			}
		}
	}

	for i := range machines {
		key := "user.sim_" + strconv.Itoa(i) + "_" + prefix[len(prefix)-6:]
		if value, _ := machines[i].Sysctl(key); value != strconv.Itoa(i+1) {
			t.Errorf("agent %d holds %q under its own key, want %d", i, value, i+1)
		}
		for j := range machines {
			other := "user.sim_" + strconv.Itoa(j) + "_" + prefix[len(prefix)-6:]
			if _, found := machines[i].Sysctl(other); found && j != i {
				t.Errorf("agent %d holds the key ordered to agent %d", i, j)
			}
		}
	}
}
