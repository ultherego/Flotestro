//go:build integration

package integration

import (
	"net/http"
	"sync"
	"testing"
	"time"
)

// refreshResult is the attempt detail of an inventory.refresh operation.
type refreshResult struct {
	Kind     string   `json:"kind"`
	Revision string   `json:"revision"`
	Changed  bool     `json:"changed"`
	Modules  []string `json:"modules"`
}

type revisionView struct {
	Revision   string    `json:"revision"`
	ObservedAt time.Time `json:"observed_at"`
}

type fragmentView struct {
	Module     string    `json:"module"`
	Revision   string    `json:"revision"`
	ObservedAt time.Time `json:"observed_at"`
}

const refreshReason = "integration test of the inventory refresh"

// TestInventoryRefreshIsSettledByARevision guards the rule of the operation:
// the job succeeds only once the panel holds the revision the agent talks
// about. Merely accepting the job proves nothing - until now the operator
// clicked "refresh" and did not know whether the panel received anything.
func TestInventoryRefreshIsSettledByARevision(t *testing.T) {
	h := newHarness(t)

	for _, family := range []string{"debian", "rhel"} {
		t.Run(family, func(t *testing.T) {
			host := h.hostByFamily(family)
			before := hostRevision(t, h, host.ID)
			ordered := time.Now()

			job, attempts := h.runOperation(host.ID, map[string]any{
				"action": "inventory.refresh", "reason": refreshReason,
			}, 3*time.Minute)
			if job.State != "succeeded" {
				t.Fatalf("refresh: state = %s, %s", job.State, lastMessage(attempts))
			}

			result := jobRefreshResult(t, h, job.ID)
			if result.Kind != "inventory_refresh" {
				t.Fatalf("result kind = %q", result.Kind)
			}
			if result.Revision == "" {
				t.Fatal("the agent gave no revision")
			}
			if len(result.Modules) != 0 {
				t.Errorf("a full refresh reported the scope %v", result.Modules)
			}

			after := hostRevision(t, h, host.ID)
			if after.Revision != result.Revision {
				t.Errorf("the panel holds revision %s, the agent reported %s", after.Revision, result.Revision)
			}
			// The read is to be fresh, not an answer from memory: the revision
			// may repeat when nothing changed, but the observation must come
			// from after the order.
			if !after.ObservedAt.After(ordered) {
				t.Errorf("observation from %s, job ordered at %s", after.ObservedAt, ordered)
			}
			if after.ObservedAt.Before(before.ObservedAt) {
				t.Errorf("the observation went backwards: %s before %s", after.ObservedAt, before.ObservedAt)
			}
		})
	}
}

// TestScopedRefreshDoesNotLoseTheOtherModules guards the most dangerous
// partial-read bug: a host that refreshed one module must not look like a
// host without the rest of its inventory.
func TestScopedRefreshDoesNotLoseTheOtherModules(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	outside := hostFragment(t, h, host.ID, "services")
	if outside.Revision == "" {
		t.Skip("the host has no services fragment yet")
	}
	ordered := time.Now()

	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "inventory.refresh", "reason": refreshReason,
		"payload": map[string]any{"inventory": map[string]any{"modules": []string{"packages"}}},
	}, 3*time.Minute)
	if job.State != "succeeded" {
		t.Fatalf("scoped refresh: state = %s, %s", job.State, lastMessage(attempts))
	}

	result := jobRefreshResult(t, h, job.ID)
	if len(result.Modules) != 1 || result.Modules[0] != "packages" {
		t.Fatalf("scope in the result = %v", result.Modules)
	}

	packages := hostFragment(t, h, host.ID, "packages")
	if !packages.ObservedAt.After(ordered) {
		t.Errorf("packages observed at %s, job ordered at %s", packages.ObservedAt, ordered)
	}
	outsideAfter := hostFragment(t, h, host.ID, "services")
	if outsideAfter.Revision == "" {
		t.Fatal("the package refresh wiped the services fragment")
	}
}

// TestConcurrentRefreshesEndWithARevision checks that jobs ordered side by
// side share one read instead of cancelling each other out. Each is to get
// the revision the panel really saved.
func TestConcurrentRefreshesEndWithARevision(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	const concurrent = 3
	results := make([]refreshResult, concurrent)
	states := make([]string, concurrent)
	messages := make([]string, concurrent)

	var group sync.WaitGroup
	for i := range concurrent {
		group.Add(1)
		go func() {
			defer group.Done()
			job, attempts := h.runOperation(host.ID, map[string]any{
				"action": "inventory.refresh", "reason": refreshReason,
			}, 3*time.Minute)
			states[i] = job.State
			messages[i] = lastMessage(attempts)
			if job.State == "succeeded" {
				results[i] = jobRefreshResult(t, h, job.ID)
			}
		}()
	}
	group.Wait()

	for i := range concurrent {
		if states[i] != "succeeded" {
			t.Fatalf("refresh %d: state = %s, %s", i, states[i], messages[i])
		}
		if results[i].Revision == "" {
			t.Errorf("refresh %d without a revision", i)
		}
	}
}

func hostRevision(t *testing.T, h *harness, hostID string) revisionView {
	t.Helper()
	var revision revisionView
	h.do(http.MethodGet, "/api/v1/hosts/"+hostID+"/inventory", nil, &revision, http.StatusOK)
	return revision
}

func hostFragment(t *testing.T, h *harness, hostID, module string) fragmentView {
	t.Helper()
	var fragment fragmentView
	h.do(http.MethodGet, "/api/v1/hosts/"+hostID+"/inventory/"+module, nil, &fragment, http.StatusOK)
	return fragment
}

func jobRefreshResult(t *testing.T, h *harness, jobID string) refreshResult {
	t.Helper()
	var response struct {
		Items []struct {
			Detail refreshResult `json:"detail"`
		} `json:"items"`
	}
	h.do(http.MethodGet, "/api/v1/jobs/"+jobID+"/attempts", nil, &response, http.StatusOK)
	if len(response.Items) == 0 {
		t.Fatal("job without attempts")
	}
	return response.Items[len(response.Items)-1].Detail
}
