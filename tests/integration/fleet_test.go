//go:build integration

package integration

import (
	"net/http"
	"testing"
	"time"
)

// TestFleetIsEnrolled checks that both hosts reported to the control plane
// and were recognised correctly.
func TestFleetIsEnrolled(t *testing.T) {
	h := newHarness(t)
	hosts := h.hosts()
	if len(hosts) < 2 {
		t.Fatalf("the fleet has %d hosts, expected at least 2", len(hosts))
	}

	families := map[string]hostView{}
	for _, host := range hosts {
		families[host.OSFamily] = host
	}

	t.Run("Debian", func(t *testing.T) {
		host, ok := families["debian"]
		if !ok {
			t.Fatal("no host of the debian family")
		}
		if host.ConnectionState != "online" {
			t.Errorf("connection state = %s, expected online", host.ConnectionState)
		}
		if !hasAdapter(host, "systemd") || !hasAdapter(host, "packages.apt") ||
			!hasAdapter(host, "journald") {
			t.Errorf("unexpected capabilities of the Debian host: %+v", host.Capabilities)
		}
		if hasAdapter(host, "packages.dnf") {
			t.Error("the Debian host should not report dnf")
		}
	})

	t.Run("Fedora", func(t *testing.T) {
		host, ok := families["rhel"]
		if !ok {
			t.Fatal("no host of the rhel family")
		}
		if host.ConnectionState != "online" {
			t.Errorf("connection state = %s, expected online", host.ConnectionState)
		}
		if !hasAdapter(host, "systemd") || !hasAdapter(host, "packages.dnf") ||
			!hasAdapter(host, "journald") {
			t.Errorf("unexpected capabilities of the Fedora host: %+v", host.Capabilities)
		}
		if hasAdapter(host, "packages.apt") {
			t.Error("the Fedora host should not report apt")
		}
	})
}

// TestHealthSignalsAreDeterminedOrEmpty guards that the agent does not turn
// a read error into zero. An empty field is allowed, a made-up value is
// not.
func TestHealthSignalsAreDeterminedOrEmpty(t *testing.T) {
	h := newHarness(t)
	for _, host := range h.hosts() {
		if host.ConnectionState != "online" {
			continue
		}
		// The values are optional, but when present they must make sense.
		if host.FailedUnits != nil && *host.FailedUnits < 0 {
			t.Errorf("%s: negative number of failed units", host.Hostname)
		}
		if host.PendingUpdates != nil && *host.PendingUpdates < 0 {
			t.Errorf("%s: negative number of updates", host.Hostname)
		}
		if host.BootID == "" {
			t.Errorf("%s: no boot_id although the host is online", host.Hostname)
		}
	}
}

// TestMutatingOperationRequiresApproval checks that the order alone changes
// nothing on the host and waits for a human decision.
func TestMutatingOperationRequiresApproval(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	job := h.createOperation(host.ID, map[string]any{
		"action":  "unit.restart",
		"payload": unitPayload("cron.service"),
	})
	if !job.RequiresApproval {
		t.Fatal("a service restart requires no approval")
	}
	if job.State != "awaiting_approval" {
		t.Fatalf("state = %s, expected awaiting_approval", job.State)
	}
	if job.PayloadHash == "" {
		t.Fatal("the plan has no hash")
	}

	// The job waits and does not reach the queue until somebody approves
	// it.
	time.Sleep(4 * time.Second)
	if state := h.job(job.ID).State; state != "awaiting_approval" {
		t.Fatalf("the unapproved job changed its state to %s", state)
	}

	h.do("POST", "/api/v1/jobs/"+job.ID+"/cancel",
		map[string]any{"reason": "cleanup after the test"}, nil, 200)
}

// TestApprovalWithAMismatchedHashIsRejected protects against swapping the
// plan between viewing and approving.
func TestApprovalWithAMismatchedHashIsRejected(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	job := h.createOperation(host.ID, map[string]any{
		"action":  "unit.restart",
		"payload": unitPayload("cron.service"),
	})
	t.Cleanup(func() {
		h.do("POST", "/api/v1/jobs/"+job.ID+"/cancel", map[string]any{"reason": "end of the test"}, nil, 200)
	})

	h.do("POST", "/api/v1/jobs/"+job.ID+"/approve",
		map[string]any{"payload_hash": "0000000000000000000000000000000000000000000000000000000000000000"},
		nil, 409)

	if state := h.job(job.ID).State; state != "awaiting_approval" {
		t.Fatalf("the rejected approval changed the state to %s", state)
	}
}

// TestServiceRestartChangesTheProcess checks the whole path: the plan, the
// approval, execution by the root helper and a result with the unit state
// before and after.
func TestServiceRestartChangesTheProcess(t *testing.T) {
	cases := []struct {
		family string
		unit   string
	}{
		{"debian", "cron.service"},
		{"rhel", "crond.service"},
	}

	for _, tc := range cases {
		t.Run(tc.family, func(t *testing.T) {
			h := newHarness(t)
			host := h.hostByFamily(tc.family)

			job, attempts := h.runOperation(host.ID, map[string]any{
				"action":  "unit.restart",
				"payload": unitPayload(tc.unit),
			}, 90*time.Second)

			if job.State != "succeeded" {
				t.Fatalf("state = %s, error code = %s", job.State, job.ResultErrorCode)
			}
			if len(attempts) == 0 {
				t.Fatal("no recorded execution attempt")
			}
			last := attempts[len(attempts)-1]
			if last.ExitCode == nil || *last.ExitCode != 0 {
				t.Fatalf("exit code = %v, stderr: %s", last.ExitCode, last.Stderr)
			}
			if last.UnitStateBefore == nil || last.UnitStateAfter == nil {
				t.Fatal("no unit state before or after the operation")
			}
			// A PID change is the proof that the restart actually happened,
			// not only returned zero.
			if last.UnitStateBefore.MainPID == last.UnitStateAfter.MainPID {
				t.Errorf("the PID did not change: %d", last.UnitStateAfter.MainPID)
			}
			if last.UnitStateAfter.ActiveState != "active" {
				t.Errorf("the unit after the restart is in state %s", last.UnitStateAfter.ActiveState)
			}
		})
	}
}

// TestJournalReadRequiresNoApproval checks a non-mutating operation.
func TestJournalReadRequiresNoApproval(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "journal.read",
		"payload": map[string]any{
			"journal": map[string]any{"unit": "cron.service", "lines": 5},
		},
	}, 60*time.Second)

	if job.RequiresApproval {
		t.Error("a journal read should not require approval")
	}
	if job.State != "succeeded" {
		t.Fatalf("state = %s, error code = %s", job.State, job.ResultErrorCode)
	}
	if len(attempts) == 0 || attempts[len(attempts)-1].Stdout == "" {
		t.Fatal("the journal read returned no content")
	}
}

// hasAdapter says whether the host reported the given adapter as available.
func hasAdapter(host hostView, name string) bool {
	for _, adapter := range host.Capabilities {
		if adapter.Name == name {
			return adapter.Available
		}
	}
	return false
}

// TestInventoryIsSplitIntoModules checks that a tab can fetch exactly what
// it shows, with its own revision and its own freshness. Earlier all the
// tabs shared one observation date, so an operator looking at packages saw
// the freshness of something else entirely.
func TestInventoryIsSplitIntoModules(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	revisions := map[string]string{}
	for _, module := range []string{"system", "packages", "services", "identity", "accounts", "network"} {
		t.Run(module, func(t *testing.T) {
			var fragment inventoryFragment
			h.do(http.MethodGet, "/api/v1/hosts/"+host.ID+"/inventory/"+module,
				nil, &fragment, http.StatusOK)

			if fragment.Module != module {
				t.Errorf("module = %q, expected %q", fragment.Module, module)
			}
			if fragment.Revision == "" {
				t.Error("module without its own revision")
			}
			// Data without a source cannot be assessed: the operator does
			// not know whether they look at a read from the host or at an
			// hour-old cache.
			if fragment.Source == "" {
				t.Error("the module does not give the source of the read")
			}
			if fragment.ObservedAt.IsZero() {
				t.Error("the module does not give the observation timestamp")
			}
			if len(fragment.Payload) == 0 {
				t.Error("module without content")
			}
			revisions[module] = fragment.Revision
		})
	}

	// Module revisions are independent. If they were all equal, the split
	// would exist only in the address, not in the data.
	seen := map[string]bool{}
	for module, revision := range revisions {
		if seen[revision] {
			t.Errorf("module %s shares its revision with another module", module)
		}
		seen[revision] = true
	}
}

// TestUnreportedModuleIsAMissingResource guards the boundary between an
// empty module and a module the host did not report. These are two
// different answers.
func TestUnreportedModuleIsAMissingResource(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	// The name deliberately matches no module and never will: the boundary
	// concerns the answer for an unreported module, not a specific module
	// that appears next week and topples this test.
	h.do(http.MethodGet, "/api/v1/hosts/"+host.ID+"/inventory/module-that-does-not-exist",
		nil, nil, http.StatusNotFound)
}

// TestContainersModuleIsReportedOnlyWithAnEngine checks that a host without
// a container engine does not pose as a host on which simply nothing runs.
// An empty module and an unavailable module are two different answers.
func TestContainersModuleIsReportedOnlyWithAnEngine(t *testing.T) {
	h := newHarness(t)

	for _, family := range []string{"debian", "rhel"} {
		t.Run(family, func(t *testing.T) {
			host := h.hostByFamily(family)
			hasEngine := hasAdapter(host, "docker")

			var fragment inventoryFragment
			h.do(http.MethodGet, "/api/v1/hosts/"+host.ID+"/inventory/containers",
				nil, &fragment, http.StatusOK)

			if fragment.Source != "agent/docker-engine" {
				t.Errorf("source = %q", fragment.Source)
			}
			if hasEngine && fragment.UnavailableReason != "" {
				t.Errorf("a host with an engine gives an unavailability reason: %q", fragment.UnavailableReason)
			}
			// A host without an engine must say why instead of staying
			// quiet.
			if !hasEngine && fragment.UnavailableReason == "" {
				t.Error("a host without an engine does not explain the missing containers")
			}
		})
	}
}

// TestContainerReadOnDemand checks the path the operator triggers by opening
// the tab: the full lists are fetched by an operation, not in every
// inventory cycle.
func TestContainerReadOnDemand(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	if !hasAdapter(host, "docker") {
		t.Skip("the test host has no container engine")
	}

	job, _ := h.runOperation(host.ID, map[string]any{
		"action":  "docker.read",
		"payload": map[string]any{"docker_read": map[string]any{}},
	}, 90*time.Second)
	if job.State != "succeeded" {
		t.Fatalf("state = %s, code = %s", job.State, job.ResultErrorCode)
	}
	// The read changes nothing, so it cannot require approval.
	if job.RequiresApproval {
		t.Error("the container read requires approval although it changes nothing")
	}

	// The result belongs to the host state, not to the job history: the tab
	// asks for the state and is to get it without browsing operations.
	var full inventoryFragment
	h.do(http.MethodGet, "/api/v1/hosts/"+host.ID+"/inventory/containers.full",
		nil, &full, http.StatusOK)
	if len(full.Payload) == 0 {
		t.Error("the full container state is empty")
	}
}

// TestHostWithoutAnEngineRejectsTheContainerRead guards that an operation
// without backing in an adapter is rejected when ordered, not after
// delivery.
func TestHostWithoutAnEngineRejectsTheContainerRead(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("rhel")
	if hasAdapter(host, "docker") {
		t.Skip("the rhel host has a container engine")
	}
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{"action": "docker.read",
			"payload": map[string]any{"docker_read": map[string]any{}}},
		nil, http.StatusConflict)
}

// TestDestructiveOperationRequiresTargetConfirmation checks the gate from
// chapter 6.1: a change that cannot be undone must not be ordered with a
// click. The operator must give a reason and type in the hostname.
func TestDestructiveOperationRequiresTargetConfirmation(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	if !hasAdapter(host, "docker") {
		t.Skip("the test host has no container engine")
	}
	const container = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	// Without a reason the operation cannot be created: the reason stays in
	// the audit log.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{
			"action":  "docker.container.remove",
			"payload": map[string]any{"docker_container": map[string]any{"container_id": container}},
		}, nil, http.StatusBadRequest)

	// With a reason, but without the hostname typed in - still a refusal.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{
			"action":  "docker.container.remove",
			"reason":  "lab cleanup",
			"payload": map[string]any{"docker_container": map[string]any{"container_id": container}},
		}, nil, http.StatusBadRequest)

	// Another host's name is no confirmation of this host.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{
			"action":              "docker.container.remove",
			"reason":              "lab cleanup",
			"target_confirmation": "entirely-different-host",
			"payload":             map[string]any{"docker_container": map[string]any{"container_id": container}},
		}, nil, http.StatusBadRequest)
}

// TestReversibleOperationRequiresNoTypedName guards that the gate did not
// spill over everything. A container restart is reversible and is to go
// with one click, like any other operation.
func TestReversibleOperationRequiresNoTypedName(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	if !hasAdapter(host, "docker") {
		t.Skip("the test host has no container engine")
	}
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{
			"action": "docker.container.start",
			"payload": map[string]any{"docker_container": map[string]any{
				"container_id": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			}},
		}, nil, http.StatusCreated)
}

// TestInvalidContainerTargetIsRejected checks the validation on the API
// side. The identifier goes into the Engine API request path, so it must
// not carry anything that changes that path.
func TestInvalidContainerTargetIsRejected(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	if !hasAdapter(host, "docker") {
		t.Skip("the test host has no container engine")
	}
	for _, id := range []string{"my-container", "../images/json", "abc", ""} {
		h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
			map[string]any{
				"action":  "docker.container.stop",
				"payload": map[string]any{"docker_container": map[string]any{"container_id": id}},
			}, nil, http.StatusBadRequest)
	}
}

// TestProjectDeploymentRequiresAnApprovedPlan checks the boundary from
// chapter 7: deploying a manifest starts the images named by the operator
// on the host, so it must not be ordered without a plan that operator
// looked at.
func TestProjectDeploymentRequiresAnApprovedPlan(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	if !hasAdapter(host, "docker.compose") {
		t.Skip("the test host has no compose plugin")
	}
	const manifest = "services:\n  web:\n    image: nginx:alpine\n"

	// Without the plan hash the deployment has no basis.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{
			"action": "docker.compose.deploy",
			"reason": "deployment of the test project",
			"payload": map[string]any{"compose": map[string]any{
				"project": "testproject", "manifest": manifest,
			}},
		}, nil, http.StatusBadRequest)

	// Planning changes nothing, so it requires neither a reason nor an
	// approval.
	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "docker.compose.plan",
		"payload": map[string]any{"compose": map[string]any{
			"project": "testproject", "manifest": manifest,
		}},
	}, 2*time.Minute)
	if job.State != "succeeded" {
		t.Fatalf("plan: state = %s, code = %s", job.State, job.ResultErrorCode)
	}
	if job.RequiresApproval {
		t.Error("project planning requires approval although it changes nothing")
	}
	if len(attempts) == 0 || attempts[len(attempts)-1].Detail == nil {
		t.Fatal("the plan returned no result")
	}
}

// TestInvalidProjectIsRejected checks the validation on the API side. The
// project name goes into a command argument and into container names.
func TestInvalidProjectIsRejected(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	if !hasAdapter(host, "docker.compose") {
		t.Skip("the test host has no compose plugin")
	}
	for _, project := range []string{"", "Shop", "shop;reboot", "../etc"} {
		h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
			map[string]any{
				"action": "docker.compose.plan",
				"payload": map[string]any{"compose": map[string]any{
					"project": project, "manifest": "services: {}",
				}},
			}, nil, http.StatusBadRequest)
	}
	// An empty manifest is not a project either.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{
			"action": "docker.compose.plan",
			"payload": map[string]any{"compose": map[string]any{
				"project": "shop", "manifest": "   ",
			}},
		}, nil, http.StatusBadRequest)
}
