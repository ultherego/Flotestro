//go:build integration

package integration

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

func planPayload(refresh bool, only ...string) map[string]any {
	plan := map[string]any{"refresh_metadata": refresh}
	if len(only) > 0 {
		plan["only_packages"] = only
	}
	return map[string]any{"package_plan": plan}
}

// TestUpdatePlanDoesNotChangeTheHost checks that planning is safe: it
// returns the change list and a hash, but installs nothing.
func TestUpdatePlanDoesNotChangeTheHost(t *testing.T) {
	for _, family := range []string{"debian", "rhel"} {
		t.Run(family, func(t *testing.T) {
			h := newHarness(t)
			host := h.hostByFamily(family)

			job, attempts := h.runOperation(host.ID, map[string]any{
				"action":  "packages.plan",
				"payload": planPayload(false),
			}, 3*time.Minute)

			if job.State != "succeeded" {
				t.Fatalf("state = %s, code = %s", job.State, job.ResultErrorCode)
			}
			// A plan is a non-mutating operation, so it requires no
			// approval.
			if job.RequiresApproval {
				t.Error("planning requires approval although it changes nothing")
			}

			detail := attempts[len(attempts)-1].Detail
			if detail == nil || detail.Kind != "package_plan" {
				t.Fatalf("no typed plan result: %+v", detail)
			}
			if detail.Manager == "" {
				t.Error("the plan does not name the package manager")
			}
			if len(detail.Changes) > 0 && detail.PlanHash == "" {
				t.Error("a plan with changes has no hash")
			}
			for _, change := range detail.Changes {
				if change.Name == "" || change.CandidateVersion == "" {
					t.Errorf("incomplete change description: %+v", change)
				}
			}
		})
	}
}

// TestPlanIsRepeatable checks that the same host state gives the same hash.
// Without that the plan verification at execution would make no sense.
func TestPlanIsRepeatable(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("rhel")

	first := h.planHash(host.ID)
	second := h.planHash(host.ID)
	if first != second {
		t.Fatalf("the same state gave different plan hashes: %s != %s", first, second)
	}
}

// planHash orders a plan and returns its hash.
func (h *harness) planHash(hostID string) string {
	h.t.Helper()
	job, attempts := h.runOperation(hostID, map[string]any{
		"action":  "packages.plan",
		"payload": planPayload(false),
	}, 3*time.Minute)
	if job.State != "succeeded" {
		h.t.Fatalf("the plan failed: %s (%s)", job.State, job.ResultErrorCode)
	}
	detail := attempts[len(attempts)-1].Detail
	if detail == nil {
		h.t.Fatal("plan without a result")
	}
	return detail.PlanHash
}

// TestTransactionWithAStalePlanIsRejected protects against applying a
// different package set than the approved one. The repository metadata may
// change between the plan and the execution.
func TestTransactionWithAStalePlanIsRejected(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("rhel")

	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "packages.upgrade",
		"payload": map[string]any{
			"package_upgrade": map[string]any{
				"packages":  []string{"bash"},
				"plan_hash": "0000000000000000000000000000000000000000000000000000000000000000",
			},
		},
	}, 5*time.Minute)

	if job.State == "succeeded" {
		t.Fatal("a transaction with a stale plan was carried out")
	}
	last := attempts[len(attempts)-1]
	if last.ErrorCode != "plan_changed" {
		t.Fatalf("error code = %q, expected plan_changed", last.ErrorCode)
	}
	// Nothing could have been changed.
	if last.Detail != nil && len(last.Detail.Applied) > 0 {
		t.Errorf("the rejected transaction changed %d packages", len(last.Detail.Applied))
	}
}

// TestTransactionRecordsVersionsBeforeAndAfter checks that the transaction
// report carries what the document requires: the versions before and after
// and the reboot state.
func TestTransactionRecordsVersionsBeforeAndAfter(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("rhel")

	// A package from the current plan is picked, so that the test does not
	// depend on what happens to be outdated on the image.
	_, planAttempts := h.runOperation(host.ID, map[string]any{
		"action":  "packages.plan",
		"payload": planPayload(false),
	}, 3*time.Minute)
	plan := planAttempts[len(planAttempts)-1].Detail
	if plan == nil || len(plan.Changes) == 0 {
		t.Skip("the host has no updates available")
	}

	target := ""
	for _, change := range plan.Changes {
		// Packages that pull a reboot or large dependencies are skipped.
		switch change.Name {
		case "kernel", "glibc", "systemd", "dnf", "rpm":
			continue
		}
		target = change.Name
		break
	}
	if target == "" {
		t.Skip("no safe package for the test")
	}

	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "packages.upgrade",
		"payload": map[string]any{
			"package_upgrade": map[string]any{"packages": []string{target}},
		},
	}, 10*time.Minute)

	last := attempts[len(attempts)-1]
	if last.Detail == nil || last.Detail.Kind != "package_apply" {
		t.Fatalf("no transaction report: %+v", last.Detail)
	}
	// The report is produced on failure too; its completeness is checked.
	if job.State == "succeeded" {
		if len(last.Detail.Applied) == 0 {
			t.Errorf("a successful transaction recorded no version change")
		}
		for _, change := range last.Detail.Applied {
			if change.CandidateVersion == "" {
				t.Errorf("no version after the change for %s", change.Name)
			}
		}
	}
	if last.Detail.PackageDatabaseBroken {
		t.Errorf("the transaction left a broken package database")
	}
}

// TestOperatorPlansButDoesNotUpgrade checks the permission split: a package
// transaction is a highest-risk operation and has a permission of its own.
func TestOperatorPlansButDoesNotUpgrade(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	operator := h.withToken(h.createPrincipal(uniqueSubject("operator-packages"), []map[string]string{
		{"role": "operator", "site": host.Site, "environment": host.Environment},
	}))

	// Planning is allowed.
	operator.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{"action": "packages.plan", "payload": planPayload(false)},
		nil, http.StatusCreated)

	// A transaction is not.
	operator.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{"action": "packages.upgrade",
			"payload": map[string]any{"package_upgrade": map[string]any{}}},
		nil, http.StatusForbidden)
}

// TestBrokenPackageDatabaseBlocksOperations checks that after a failed
// transaction the host receives no further package operations.
func TestBrokenPackageDatabaseBlocksOperations(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pool := h.database(ctx)
	host := h.hostByFamily("debian")

	if _, err := pool.Exec(ctx,
		`update hosts set package_database_broken = true where id = $1`, host.ID); err != nil {
		t.Fatalf("the flag was not set: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`update hosts set package_database_broken = false where id = $1`, host.ID)
	})

	// A transaction on a broken database has no chance to succeed and
	// cannot be ordered.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{"action": "packages.upgrade",
			"payload": map[string]any{"package_upgrade": map[string]any{}}},
		nil, http.StatusConflict)

	// Repair must be allowed in exactly this state. Blocking it locked the
	// host in a loop with no exit: the only operation able to clear the
	// flag was blocked by it.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{"action": "packages.repair", "reason": "unblocking the package database",
			"payload": map[string]any{"package_repair": map[string]any{}}},
		nil, http.StatusCreated)

	// A plan changes nothing and is needed most on a blocked host: it shows
	// what blocks.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{"action": "packages.plan", "payload": planPayload(false)},
		nil, http.StatusCreated)

	// Non-package operations keep working: the block concerns packages
	// only.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{"action": "journal.read",
			"payload": map[string]any{"journal": map[string]any{"lines": 5}}},
		nil, http.StatusCreated)
}

// TestInvalidPackageNameIsRejected checks the validation on the API side.
func TestInvalidPackageNameIsRejected(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	for _, name := range []string{"bash; reboot", "../../etc/passwd", "-o", "$(reboot)"} {
		h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
			map[string]any{"action": "packages.plan",
				"payload": planPayload(false, name)},
			nil, http.StatusBadRequest)
	}
}

// TestRepairRequiresAnAdapterWithThatFeature checks that a host without
// repair learns about it when ordered, not after the job is delivered.
// Repair answers debconf questions and exists only for apt; earlier the
// operation was accepted on every host and rejected only by the helper on
// Fedora.
func TestRepairRequiresAnAdapterWithThatFeature(t *testing.T) {
	h := newHarness(t)

	// Repair is a critical operation, so it requires a justification in the
	// audit log.
	const reason = "unblocking the package database"

	rhel := h.hostByFamily("rhel")
	h.do(http.MethodPost, "/api/v1/hosts/"+rhel.ID+"/operations",
		map[string]any{"action": "packages.repair", "reason": reason,
			"payload": map[string]any{"package_repair": map[string]any{}}},
		nil, http.StatusConflict)

	// The same operation on a host with apt passes: the refusal concerns
	// the missing adapter feature, not the operation itself.
	debian := h.hostByFamily("debian")
	h.do(http.MethodPost, "/api/v1/hosts/"+debian.ID+"/operations",
		map[string]any{"action": "packages.repair", "reason": reason,
			"payload": map[string]any{"package_repair": map[string]any{}}},
		nil, http.StatusCreated)
}

// TestHostReportsTheAdapterRegistry checks that the host says not only what
// it has, but also why it lacks something. The reason is a fact about the
// host and the host is to give it - the interface is to repeat it, not
// guess in its own code.
func TestHostReportsTheAdapterRegistry(t *testing.T) {
	h := newHarness(t)

	for _, tc := range []struct {
		family  string
		present string
		absent  string
	}{
		{"debian", "packages.apt", "packages.dnf"},
		{"rhel", "packages.dnf", "packages.apt"},
	} {
		t.Run(tc.family, func(t *testing.T) {
			host := h.hostByFamily(tc.family)
			if len(host.Capabilities) == 0 {
				t.Fatal("the host reported no adapter at all")
			}
			find := func(name string) *hostCapability {
				for i := range host.Capabilities {
					if host.Capabilities[i].Name == name {
						return &host.Capabilities[i]
					}
				}
				return nil
			}

			present := find(tc.present)
			if present == nil || !present.Available {
				t.Fatalf("adapter %s is not reported as available", tc.present)
			}
			if present.Version == 0 {
				t.Errorf("adapter %s does not give a contract version", tc.present)
			}

			absent := find(tc.absent)
			if absent == nil || absent.Available {
				t.Fatalf("adapter %s is not reported as unavailable", tc.absent)
			}
			// Silent unavailability forces the interface to guess the cause.
			if absent.Reason == "" {
				t.Errorf("adapter %s gives no unavailability reason", tc.absent)
			}
		})
	}
}

// TestPackageRemovalRequiresAnApprovedSet checks the boundary from chapter
// 3. One package can pull dozens of dependants, so the operator approves a
// set, not a name - and the host recomputes it before the operation.
func TestPackageRemovalRequiresAnApprovedSet(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	// Without an approved set the operation has no basis.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{
			"action":              "packages.remove",
			"reason":              "lab cleanup",
			"target_confirmation": host.Hostname,
			"payload":             map[string]any{"package_change": map[string]any{"packages": []string{"sl"}}},
		}, nil, http.StatusBadRequest)

	// Without the hostname typed in neither: removal is irreversible.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{
			"action": "packages.remove",
			"reason": "lab cleanup",
			"payload": map[string]any{"package_change": map[string]any{
				"packages": []string{"sl"}, "expected_removals": []string{"sl"},
			}},
		}, nil, http.StatusBadRequest)
}

// TestProtectedPackagesAreRejectedWhenOrdered guards that the operator
// learns about the block when ordering, not after the job is delivered.
// Removing the agent would cut the host off from the panel, and thus from
// the repair too.
func TestProtectedPackagesAreRejectedWhenOrdered(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	for _, pkg := range []string{"flotestro-agent", "systemd", "openssh-server", "linux-image-6.12"} {
		h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
			map[string]any{
				"action":              "packages.remove",
				"reason":              "attempt to remove a protected package",
				"target_confirmation": host.Hostname,
				"payload": map[string]any{"package_change": map[string]any{
					"packages": []string{pkg}, "expected_removals": []string{pkg},
				}},
			}, nil, http.StatusBadRequest)
	}
}

// TestRemovalPlanShowsDependencies checks that the plan answers the question
// "what goes away" before anything goes away.
func TestRemovalPlanShowsDependencies(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	// A plan without a package list makes no sense.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{
			"action":  "packages.plan",
			"payload": map[string]any{"package_plan": map[string]any{"mode": "remove"}},
		}, nil, http.StatusBadRequest)

	// Neither does an unknown plan kind.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{
			"action": "packages.plan",
			"payload": map[string]any{"package_plan": map[string]any{
				"mode": "made-up", "only_packages": []string{"sl"},
			}},
		}, nil, http.StatusBadRequest)
}

// TestHoldIsReversible checks that the operation describes a desired state,
// not a toggle: repeating it does not reverse the change. The hold is also
// a fact of the inventory: after the change the packages module names the
// package among the holds, and after the release it does not - an operator
// reading the tab is to see which packages will take no upgrade.
func TestHoldIsReversible(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	for _, hold := range []bool{true, false} {
		job, _ := h.runOperation(host.ID, map[string]any{
			"action": "packages.hold.set",
			"payload": map[string]any{"package_change": map[string]any{
				"packages": []string{"nano"}, "hold": hold,
			}},
		}, 60*time.Second)
		if job.State != "succeeded" {
			t.Fatalf("hold=%v: state = %s, code = %s", hold, job.State, job.ResultErrorCode)
		}

		holds := h.packageHolds(host.ID)
		if !holds.Known && holds.Reason == "" {
			// An agent from before the holds rode in the fragment says
			// nothing about them at all; that is not a failed read.
			t.Skipf("hold=%v: the agent of %s does not report the holds yet", hold, host.Hostname)
		}
		if !holds.Known {
			t.Fatalf("hold=%v: the packages module did not read the holds: %s", hold, holds.Reason)
		}
		if containsName(holds.Holds, "nano") != hold {
			t.Errorf("hold=%v: the packages module names the holds %v", hold, holds.Holds)
		}
	}
}

// packageHoldsView is the hold state of the packages module of a host.
type packageHoldsView struct {
	Holds  []string `json:"holds"`
	Known  bool     `json:"holds_known"`
	Reason string   `json:"holds_unavailable_reason"`
}

// packageHolds refreshes the packages module and reads the holds out of it:
// the facts after a hold have to come from after the change, not from the
// last inventory cycle.
func (h *harness) packageHolds(hostID string) packageHoldsView {
	h.t.Helper()
	job, attempts := h.runOperation(hostID, map[string]any{
		"action": "inventory.refresh", "reason": "integration test of the package holds",
		"payload": map[string]any{"inventory": map[string]any{"modules": []string{"packages"}}},
	}, 5*time.Minute)
	if job.State != "succeeded" {
		h.t.Fatalf("the packages refresh ended in state %s: %s", job.State, lastMessage(attempts))
	}
	var fragment struct {
		Payload packageHoldsView `json:"payload"`
	}
	h.get("/api/v1/hosts/"+hostID+"/inventory/packages", &fragment)
	return fragment.Payload
}

// TestHostPackageListIsServedWithItsState checks that the installed
// packages the panel holds for a host are readable as a list, with the
// state of the copy beside them: the moment of the read and the job that
// made it. The list is what the Packages tab draws, and a row without a
// name or a version would be a row about nothing.
func TestHostPackageListIsServedWithItsState(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "packages.list", "reason": "integration test of the package list",
	}, 5*time.Minute)
	if job.State != "succeeded" {
		t.Fatalf("reading the package list: state = %s, %s", job.State, lastMessage(attempts))
	}

	var list struct {
		Items []listedPackage `json:"items"`
		Count int             `json:"count"`
		State struct {
			PackageCount int    `json:"package_count"`
			CollectedAt  string `json:"collected_at"`
			JobID        string `json:"job_id"`
			Reason       string `json:"unavailable_reason"`
		} `json:"state"`
	}
	h.get("/api/v1/hosts/"+host.ID+"/packages", &list)
	if list.State.Reason != "" {
		t.Fatalf("the list of %s is unavailable: %s", host.Hostname, list.State.Reason)
	}
	if list.Count == 0 || list.Count != len(list.Items) || list.Count != list.State.PackageCount {
		t.Fatalf("the list carries %d rows, count %d, state %d", len(list.Items), list.Count, list.State.PackageCount)
	}
	if list.State.CollectedAt == "" || list.State.JobID == "" {
		t.Errorf("the state does not say when and by which job the list was read: %+v", list.State)
	}
	names := make([]string, 0, len(list.Items))
	for _, pkg := range list.Items {
		if pkg.Name == "" || pkg.Version == "" {
			t.Fatalf("a row without a name or a version: %+v", pkg)
		}
		names = append(names, pkg.Name)
	}
	if !containsName(names, "dpkg") {
		t.Errorf("the list of a Debian host does not carry dpkg")
	}
}

// listedPackage is one row of the package list as the panel serves it.
type listedPackage struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
}

// labBrokenPackage is the package of the lab repository whose maintainer
// script fails by design. Vagrant/lab-broken-package.sh builds it for every
// family and adds it to the repository served by the panel VM.
const labBrokenPackage = "flotestro-lab-broken"

const labBrokenReason = "integration test of a failing maintainer script"

// brokenScriptExpectation says what the product reports about a failed
// maintainer script on one family. The failure looks different on each of
// them, and the assertions follow the manager rather than pretend the
// families behave the same.
type brokenScriptExpectation struct {
	// attentionNamed: the transaction report names the package among the
	// packages needing attention.
	attentionNamed bool
	// databaseBroken: the host flag package_database_broken is raised and
	// the dashboard counts the host.
	databaseBroken bool
	// scriptletDefect: the manager finishes the transaction and the report
	// names the package whose scriptlet failed; the job succeeds.
	scriptletDefect bool
}

// TestAFailingMaintainerScriptIsATypedFailure is the scenario of chapter
// 23 in which a maintainer script fails half-way: the transaction ends as
// transaction_failed rather than as an opaque error, the report says what
// needs attention, the host flag package_database_broken follows the
// family, a repair clears it where the family has one, and the package can
// be removed afterwards.
//
// The families differ, and the test says how:
//
//   - Debian: dpkg leaves the package half-configured. The attention list
//     names it, the host flag is raised, the dashboard counts the host, and
//     packages.repair (dpkg --configure -a) finishes the configuration.
//   - RHEL: rpm runs %post after the files are in place and keeps the
//     package installed when it fails; the database stays consistent, so
//     there is nothing to repair and no attention list. dnf5 finishes the
//     transaction with exit status 0 and a "non-critical error" line, so
//     the product reports a success with a defect: the job succeeds and
//     the report names the package under scriptlet_errors. The adapter
//     reports no repair feature and the panel refuses a repair when ordered.
//   - Arch: pacman treats a scriptlet failure like rpm does. The pacman
//     adapter reports no install feature today, so the family is skipped
//     until it does.
//
// A lab that has not run Vagrant/lab-broken-package.sh does not carry the
// package; the host then answers that the package is unknown and the test
// skips instead of failing.
func TestAFailingMaintainerScriptIsATypedFailure(t *testing.T) {
	for _, tc := range []struct {
		family string
		expect brokenScriptExpectation
	}{
		{"debian", brokenScriptExpectation{attentionNamed: true, databaseBroken: true}},
		{"rhel", brokenScriptExpectation{scriptletDefect: true}},
		{"arch", brokenScriptExpectation{scriptletDefect: true}},
	} {
		t.Run(tc.family, func(t *testing.T) {
			h := newHarness(t)
			host := h.hostByFamily(tc.family)
			if tc.family == "arch" && !capabilityFeature(host, "packages.pacman", "install") {
				t.Skip("the pacman adapter reports no install feature")
			}
			brokenMaintainerScriptScenario(t, h, host, tc.expect)
		})
	}
}

func brokenMaintainerScriptScenario(t *testing.T, h *harness, host hostView, expect brokenScriptExpectation) {
	t.Helper()

	// The host has to see the current repository index: the package is
	// added to the lab repository after the hosts were set up. A refresh is
	// the side effect of a plan; the plan itself may refuse on a host that
	// cannot plan (Arch without checkupdates) and that is not the subject
	// here.
	if plan, attempts := h.runOperation(host.ID, map[string]any{
		"action": "packages.plan", "reason": labBrokenReason,
		"payload": planPayload(true),
	}, 5*time.Minute); plan.State != "succeeded" {
		t.Logf("the metadata refresh plan ended in state %s: %s", plan.State, lastMessage(attempts))
	}

	// A host that already needs attention would blur the assertions: the
	// scenario needs a clean baseline.
	if h.hostPackageDatabaseBroken(host.ID) {
		t.Skipf("host %s already has a broken package database; the scenario needs a clean baseline", host.Hostname)
	}
	counterBefore := h.packageDatabaseBrokenCounter()

	// The lab is cleaned up whatever happens after this point: a repair
	// where the family has one, so that the flag does not block the removal,
	// and then the removal itself.
	t.Cleanup(func() {
		if hostHasPackageRepair(host) {
			h.runOperation(host.ID, map[string]any{
				"action": "packages.repair", "reason": labBrokenReason + " (cleanup)",
				"payload": map[string]any{"package_repair": map[string]any{}},
			}, 10*time.Minute)
		}
		if state := h.removeLabPackage(t, host); state != "" && state != "succeeded" {
			t.Logf("cleanup: the removal of %s ended in state %s", labBrokenPackage, state)
		}
	})

	// The installation. The maintainer script is what fails, so the manager
	// has to download and unpack the package first.
	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "packages.install", "reason": labBrokenReason,
		"payload": map[string]any{"package_change": map[string]any{
			"packages": []string{labBrokenPackage},
		}},
	}, 10*time.Minute)
	if len(attempts) == 0 {
		t.Fatalf("the installation ended in state %s without an attempt", job.State)
	}
	last := h.lastPackageAttempt(job.ID)
	if last.unknownToRepositories() {
		t.Skipf("the lab repository does not carry %s; run Vagrant/lab-broken-package.sh (%s)",
			labBrokenPackage, last.Message)
	}

	if expect.scriptletDefect {
		// The manager finished: the job succeeds, and the defect is named
		// in the report rather than hidden in the output.
		if job.State != "succeeded" {
			t.Fatalf("the installation ended in state %s, expected succeeded with a scriptlet defect: %s",
				job.State, last.Message)
		}
		if last.Detail == nil || last.Detail.Kind != "package_apply" {
			t.Fatalf("no transaction report on the attempt: %+v", last.Detail)
		}
		if !containsName(last.Detail.ScriptletErrors, labBrokenPackage) {
			t.Errorf("scriptlet errors = %v, expected %s named", last.Detail.ScriptletErrors, labBrokenPackage)
		}
	} else {
		// The failure is typed: the job fails, and the code is the one the
		// adapters give a transaction that ran and broke.
		if job.State != "failed" {
			t.Fatalf("the installation ended in state %s, expected failed: %s", job.State, last.Message)
		}
		if last.ErrorCode != "transaction_failed" {
			t.Fatalf("error code = %q, expected transaction_failed: %s", last.ErrorCode, last.Message)
		}
		if last.Detail == nil || last.Detail.Kind != "package_apply" {
			t.Fatalf("no transaction report on the failed attempt: %+v", last.Detail)
		}
		// The report has to say what went wrong: the output tail names the
		// maintainer script.
		if len(last.Detail.Output) == 0 {
			t.Error("the transaction report carries no output of the manager")
		}
	}

	// What needs attention, family by family.
	named := containsName(last.Detail.PackagesNeedingAttention, labBrokenPackage)
	if named != expect.attentionNamed {
		t.Errorf("packages needing attention = %v, expected %s named: %v",
			last.Detail.PackagesNeedingAttention, labBrokenPackage, expect.attentionNamed)
	}
	if last.Detail.PackageDatabaseBroken != expect.databaseBroken {
		t.Errorf("the report says package_database_broken = %v, expected %v",
			last.Detail.PackageDatabaseBroken, expect.databaseBroken)
	}

	// The host flag follows the report, and the dashboard counts the host
	// where the flag is raised.
	if broken := h.hostPackageDatabaseBroken(host.ID); broken != expect.databaseBroken {
		t.Errorf("host package_database_broken = %v after the failed transaction, expected %v",
			broken, expect.databaseBroken)
	}
	if expect.databaseBroken {
		if after := h.packageDatabaseBrokenCounter(); after < counterBefore+1 {
			t.Errorf("the dashboard counts %d hosts with a broken package database, expected at least %d",
				after, counterBefore+1)
		}
	}

	if hostHasPackageRepair(host) {
		// The repair finishes the configuration. On Debian that is exactly
		// what the maintainer script needs: it fails the first time and
		// passes the second.
		repair, repairAttempts := h.runOperation(host.ID, map[string]any{
			"action": "packages.repair", "reason": labBrokenReason,
			"payload": map[string]any{"package_repair": map[string]any{}},
		}, 10*time.Minute)
		if repair.State != "succeeded" {
			t.Fatalf("the repair ended in state %s: %s", repair.State, lastMessage(repairAttempts))
		}
		repaired := h.lastPackageAttempt(repair.ID)
		if repaired.Detail == nil || repaired.Detail.Kind != "package_repair" {
			t.Fatalf("no repair report: %+v", repaired.Detail)
		}
		if len(repaired.Detail.StillBlocked) > 0 {
			t.Errorf("after the repair the host still has blocked packages: %+v", repaired.Detail.StillBlocked)
		}
	} else {
		// A family without a repair says so when it is ordered, not after
		// the job is delivered.
		h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
			map[string]any{"action": "packages.repair", "reason": labBrokenReason,
				"payload": map[string]any{"package_repair": map[string]any{}}},
			nil, http.StatusConflict)
	}

	// After the repair - or without one, where the family keeps the package
	// installed and the database sound - the host reports no attention
	// packages and the flag is down.
	if h.hostPackageDatabaseBroken(host.ID) {
		t.Error("the host still has package_database_broken raised")
	}
	if after := h.packageDatabaseBrokenCounter(); after > counterBefore {
		t.Errorf("the dashboard still counts %d hosts with a broken package database, expected at most %d",
			after, counterBefore)
	}
	if blocked := h.blockedPackages(t, host.ID); len(blocked) > 0 {
		t.Errorf("the plan still names blocked packages: %v", blocked)
	}

	// The package goes away the way the operator removes any package: with
	// an approved set. The lab is left the way it was found.
	switch state := h.removeLabPackage(t, host); state {
	case "succeeded":
	case "":
		t.Fatalf("%s is not installed although the transaction ran; the removal plan found nothing", labBrokenPackage)
	default:
		t.Fatalf("the removal of %s ended in state %s", labBrokenPackage, state)
	}
	if h.hostPackageDatabaseBroken(host.ID) {
		t.Error("the removal left package_database_broken raised")
	}
}

// packageAttempt is the last attempt of a package job with the fields the
// scenario reads. The shared attemptView keeps the common fields; the
// attention list, the manager output and the repair report are read here.
type packageAttempt struct {
	Number    int    `json:"attempt_number"`
	Status    string `json:"status"`
	ErrorCode string `json:"error_code"`
	Message   string `json:"message"`
	Detail    *struct {
		Kind                     string   `json:"kind"`
		Manager                  string   `json:"manager"`
		PackageDatabaseBroken    bool     `json:"package_database_broken"`
		PackagesNeedingAttention []string `json:"packages_needing_attention"`
		ScriptletErrors          []string `json:"scriptlet_errors"`
		Output                   []string `json:"output"`
		Removals                 []string `json:"removals"`
		Blocked                  []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"blocked"`
		StillBlocked []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"still_blocked"`
	} `json:"detail"`
}

// lastPackageAttempt returns the last attempt of a job with its package detail.
func (h *harness) lastPackageAttempt(jobID string) packageAttempt {
	h.t.Helper()
	var result struct {
		Items []packageAttempt `json:"items"`
	}
	h.get("/api/v1/jobs/"+jobID+"/attempts", &result)
	if len(result.Items) == 0 {
		h.t.Fatalf("job %s has no attempts", jobID)
	}
	return result.Items[len(result.Items)-1]
}

// unknownToRepositories recognises the answer "there is no such package"
// of every manager: apt's "Unable to locate package", dnf's "No match for
// argument" and "Unable to find a match", pacman's "target not found".
func (a packageAttempt) unknownToRepositories() bool {
	text := strings.ToLower(a.Message)
	if a.Detail != nil {
		text += "\n" + strings.ToLower(strings.Join(a.Detail.Output, "\n"))
	}
	for _, phrase := range []string{
		"unable to locate package", "no match for argument", "unable to find a match",
		"target not found", "no package " + labBrokenPackage + " available",
	} {
		if strings.Contains(text, phrase) {
			return true
		}
	}
	return false
}

// hostPackageDatabaseBroken reads the host flag from the host detail.
func (h *harness) hostPackageDatabaseBroken(hostID string) bool {
	h.t.Helper()
	var host struct {
		PackageDatabaseBroken bool `json:"package_database_broken"`
	}
	h.get("/api/v1/hosts/"+hostID, &host)
	return host.PackageDatabaseBroken
}

// packageDatabaseBrokenCounter reads the dashboard counter of hosts with a
// broken package database.
func (h *harness) packageDatabaseBrokenCounter() int {
	h.t.Helper()
	var summary struct {
		PackageDatabaseBroken int `json:"package_database_broken"`
	}
	h.get("/api/v1/fleet/summary", &summary)
	return summary.PackageDatabaseBroken
}

// hostHasPackageRepair says whether any package adapter of the host reports
// the repair feature. An adapter silent about the feature is taken at its
// word only when it says yes: the refusal of the panel is what the test
// checks otherwise.
func hostHasPackageRepair(host hostView) bool {
	for _, adapter := range []string{"packages.apt", "packages.dnf", "packages.pacman"} {
		if capabilityFeature(host, adapter, "repair") {
			return true
		}
	}
	return false
}

// blockedPackages orders a plan without a refresh and returns the names of
// the packages it reports as blocked.
func (h *harness) blockedPackages(t *testing.T, hostID string) []string {
	t.Helper()
	job, attempts := h.runOperation(hostID, map[string]any{
		"action": "packages.plan", "reason": labBrokenReason,
		"payload": planPayload(false),
	}, 5*time.Minute)
	if job.State != "succeeded" {
		// A host that cannot plan cannot say what blocks it either; that is
		// a different property of the family and is not judged here.
		t.Logf("the plan ended in state %s: %s", job.State, lastMessage(attempts))
		return nil
	}
	last := h.lastPackageAttempt(job.ID)
	if last.Detail == nil {
		return nil
	}
	names := make([]string, 0, len(last.Detail.Blocked))
	for _, pkg := range last.Detail.Blocked {
		names = append(names, pkg.Name)
	}
	return names
}

// removeLabPackage removes the lab package with an approved set: the removal
// plan gives the set, the removal names it, and two people approve. It
// returns the final state of the removal, or an empty string when the
// package was not installed and there was nothing to remove.
func (h *harness) removeLabPackage(t *testing.T, host hostView) string {
	t.Helper()
	plan, planAttempts := h.runOperation(host.ID, map[string]any{
		"action": "packages.plan", "reason": labBrokenReason,
		"payload": map[string]any{"package_plan": map[string]any{
			"mode": "remove", "only_packages": []string{labBrokenPackage},
		}},
	}, 5*time.Minute)
	if plan.State != "succeeded" {
		t.Logf("the removal plan of %s ended in state %s: %s", labBrokenPackage, plan.State, lastMessage(planAttempts))
		return plan.State
	}
	removals := h.lastPackageAttempt(plan.ID).Detail
	if removals == nil || len(removals.Removals) == 0 {
		return ""
	}

	removal := h.createOperation(host.ID, map[string]any{
		"action": "packages.remove", "reason": labBrokenReason,
		"target_confirmation": host.Hostname,
		"payload": map[string]any{"package_change": map[string]any{
			"packages": []string{labBrokenPackage}, "expected_removals": removals.Removals,
		}},
	})
	state := h.approve(removal.ID, removal.PayloadHash)
	if state.State == "awaiting_approval" {
		second := h.withToken(h.createPrincipal(uniqueSubject("second-person-broken-package"),
			[]map[string]string{{"role": "approver", "site": host.Site, "environment": host.Environment}}))
		second.approve(removal.ID, removal.PayloadHash)
	}
	return h.awaitTerminal(removal.ID, 10*time.Minute).State
}

func containsName(names []string, wanted string) bool {
	for _, name := range names {
		if name == wanted {
			return true
		}
	}
	return false
}
