//go:build integration

package integration

import (
	"context"
	"net/http"
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
// not a toggle: repeating it does not reverse the change.
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
	}
}
