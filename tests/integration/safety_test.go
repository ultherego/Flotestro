//go:build integration

package integration

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestProtectedUnitsAreRejected checks that an operation on a unit whose
// stopping would cut off the way to repair the host is not carried out.
func TestProtectedUnitsAreRejected(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	for _, unit := range []string{"sshd.service", "flotestro-agent.service", "NetworkManager.service"} {
		t.Run(unit, func(t *testing.T) {
			job, attempts := h.runOperation(host.ID, map[string]any{
				"action":  "unit.stop",
				"payload": unitPayload(unit),
			}, 60*time.Second)

			if job.State == "succeeded" {
				t.Fatalf("the operation on the protected unit %s succeeded", unit)
			}
			if len(attempts) == 0 {
				t.Fatal("no recorded attempt")
			}
			last := attempts[len(attempts)-1]
			if last.ErrorCode != "protected_unit" {
				t.Fatalf("error code = %q, expected protected_unit", last.ErrorCode)
			}
			// The rejection must happen before any state change.
			if last.UnitStateAfter != nil {
				t.Error("the rejected operation returned a state after the change")
			}
		})
	}
}

// TestInvalidUnitNameIsRejected checks the validation on the host side. The
// name never reaches a shell, but the rejection must be explicit.
func TestInvalidUnitNameIsRejected(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	for _, unit := range []string{"cron.service; reboot", "../../etc/passwd", "cron"} {
		t.Run(unit, func(t *testing.T) {
			job, attempts := h.runOperation(host.ID, map[string]any{
				"action":  "unit.restart",
				"payload": unitPayload(unit),
			}, 60*time.Second)

			if job.State == "succeeded" {
				t.Fatalf("the invalid name %q was carried out", unit)
			}
			if len(attempts) > 0 && attempts[len(attempts)-1].ErrorCode != "invalid_unit" {
				t.Errorf("error code = %q, expected invalid_unit",
					attempts[len(attempts)-1].ErrorCode)
			}
		})
	}
}

// TestUnknownOperationIsRejectedByTheAPI checks that the operation
// catalogue is closed: there is no way to order an arbitrary command.
func TestUnknownOperationIsRejectedByTheAPI(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	for _, action := range []string{"shell.exec", "unit.mask", "", "systemctl"} {
		h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
			map[string]any{"action": action, "payload": unitPayload("cron.service")},
			nil, http.StatusBadRequest)
	}
}

// TestOperationCatalogueHasNoShell guards the forbidden anti-property from
// the document: the base contract has no operation that starts a shell.
func TestOperationCatalogueHasNoShell(t *testing.T) {
	h := newHarness(t)
	var catalog struct {
		Items []struct {
			Action     string `json:"action"`
			Permission string `json:"permission"`
		} `json:"items"`
	}
	h.get("/api/v1/actions", &catalog)

	if len(catalog.Items) == 0 {
		t.Fatal("the operation catalogue is empty")
	}
	for _, item := range catalog.Items {
		switch item.Action {
		case "shell.exec", "shell", "command.run", "exec":
			t.Fatalf("the catalogue contains a shell operation: %s", item.Action)
		}
		if item.Permission == "" {
			t.Errorf("operation %s has no permission", item.Action)
		}
	}
}

// TestRedeliveryDoesNotRepeatTheMutation is a test of the most important
// at-least-once property. A lease expiry is simulated by returning the job
// to the queue, and the agent is checked to return the recorded result
// instead of restarting the service a second time.
func TestRedeliveryDoesNotRepeatTheMutation(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pool := h.database(ctx)
	host := h.hostByFamily("debian")

	job, attempts := h.runOperation(host.ID, map[string]any{
		"action":  "unit.restart",
		"payload": unitPayload("cron.service"),
	}, 90*time.Second)
	if job.State != "succeeded" {
		t.Fatalf("the first execution failed: %s", job.State)
	}
	pidAfterFirst := attempts[len(attempts)-1].UnitStateAfter.MainPID

	// The job goes back to the queue exactly as after a lease expiry.
	if _, err := pool.Exec(ctx, `
		update jobs set state = 'queued', finished_at = null, result_status = null
		where id = $1`, job.ID); err != nil {
		t.Fatalf("the job was not returned to the queue: %v", err)
	}

	repeated := h.awaitTerminal(job.ID, 90*time.Second)
	if repeated.State != "succeeded" {
		t.Fatalf("the redelivery ended in state %s", repeated.State)
	}

	repeatedAttempts := h.attempts(job.ID)
	if len(repeatedAttempts) < 2 {
		t.Fatalf("expected a second attempt, there are %d", len(repeatedAttempts))
	}
	last := repeatedAttempts[len(repeatedAttempts)-1]
	if !last.Replayed {
		t.Error("the second attempt was not marked as replayed from the journal")
	}
	// The crux of the test: the service was not restarted a second time.
	if last.UnitStateAfter != nil && last.UnitStateAfter.MainPID != pidAfterFirst {
		t.Fatalf("the mutation was repeated: PID %d -> %d",
			pidAfterFirst, last.UnitStateAfter.MainPID)
	}
}

// TestAuditTrailIsComplete checks that every step of an operation leaves an
// event: creation, approval, dispatch and the result.
func TestAuditTrailIsComplete(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	job, _ := h.runOperation(host.ID, map[string]any{
		"action":  "unit.restart",
		"payload": unitPayload("cron.service"),
	}, 90*time.Second)

	var events struct {
		Items []struct {
			Action    string `json:"action"`
			ActorID   string `json:"actor_id"`
			ActorType string `json:"actor_type"`
			Outcome   string `json:"outcome"`
			TargetID  string `json:"target_id"`
		} `json:"items"`
	}
	h.get("/api/v1/audit?target_id="+job.ID+"&limit=50", &events)

	seen := map[string]bool{}
	for _, event := range events.Items {
		seen[event.Action] = true
	}
	for _, required := range []string{"job.create", "job.approve", "job.dispatch", "job.result"} {
		if !seen[required] {
			t.Errorf("no audit event %s for job %s", required, job.ID)
		}
	}
}

// TestDenialIsAuditedToo checks that a failed approval attempt leaves a
// trace. An audit log without denials would show only what succeeded.
func TestDenialIsAuditedToo(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	job := h.createOperation(host.ID, map[string]any{
		"action":  "unit.restart",
		"payload": unitPayload("cron.service"),
	})
	t.Cleanup(func() {
		h.do(http.MethodPost, "/api/v1/jobs/"+job.ID+"/cancel",
			map[string]any{"reason": "end of the test"}, nil, http.StatusOK)
	})

	h.do(http.MethodPost, "/api/v1/jobs/"+job.ID+"/approve",
		map[string]any{"payload_hash": "deadbeef"}, nil, http.StatusConflict)

	var events struct {
		Items []struct {
			Action  string `json:"action"`
			Outcome string `json:"outcome"`
		} `json:"items"`
	}
	h.get("/api/v1/audit?target_id="+job.ID+"&limit=50", &events)

	denied := false
	for _, event := range events.Items {
		if event.Action == "job.approve" && event.Outcome == "denied" {
			denied = true
		}
	}
	if !denied {
		t.Fatal("the rejected approval left no audit event")
	}
}

// TestFileReadOnlyFromTheAllowlist checks the boundary from chapter 6. A
// panel that can read any root file can read private keys and /etc/shadow -
// the scope belongs to the host, not to the job.
func TestFileReadOnlyFromTheAllowlist(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	for _, path := range []string{"/etc/shadow", "/root/.ssh/id_rsa", "/etc/flotestro/agent.env"} {
		job, attempts := h.runOperation(host.ID, map[string]any{
			"action":  "logfile.read",
			"payload": map[string]any{"logfile": map[string]any{"path": path, "lines": 5}},
		}, 60*time.Second)

		if job.State == "succeeded" {
			t.Errorf("a file outside the allowlist was read: %s", path)
		}
		if len(attempts) > 0 && attempts[len(attempts)-1].Message == "" {
			t.Errorf("the refusal for %s carries no reason", path)
		}
	}
}

// TestInvalidLogPathIsRejected checks the validation on the API side.
// Climbing up a directory would allow matching an allowlist pattern and
// still reading a file outside it.
func TestInvalidLogPathIsRejected(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	for _, path := range []string{"", "var/log/syslog", "/var/log/../../etc/shadow"} {
		h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
			map[string]any{
				"action":  "logfile.read",
				"payload": map[string]any{"logfile": map[string]any{"path": path, "lines": 5}},
			}, nil, http.StatusBadRequest)
	}
}

// TestFullUnitListingIsOrderedExplicitly guards that an empty name list
// does not mean "all". Reading a few units and listing the whole host cost
// differently, so they must be different requests.
func TestFullUnitListingIsOrderedExplicitly(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	// An empty list without an explicit order is a mistake in the call.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{
			"action":  "unit.status",
			"payload": map[string]any{"unit_status": map[string]any{"units": []string{}}},
		}, nil, http.StatusBadRequest)

	// Ordering the full listing together with a name list is contradictory.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{
			"action": "unit.status",
			"payload": map[string]any{"unit_status": map[string]any{
				"all": true, "units": []string{"cron.service"},
			}},
		}, nil, http.StatusBadRequest)

	job, attempts := h.runOperation(host.ID, map[string]any{
		"action":  "unit.status",
		"payload": map[string]any{"unit_status": map[string]any{"all": true}},
	}, 90*time.Second)
	if job.State != "succeeded" {
		t.Fatalf("listing: state = %s, code = %s", job.State, job.ResultErrorCode)
	}
	if len(attempts) == 0 || attempts[len(attempts)-1].Detail == nil {
		t.Fatal("the listing returned no units")
	}
}

// TestMaskingRequiresAJustification checks that a critical operation does
// not go with one click. Masking takes away the unit's ability to start
// even manually and survives a host reboot.
func TestMaskingRequiresAJustification(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{
			"action":  "unit.mask.set",
			"payload": map[string]any{"unit_toggle": map[string]any{"unit": "cron.service", "enabled": true}},
		}, nil, http.StatusBadRequest)

	// Enabling a unit is reversible and goes without a justification.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{
			"action":  "unit.enable.set",
			"payload": map[string]any{"unit_toggle": map[string]any{"unit": "cron.service", "enabled": true}},
		}, nil, http.StatusCreated)
}

// TestJournalPreviewEndsOnItsOwn checks the boundary from chapter 6: the
// stream is short-lived and bounded from above. A preview without an upper
// bound would hold a process on the host also when the operator closed the
// tab long ago.
func TestJournalPreviewEndsOnItsOwn(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	job, _ := h.runOperation(host.ID, map[string]any{
		"action": "journal.follow",
		"payload": map[string]any{"journal": map[string]any{
			"lines": 3, "follow_seconds": 5,
		}},
	}, 90*time.Second)

	if job.State != "succeeded" {
		t.Fatalf("state = %s, code = %s", job.State, job.ResultErrorCode)
	}
	// The end of the preview is a success: the stream was meant to end.
	if !strings.Contains(job.ResultMessage, "the preview ended") {
		t.Errorf("the result does not summarise the preview: %q", job.ResultMessage)
	}
}

// TestPreviewCannotLastForever guards the upper time bound.
func TestPreviewCannotLastForever(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{
			"action": "journal.follow",
			"payload": map[string]any{"journal": map[string]any{
				"lines": 3, "follow_seconds": 100000,
			}},
		}, nil, http.StatusBadRequest)
}

// TestJournalTimeRangeIsValidated checks the validation of the "since"
// filter. The value goes into a journalctl argument - not into a shell, but
// a narrower validation is still cheaper than trust.
func TestJournalTimeRangeIsValidated(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	for _, since := range []string{"wczoraj", "-1h; reboot", "$(date)"} {
		h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
			map[string]any{
				"action": "journal.read",
				"payload": map[string]any{"journal": map[string]any{
					"lines": 5, "since": since,
				}},
			}, nil, http.StatusBadRequest)
	}
	// Formats journalctl understands must pass.
	for _, since := range []string{"-1h", "yesterday", "2026-08-01"} {
		h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
			map[string]any{
				"action": "journal.read",
				"payload": map[string]any{"journal": map[string]any{
					"lines": 5, "since": since,
				}},
			}, nil, http.StatusCreated)
	}
}

// TestSignalRequiresTheStartTime checks the boundary from chapter 5. A PID
// alone does not identify a process: the kernel reuses the numbers, so a
// signal sent a moment after viewing the list could hit something entirely
// different.
func TestSignalRequiresTheStartTime(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{
			"action": "process.signal",
			"payload": map[string]any{"process_signal": map[string]any{
				"pid": 99999, "signal": "TERM",
			}},
		}, nil, http.StatusBadRequest)
}

// TestSignalsOutsideTheListAreRejected guards that the list is closed:
// there is no "send any signal" operation.
func TestSignalsOutsideTheListAreRejected(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	for _, signal := range []string{"STOP", "SEGV", "USR1", "9", ""} {
		h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
			map[string]any{
				"action": "process.signal",
				"payload": map[string]any{"process_signal": map[string]any{
					"pid": 99999, "expected_start_ticks": 1, "signal": signal,
				}},
			}, nil, http.StatusBadRequest)
	}
}

// TestInitProcessIsProtected checks that halting the system is not an
// operation available from the process list.
func TestInitProcessIsProtected(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	for _, pid := range []int{1, 0, -1} {
		h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
			map[string]any{
				"action": "process.signal",
				"payload": map[string]any{"process_signal": map[string]any{
					"pid": pid, "expected_start_ticks": 1, "signal": "TERM",
				}},
			}, nil, http.StatusBadRequest)
	}
}

// TestProcessSnapshotHasUpperBounds checks the cost on the host: the
// snapshot is made on request and cannot grow to an arbitrary size.
func TestProcessSnapshotHasUpperBounds(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{
			"action":  "process.list",
			"payload": map[string]any{"process_list": map[string]any{"limit": 100000}},
		}, nil, http.StatusBadRequest)

	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{
			"action":  "process.list",
			"payload": map[string]any{"process_list": map[string]any{"sort_by": "made-up"}},
		}, nil, http.StatusBadRequest)

	job, _ := h.runOperation(host.ID, map[string]any{
		"action":  "process.list",
		"payload": map[string]any{"process_list": map[string]any{"sort_by": "rss", "limit": 10}},
	}, 60*time.Second)
	if job.State != "succeeded" {
		t.Fatalf("state = %s, code = %s", job.State, job.ResultErrorCode)
	}

	var fragment inventoryFragment
	h.do(http.MethodGet, "/api/v1/hosts/"+host.ID+"/inventory/processes",
		nil, &fragment, http.StatusOK)
	if len(fragment.Payload) == 0 {
		t.Error("the process snapshot is empty")
	}
}
