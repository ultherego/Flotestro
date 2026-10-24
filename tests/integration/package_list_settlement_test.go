//go:build integration

package integration

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestAJobThatReadsThePackageListIsNotSucceededWithoutTheList makes the write of the
// list fail and watches the job. The list is written in the transaction that settles
// the job, so while the write fails the job stays unsettled and the host keeps the
// answer and offers it again; the moment the write works the job settles and the
// list is the one this job read. Before, the job was settled first and the list
// written after it, so a failing write left a job that said it had read the list over
// a list that was not there - and a reader that came in between saw the one before.
func TestAJobThatReadsThePackageListIsNotSucceededWithoutTheList(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	host := h.hostByFamily("debian")
	pool := h.database(ctx)

	drop := refusePackageList(t, h, host.ID, "P0001")

	job := h.createOperation(host.ID, map[string]any{
		"action": "packages.list", "reason": "the list is written with the settlement",
	})
	if job.RequiresApproval {
		job = h.approve(job.ID, job.PayloadHash)
	}

	// While the write is refused the job must not settle as succeeded.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if state := h.job(job.ID).State; state == "succeeded" {
			t.Fatal("the job settled as succeeded while the list could not be written")
		}
		time.Sleep(2 * time.Second)
	}

	// The refusal ends: the host offers its answer again and the job settles with the list.
	drop()
	final := h.awaitTerminal(job.ID, 5*time.Minute)
	if final.State != "succeeded" {
		t.Fatalf("the job did not settle once the list could be written: %s", final.State)
	}
	var written string
	if err := pool.QueryRow(ctx, `select coalesce(job_id::text, '') from host_package_state where host_id = $1::uuid`,
		host.ID).Scan(&written); err != nil {
		t.Fatal(err)
	}
	if written != job.ID {
		t.Fatalf("the list stored is the one of job %q, not of the job that settled, %s", written, job.ID)
	}
}

// refusePackageList makes the database refuse the write of the package list of one
// host with the SQLSTATE given, and returns the function that ends the refusal. The
// trigger is removed when the test ends whatever happens.
func refusePackageList(t *testing.T, h *harness, hostID, sqlstate string) func() {
	t.Helper()
	ctx := context.Background()
	pool := h.database(ctx)
	trigger := "refuse_list_" + strings.ReplaceAll(hostID[:8], "-", "") + "_" + strings.ToLower(sqlstate)
	if _, err := pool.Exec(ctx, fmt.Sprintf(`
		create or replace function %[1]s() returns trigger language plpgsql as $$
		begin
			if new.host_id = '%[2]s'::uuid then
				raise exception 'the laboratory refuses the package list of this host' using errcode = '%[3]s';
			end if;
			return new;
		end $$`, trigger, hostID, sqlstate)); err != nil {
		t.Fatalf("preparing the refusal: %v", err)
	}
	drop := func() {
		_, _ = pool.Exec(context.Background(), fmt.Sprintf(
			`drop trigger if exists %[1]s on host_package_state; drop function if exists %[1]s()`, trigger))
	}
	t.Cleanup(drop)
	if _, err := pool.Exec(ctx, fmt.Sprintf(`
		create trigger %[1]s before insert or update on host_package_state
		for each row execute function %[1]s()`, trigger)); err != nil {
		t.Fatalf("installing the refusal: %v", err)
	}
	return drop
}

// A list the database refuses for what is in it (an integrity error) would be
// refused at every redelivery, so the job settles without it and the list stored
// before stays: a job that never settles over a list is worse than that.
func TestAPackageListRefusedForItsContentDoesNotHoldTheJobBack(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	host := h.hostByFamily("debian")
	pool := h.database(ctx)

	var before string
	_ = pool.QueryRow(ctx, `select coalesce(job_id::text, '') from host_package_state where host_id = $1::uuid`,
		host.ID).Scan(&before)

	refusePackageList(t, h, host.ID, "23505")
	final, _ := h.runOperation(host.ID, map[string]any{
		"action": "packages.list", "reason": "a list the database refuses for its content",
	}, 2*time.Minute)
	if final.State != "succeeded" {
		t.Fatalf("a list refused for its content held the job at %s", final.State)
	}
	var after string
	if err := pool.QueryRow(ctx, `select coalesce(job_id::text, '') from host_package_state where host_id = $1::uuid`,
		host.ID).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("the list of the host changed to the one of job %q though the database refused it", after)
	}
}
