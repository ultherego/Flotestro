//go:build integration

package integration

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestABootFilterNeedsTheCapability checks that a journal read narrowed to one
// boot is refused before dispatch, with its own code, on a host whose agent
// does not announce the boot filter.
func TestABootFilterNeedsTheCapability(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool := h.database(ctx)

	// A synthetic host with the journald adapter of an agent from before
	// the feature: available, silent about boot_filter.
	host := h.enrollSyntheticHost(t)
	if _, err := pool.Exec(ctx, `
		insert into host_capability_registry (host_id, name, version, available, features)
		values ($1::uuid, 'journald', 1, true, '{}'::jsonb)
		on conflict (host_id, name) do update set available = true, features = '{}'::jsonb`,
		host.ID); err != nil {
		t.Fatalf("giving the synthetic host a journald adapter: %v", err)
	}
	const bootID = "2cd11312-4365-4fe6-b49e-e4d704ea2c5a"
	byBoot := map[string]any{
		"action":  "journal.read",
		"payload": map[string]any{"journal": map[string]any{"lines": 5, "boot_id": bootID}},
	}

	var problem struct {
		Code   string `json:"code"`
		Detail string `json:"detail"`
	}
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations", byBoot, &problem, http.StatusConflict)
	if problem.Code != "boot_filter_unsupported" {
		t.Fatalf("code = %q (%s), expected boot_filter_unsupported", problem.Code, problem.Detail)
	}
	// No job was queued for the refused read: nothing waits to be
	// delivered to an agent that would misread it.
	var jobs struct {
		Items []jobView `json:"items"`
	}
	h.get("/api/v1/jobs?host_id="+host.ID+"&action=journal.read", &jobs)
	if len(jobs.Items) != 0 {
		t.Fatalf("a refused read left %d jobs queued", len(jobs.Items))
	}

	// A read without the boot filter is what the old agent can do, and it
	// is accepted as before.
	plain := h.createOperation(host.ID, map[string]any{
		"action":  "journal.read",
		"payload": map[string]any{"journal": map[string]any{"lines": 5}},
	})
	t.Cleanup(func() { h.cancelJob(plain.ID) })

	// A value that is not a boot identifier is a wrong order, whatever the
	// agent can do.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations", map[string]any{
		"action":  "journal.read",
		"payload": map[string]any{"journal": map[string]any{"lines": 5, "boot_id": "yesterday"}},
	}, &problem, http.StatusBadRequest)
	if problem.Code != "invalid_payload" {
		t.Fatalf("code = %q (%s), expected invalid_payload", problem.Code, problem.Detail)
	}

	// The adapter names the feature: the same read goes through.
	if _, err := pool.Exec(ctx, `
		update host_capability_registry set features = '{"boot_filter": true}'::jsonb
		where host_id = $1::uuid and name = 'journald'`, host.ID); err != nil {
		t.Fatalf("giving the synthetic host the boot filter: %v", err)
	}
	filtered := h.createOperation(host.ID, byBoot)
	t.Cleanup(func() { h.cancelJob(filtered.ID) })

	// A host of the lab whose agent has the feature reads its own current
	// boot; the lines come back and name nothing of another boot.
	real := h.hostByFamily("debian")
	supported := false
	for _, capability := range real.Capabilities {
		if capability.Name == "journald" && capability.Available && capability.Features["boot_filter"] {
			supported = true
		}
	}
	if !supported || real.BootID == "" {
		t.Logf("the agent of %s does not announce the boot filter yet; the live read is not checked", real.Hostname)
		return
	}
	job, attempts := h.runOperation(real.ID, map[string]any{
		"action":  "journal.read",
		"payload": map[string]any{"journal": map[string]any{"lines": 5, "boot_id": real.BootID}},
	}, 60*time.Second)
	if job.State != "succeeded" {
		t.Fatalf("the read by the current boot ended %s: %+v", job.State, attempts)
	}
	if len(attempts) == 0 || strings.TrimSpace(attempts[len(attempts)-1].Stdout) == "" {
		t.Fatalf("the read by the current boot came back empty: %+v", attempts)
	}
}
