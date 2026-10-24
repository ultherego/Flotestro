//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/inventory"
	"github.com/ultherego/flotestro/internal/policy"
)

// A host that reconnects reports everything again. The rows that say what they said
// a few minutes ago are not written again - the writes of a fleet coming back are
// most of what it costs the database - and they are written once the mark of their
// last observation is older than the window of their module.
//
// The row's xmin is the version of it: a rewrite gives it a new one, and a skipped
// write leaves it as it was.
func TestAnUnchangedReportIsNotWrittenAgainWithinTheWindow(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	host := h.enrollSyntheticHost(t)
	pool := h.database(ctx)

	store := inventory.NewStore(pool)
	store.SetRefreshWindow(func(module string) time.Duration { return policy.MaxFactAge(module) / 4 })
	locked := false

	report := func(revision string, shell string, observed time.Time) inventory.Report {
		return inventory.Report{
			Revision: revision, Full: true, SchemaVersion: "1", RawJSON: []byte(`{}`),
			LocalAccounts: []inventory.LocalAccount{{
				Name: "svc", UID: 1001, GID: 1001, Shell: shell, Source: "local",
				Groups: []string{"svc"}, Locked: &locked, SSHKeys: json.RawMessage("[]"),
			}},
			Fragments: []inventory.Fragment{
				{Module: "services", Revision: "s1", Source: "agent/systemctl",
					Payload: json.RawMessage(`{"units":1}`), ObservedAt: observed},
				{Module: "kernel", Revision: "k1", Source: "agent/sysctl",
					Payload: json.RawMessage(`{"keys":1}`), ObservedAt: observed},
			},
		}
	}
	save := func(r inventory.Report) {
		t.Helper()
		if _, err := store.Save(ctx, host.ID, r); err != nil {
			t.Fatalf("saving the report: %v", err)
		}
	}
	version := func(query string, args ...any) string {
		t.Helper()
		var xmin string
		if err := pool.QueryRow(ctx, query, args...).Scan(&xmin); err != nil {
			t.Fatalf("reading the version of a row: %v", err)
		}
		return xmin
	}
	account := func() string {
		return version(`select xmin::text from host_local_accounts where host_id = $1::uuid and name = 'svc'`, host.ID)
	}
	module := func(name string) string {
		return version(`select xmin::text from host_module_inventory where host_id = $1::uuid and module = $2`, host.ID, name)
	}
	age := func(minutes int) {
		t.Helper()
		past := fmt.Sprintf("%d minutes", minutes)
		if _, err := pool.Exec(ctx, `update host_local_accounts set observed_at = now() - $2::interval where host_id = $1::uuid`,
			host.ID, past); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `update host_module_inventory set observed_at = now() - $2::interval where host_id = $1::uuid`,
			host.ID, past); err != nil {
			t.Fatal(err)
		}
	}

	now := time.Now().UTC()
	save(report("r1", "/bin/sh", now))
	accountV, servicesV, kernelV := account(), module("services"), module("kernel")

	// The same report a minute later: nothing is written.
	save(report("r2", "/bin/sh", now.Add(time.Minute)))
	if account() != accountV || module("services") != servicesV || module("kernel") != kernelV {
		t.Fatal("rows that said what they said a minute ago were written again")
	}

	// A changed account is written at once, whatever the mark says.
	save(report("r3", "/bin/bash", now.Add(2*time.Minute)))
	if account() == accountV {
		t.Fatal("an account that changed was not written")
	}
	accountV = account()

	// Ten minutes since the last observation: services (the policy tolerates 30
	// minutes of age, so its window is a quarter of that) is written, the kernel
	// (tolerated two days, so the window is the fifteen minutes at most) is not.
	age(10)
	accountV, servicesV, kernelV = account(), module("services"), module("kernel")
	save(report("r4", "/bin/bash", time.Now().UTC()))
	if module("services") == servicesV {
		t.Error("services, older than its window, kept its old mark")
	}
	if module("kernel") != kernelV {
		t.Error("the kernel, inside its window, was written again")
	}
	if account() != accountV {
		t.Error("an account inside its window was written again")
	}

	// Twenty minutes: everything is older than its window and is observed again.
	age(20)
	accountV, servicesV, kernelV = account(), module("services"), module("kernel")
	save(report("r5", "/bin/bash", time.Now().UTC()))
	if account() == accountV || module("services") == servicesV || module("kernel") == kernelV {
		t.Error("rows older than every window kept their old mark")
	}
}

// The registry of adapters is the same story: a host that comes back with the one it
// left, not long ago, leaves the rows alone.
func TestAnUnchangedRegistryIsNotWrittenAgainWithinTheWindow(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	host := h.enrollSyntheticHost(t)
	pool := h.database(ctx)
	store := hosts.NewStore(pool)

	caps := hosts.Capabilities{
		{Name: hosts.CapSystemd, Version: 1, Available: true},
		{Name: hosts.CapJournald, Version: 1, Available: true, Features: map[string]bool{"follow": true}},
	}
	versions := func() string {
		t.Helper()
		var out string
		if err := pool.QueryRow(ctx, `select string_agg(xmin::text, ',' order by name)
			from host_capability_registry where host_id = $1::uuid`, host.ID).Scan(&out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	hello := func(list hosts.Capabilities) {
		t.Helper()
		if err := store.ApplyHello(ctx, host.ID, "0.64.3", "boot-1", list); err != nil {
			t.Fatalf("the hello: %v", err)
		}
	}

	hello(caps)
	first := versions()
	hello(caps)
	if versions() != first {
		t.Fatal("a registry that came back unchanged was written again")
	}

	changed := append(hosts.Capabilities(nil), caps...)
	changed[1].Features = map[string]bool{"follow": false}
	hello(changed)
	if versions() == first {
		t.Fatal("a registry that changed was not written")
	}

	if _, err := pool.Exec(ctx, `update host_capability_registry set observed_at = now() - interval '20 minutes'
		where host_id = $1::uuid`, host.ID); err != nil {
		t.Fatal(err)
	}
	again := versions()
	hello(changed)
	if versions() == again {
		t.Fatal("a registry observed twenty minutes ago kept its old mark")
	}
}
