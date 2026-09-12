package agent

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/opspec"
)

func quietLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestARefreshWaitsForTheRevision guards the property this operation exists for
// at all: the task ends after a new picture has been built, not at the moment
// the order is accepted.
func TestARefreshWaitsForTheRevision(t *testing.T) {
	k := newCollector()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	collected := make(chan struct{})
	go func() {
		_ = k.run(ctx, func(context.Context, []string) (Facts, error) {
			close(collected)
			return Facts{Hostname: "host"}, nil
		}, func(Facts) (Refresh, error) {
			return Refresh{Revision: "abc", Changed: true}, nil
		}, quietLog())
	}()

	result := k.refresh(ctx, nil)
	select {
	case <-collected:
	default:
		t.Fatal("the refresh came back without collecting the inventory")
	}
	if result.Err != nil {
		t.Fatalf("refresh: %v", result.Err)
	}
	if result.Revision != "abc" || !result.Changed {
		t.Fatalf("result = %+v", result)
	}
}

// TestConcurrentRequestsShareTheRead guards the deduplication: the host must
// not pay for a picture once per person who clicked at the same moment. The
// requests that arrived after the read started share one next read - which is
// why the boundary is two and not the number of requesters.
func TestConcurrentRequestsShareTheRead(t *testing.T) {
	k := newCollector()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var collected atomic.Int32
	slow := make(chan struct{})
	go func() {
		_ = k.run(ctx, func(context.Context, []string) (Facts, error) {
			collected.Add(1)
			<-slow
			return Facts{Hostname: "host"}, nil
		}, func(Facts) (Refresh, error) {
			return Refresh{Revision: "abc", Changed: true}, nil
		}, quietLog())
	}()

	const count = 5
	var group sync.WaitGroup
	results := make([]Refresh, count)
	for i := 0; i < count; i++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			results[index] = k.refresh(ctx, nil)
		}(i)
	}
	// Give the requests time to reach the collector before the read finishes.
	time.Sleep(50 * time.Millisecond)
	close(slow)
	group.Wait()

	if reads := collected.Load(); reads > 2 {
		t.Fatalf("number of reads = %d for %d requests", reads, count)
	}
	for i, result := range results {
		if result.Err != nil || result.Revision != "abc" {
			t.Fatalf("result %d = %+v", i, result)
		}
	}
}

// TestThePartialScopeReachesTheRead guards that the ordered modules reach the
// collection instead of getting lost on the way.
func TestThePartialScopeReachesTheRead(t *testing.T) {
	k := newCollector()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	scope := make(chan []string, 1)
	go func() {
		_ = k.run(ctx, func(_ context.Context, modules []string) (Facts, error) {
			scope <- modules
			return Facts{}, nil
		}, func(Facts) (Refresh, error) {
			return Refresh{Revision: "abc"}, nil
		}, quietLog())
	}()

	result := k.refresh(ctx, []string{ModulePackages})
	if result.Err != nil {
		t.Fatal(result.Err)
	}
	read := <-scope
	if len(read) != 1 || read[0] != ModulePackages {
		t.Fatalf("scope of the read = %v", read)
	}
	if len(result.Modules) != 1 || result.Modules[0] != ModulePackages {
		t.Fatalf("scope of the result = %v", result.Modules)
	}
}

// TestTheEndOfTheSessionEndsTheWait guards that a task does not hang until the
// time limit when the session ends during a collection.
func TestTheEndOfTheSessionEndsTheWaitOnRefresh(t *testing.T) {
	k := newCollector()
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		_ = k.run(ctx, func(ctx context.Context, _ []string) (Facts, error) {
			<-ctx.Done()
			return Facts{}, ctx.Err()
		}, func(Facts) (Refresh, error) {
			return Refresh{}, nil
		}, quietLog())
	}()

	done := make(chan Refresh, 1)
	go func() { done <- k.refresh(context.Background(), nil) }()
	time.Sleep(30 * time.Millisecond)
	cancel()

	select {
	case result := <-done:
		if result.Err == nil {
			t.Fatal("a refresh after the end of the session returned a success")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the refresh did not end after the session was closed")
	}
}

// TestARequestDuringACollectionWaitsForTheNextOne guards the most dangerous
// shortcut of the deduplication: a request for a module that arrived after the
// read started must not be settled with a picture that does not cover that
// module.
func TestARequestDuringACollectionWaitsForTheNextOne(t *testing.T) {
	k := newCollector()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	scopes := make(chan []string, 4)
	slow := make(chan struct{})
	firstRead := make(chan struct{})
	var index atomic.Int32
	go func() {
		_ = k.run(ctx, func(_ context.Context, modules []string) (Facts, error) {
			scopes <- modules
			if index.Add(1) == 1 {
				close(firstRead)
				<-slow
			}
			return Facts{}, nil
		}, func(Facts) (Refresh, error) {
			return Refresh{Revision: "abc"}, nil
		}, quietLog())
	}()

	// The first read covers only the services and stops halfway.
	late := make(chan Refresh, 1)
	go func() { late <- k.refresh(ctx, []string{ModuleServices}) }()
	<-firstRead

	// The request for packages arrives after its start.
	done := make(chan Refresh, 1)
	go func() { done <- k.refresh(ctx, []string{ModulePackages}) }()
	time.Sleep(50 * time.Millisecond)
	select {
	case result := <-done:
		t.Fatalf("the request for packages was settled with a read of services: %+v", result)
	default:
	}

	close(slow)
	if result := <-late; result.Err != nil {
		t.Fatalf("the read of services: %v", result.Err)
	}
	select {
	case result := <-done:
		if result.Err != nil {
			t.Fatalf("the read of packages: %v", result.Err)
		}
		if len(result.Modules) != 1 || result.Modules[0] != ModulePackages {
			t.Fatalf("scope of the result = %v", result.Modules)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the request for packages did not live to see the second read")
	}

	if scope := <-scopes; len(scope) != 1 || scope[0] != ModuleServices {
		t.Fatalf("the first read = %v", scope)
	}
	if scope := <-scopes; len(scope) != 1 || scope[0] != ModulePackages {
		t.Fatalf("the second read = %v", scope)
	}
}

// TestEveryContractModuleHasACollector guards that the list of modules the
// panel accepts in an order does not drift apart from what the agent can read.
// The drift would not be visible: the task would end in success without
// refreshing anything.
func TestEveryContractModuleHasACollector(t *testing.T) {
	for _, name := range opspec.InventoryModules {
		if name == ModuleSystem {
			// The basic facts are always collected, so they have no entry in
			// the map of collectors.
			continue
		}
		if _, ok := moduleCollectors[name]; !ok {
			t.Errorf("the panel accepts the module %q, which the agent does not collect", name)
		}
	}
	for name := range moduleCollectors {
		if !opspec.IsInventoryModule(name) {
			t.Errorf("the agent collects the module %q, which the panel does not accept", name)
		}
	}
	// The collection order is a list of names, so a typo in it would give an
	// empty collector - and would bring the whole inventory read down.
	for _, name := range ModuleOrder {
		if _, ok := moduleCollectors[name]; !ok {
			t.Errorf("the order lists the module %q without a collector", name)
		}
	}
	if len(ModuleOrder) != len(moduleCollectors) {
		t.Errorf("the order has %d modules, there are %d collectors",
			len(ModuleOrder), len(moduleCollectors))
	}
}
