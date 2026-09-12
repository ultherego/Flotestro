package agent

import (
	"context"
	"testing"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
)

// The heart of the split into classes: a long package read must not stop the
// operations that take milliseconds. Without it the host looks hung from the
// panel.
func TestPackageOperationsDoNotBlockTheRest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := newBudget(2)

	// The package class is saturated - a transaction is running.
	taken := b.acquire(ctx, ClassPackages)
	if taken == nil {
		t.Fatal("no slot was obtained in the package class")
	}
	defer taken()

	free := make(chan struct{})
	go func() {
		if release := b.acquire(ctx, ClassGeneral); release != nil {
			release()
		}
		close(free)
	}()
	select {
	case <-free:
	case <-time.After(2 * time.Second):
		t.Fatal("a general operation waited for the package operation to finish")
	}
}

// Two apt runs at once rebuild the same cache and together take longer than one
// after the other, so the package class has exactly one slot.
func TestASecondPackageOperationWaits(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := newBudget(4)

	first := b.acquire(ctx, ClassPackages)
	if first == nil {
		t.Fatal("the first slot was not obtained")
	}

	entered := make(chan struct{})
	go func() {
		if release := b.acquire(ctx, ClassPackages); release != nil {
			defer release()
			close(entered)
		}
	}()
	select {
	case <-entered:
		t.Fatal("two package operations entered at once")
	case <-time.After(200 * time.Millisecond):
	}

	first()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("the released slot was not taken over")
	}
}

// The end of the session must not leave a task waiting for a slot forever.
func TestTheEndOfTheSessionEndsTheWait(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	b := newBudget(1)
	taken := b.acquire(ctx, ClassPackages)
	if taken == nil {
		t.Fatal("no slot was obtained")
	}
	defer taken()

	cancel()
	if release := b.acquire(ctx, ClassPackages); release != nil {
		t.Fatal("a slot was obtained after the session ended")
	}
}

// The class of a task follows from the type of the operation, not from a name
// passed in from outside.
func TestTheTaskClassFollowsFromTheOperationType(t *testing.T) {
	cases := []struct {
		name    string
		request *agentv1.TaskEnvelope
		class   string
	}{
		{"a plan", &agentv1.TaskEnvelope{Action: &agentv1.TaskEnvelope_PackagePlan{}}, ClassPackages},
		{"a transaction", &agentv1.TaskEnvelope{Action: &agentv1.TaskEnvelope_PackageUpgrade{}}, ClassPackages},
		{"a repair", &agentv1.TaskEnvelope{Action: &agentv1.TaskEnvelope_PackagesRepair{}}, ClassPackages},
		{"a unit", &agentv1.TaskEnvelope{Action: &agentv1.TaskEnvelope_UnitAction{}}, ClassGeneral},
		{"a journal", &agentv1.TaskEnvelope{Action: &agentv1.TaskEnvelope_ReadJournal{}}, ClassGeneral},
		{"no operation", &agentv1.TaskEnvelope{}, ClassGeneral},
	}
	for _, tc := range cases {
		if got := taskClass(tc.request); got != tc.class {
			t.Errorf("%s: class = %q, expected %q", tc.name, got, tc.class)
		}
	}
}
