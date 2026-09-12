package agent

import (
	"context"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
)

// The resource classes of the host. Tasks of one class compete with each other
// and not with the whole management of the host.
const (
	// ClassPackages covers the operations of the package manager. A limit of one
	// is not caution: two apt runs at once rebuild the same cache and together
	// take longer than one after the other.
	ClassPackages = "packages"
	// ClassGeneral is the rest: unit operations, journal reads, state.
	ClassGeneral = "general"
)

// budget watches how many tasks of a given class may run at once.
//
// A shared pool for all tasks had a flaw visible from the panel: two long
// package reads took both slots, and an operation lasting milliseconds waited
// behind them for a minute. The host then looked hung although it was working.
type budget struct {
	slots map[string]chan struct{}
}

func newBudget(general int) *budget {
	if general <= 0 {
		general = 2
	}
	return &budget{slots: map[string]chan struct{}{
		ClassPackages: make(chan struct{}, 1),
		ClassGeneral:  make(chan struct{}, general),
	}}
}

// acquire waits for a slot in the class of the task. The returned function
// releases it; nil means the session ended before a slot was obtained.
func (b *budget) acquire(ctx context.Context, class string) func() {
	slots, ok := b.slots[class]
	if !ok {
		slots = b.slots[ClassGeneral]
	}
	select {
	case slots <- struct{}{}:
		return func() { <-slots }
	case <-ctx.Done():
		return nil
	}
}

// taskClass recognizes the resource class by the type of the operation. An
// unknown operation lands in the general class: an unknown cost must not block
// the whole package class, and it still passes through the general limit.
func taskClass(task *agentv1.TaskEnvelope) string {
	switch task.GetAction().(type) {
	case *agentv1.TaskEnvelope_PackagePlan,
		*agentv1.TaskEnvelope_PackageUpgrade,
		*agentv1.TaskEnvelope_PackagesRepair:
		return ClassPackages
	default:
		return ClassGeneral
	}
}
