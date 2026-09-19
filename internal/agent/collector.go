package agent

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"sync"
)

// collector runs the inventory collection outside the message receive loop.
type collector struct {
	// A capacity of one folds the requests together: another collection during
	// one already running would return the same state, so one in reserve is
	// enough.
	requests chan struct{}

	mu sync.Mutex
	// waiting collects the requests awaiting the next collection.
	waiting []chan Refresh
	// current are the requests covered by a collection that is already running.
	current []chan Refresh
	// scope collects the modules ordered by the waiting requests. An order for
	// the whole inventory absorbs every partial one.
	scope map[string]bool
	full  bool
}

// Refresh is the result of an inventory collection made on request.
type Refresh struct {
	// Revision is the revision of the picture that came out of this collection.
	Revision string
	// Changed says whether the picture differs from the previous one. No change
	// is not an error: a host that has not changed is a true answer.
	Changed bool
	// Modules lists what was really read.
	Modules []string
	Err     error
}

// ErrSessionEnded means the session ended before the refresh.
var ErrSessionEnded = errors.New("session_ended")

func newCollector() *collector {
	return &collector{requests: make(chan struct{}, 1), scope: map[string]bool{}}
}

// request orders a collection of the whole inventory and never blocks the
// caller.
func (c *collector) request() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.addScope(nil)
	c.enqueue()
}

// requestModules orders a collection of the given modules and never blocks the
// caller.
func (c *collector) requestModules(modules []string) {
	if len(modules) == 0 {
		c.request()
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.addScope(modules)
	c.enqueue()
}

// refresh orders a collection and waits for its result. This is the path of
// the inventory.
func (c *collector) refresh(ctx context.Context, modules []string) Refresh {
	answer := make(chan Refresh, 1)

	// Signing up and ordering go under one lock.
	c.mu.Lock()
	c.waiting = append(c.waiting, answer)
	c.addScope(modules)
	c.enqueue()
	c.mu.Unlock()

	select {
	case <-ctx.Done():
		return Refresh{Err: ctx.Err()}
	case result := <-answer:
		return result
	}
}

// enqueue puts an order in the collection queue.
func (c *collector) enqueue() {
	select {
	case c.requests <- struct{}{}:
	default:
	}
}

// addScope adds the modules to the scope of the next collection. Requires the
// lock to be held.
func (c *collector) addScope(modules []string) {
	if len(modules) == 0 {
		// The whole inventory absorbs every partial order.
		c.full = true
		return
	}
	for _, name := range modules {
		c.scope[name] = true
	}
}

// takeScope opens a collection: it takes over the waiting requests and their
// scope.
func (c *collector) takeScope() ([]string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.full && len(c.scope) == 0 && len(c.waiting) == 0 {
		return nil, false
	}
	c.current, c.waiting = c.waiting, nil
	if c.full || len(c.scope) == 0 {
		c.full = false
		return nil, true
	}
	modules := make([]string, 0, len(c.scope))
	for name := range c.scope {
		modules = append(modules, name)
	}
	clear(c.scope)
	slices.Sort(modules)
	return modules, true
}

// broadcast gives the result to the requests covered by the collection and
// closes them.
func (c *collector) broadcast(result Refresh) {
	c.mu.Lock()
	current := c.current
	c.current = nil
	c.mu.Unlock()
	for _, answer := range current {
		answer <- result
	}
}

// finish dismisses all the waiting requests, including those outside the
// current collection: after the end of the session nobody will serve them.
func (c *collector) finish(err error) {
	c.mu.Lock()
	waiting := append(c.current, c.waiting...)
	c.current, c.waiting = nil, nil
	c.mu.Unlock()
	for _, answer := range waiting {
		answer <- Refresh{Err: err}
	}
}

// run serves the orders until the end of the context.
func (c *collector) run(ctx context.Context, collect func(context.Context, []string) (Facts, error),
	accept func(Facts, []string) (Refresh, error), log *slog.Logger) error {
	defer c.finish(ErrSessionEnded)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-c.requests:
			modules, ok := c.takeScope()
			if !ok {
				continue
			}
			fresh, err := collect(ctx, modules)
			if err != nil {
				log.Error("the inventory was not collected", "err", err, "modules", modules)
				c.broadcast(Refresh{Err: err, Modules: modules})
				continue
			}
			result, err := accept(fresh, modules)
			if err != nil {
				c.broadcast(Refresh{Err: err, Modules: modules})
				return err
			}
			result.Modules = modules
			c.broadcast(result)
		}
	}
}
