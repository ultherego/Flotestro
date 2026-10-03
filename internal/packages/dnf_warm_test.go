package packages

import (
	"errors"
	"strings"
	"testing"
)

// The step that leaves the metadata cache in a shape the unprivileged read can
// use used to throw its result away, so a refresh reported success over a cache
// it had not compiled - and the agent's next plan then failed with a filesystem
// error no operator can act on. 03.10.
func TestTheWarmedCacheIsAnswerableFor(t *testing.T) {
	for _, c := range []struct {
		name   string
		result commandResult
		fails  bool
		says   string
	}{
		// check-update answers 100 when there is something to update and 0 when
		// there is not. Both got as far as compiling the cache, which is all this
		// step asks of it.
		{"nothing to update", commandResult{Ran: true, ExitCode: 0}, false, ""},
		{"updates waiting", commandResult{Ran: true, ExitCode: 100}, false, ""},
		// Everything else is an answer.
		{"the read failed", commandResult{Ran: true, ExitCode: 1, Stderr: "cannot create temporary file"},
			true, "cannot create temporary file"},
		// A tool that never started leaves the cache exactly as it was.
		{"never started", commandResult{Ran: false, Err: errors.New("dnf: the tool is missing")},
			true, "the tool is missing"},
		// So does one the timeout killed.
		{"killed by the timeout", commandResult{Ran: false, Err: errors.New("context deadline exceeded")},
			true, "context deadline exceeded"},
		// And one that says nothing at all about why.
		{"no reason given", commandResult{Ran: false}, true, "it did not run"},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := warmedTheCache(c.result)
			if c.fails && err == nil {
				t.Fatal("the cache was reported as compiled")
			}
			if !c.fails && err != nil {
				t.Fatalf("a compiled cache was reported as a failure: %v", err)
			}
			if c.fails && !strings.Contains(err.Error(), c.says) {
				t.Errorf("the failure does not say %q: %v", c.says, err)
			}
		})
	}
}
