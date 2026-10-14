//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/cryptostate"
)

// The commands that move the cryptographic identity of an installation -
// import-state, revert-state, rewrap-kek, forget-files - check the state and
// then change it, and part of what they change is files, which are in no
// transaction. What keeps two of them from interleaving is one lock, held for
// the whole command. These tests are over the live installation's database,
// because a lock that two sessions do not actually exclude each other with is
// a lock in name only.

// TestATransitionExcludesASecondOne is the property the four commands stand
// on: while one holds the lock, the next one is refused rather than let in.
func TestATransitionExcludesASecondOne(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	store := cryptostate.NewPostgres(h.database(ctx))

	// A generous wait: a refusal here would mean something else is moving the
	// state of the laboratory's installation, which is worth saying plainly
	// rather than reading as this test's own result.
	release, err := store.LockTransition(ctx, 15*time.Second)
	if err != nil {
		t.Fatalf("the transition lock could not be taken: %v", err)
	}
	released := false
	defer func() {
		if !released {
			release()
		}
	}()

	second, err := store.LockTransition(ctx, 500*time.Millisecond)
	if err == nil {
		second()
		t.Fatal("two transitions held the installation lock at once")
	}
	if !errors.Is(err, cryptostate.ErrTransitionBusy) {
		t.Fatalf("the second transition was refused as %v, want %v", err, cryptostate.ErrTransitionBusy)
	}

	// The lock is the installation's, not the process's: it has to be free for
	// the next command once this one has finished.
	release()
	released = true
	third, err := store.LockTransition(ctx, 15*time.Second)
	if err != nil {
		t.Fatalf("the lock was not free after the transition ahead of it finished: %v", err)
	}
	third()
}

// TestATransitionAndAStartingPanelTakeTheSameLock checks the sharing that the
// exclusion between a transition and a start depends on. The startup guard's
// lock blocks, so it is not called here - what is read instead is the lock the
// database records while a transition holds it, which is the same object the
// guard asks for.
func TestATransitionAndAStartingPanelTakeTheSameLock(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	pool := h.database(ctx)
	store := cryptostate.NewPostgres(pool)

	release, err := store.LockTransition(ctx, 15*time.Second)
	if err != nil {
		t.Fatalf("the transition lock could not be taken: %v", err)
	}
	defer release()

	// "FCRY": the identifier the startup guard names, as a key of this width
	// lands in pg_locks - the whole key in objid, the class left at zero.
	const installationLock = 0x46435259
	var held int
	if err := pool.QueryRow(ctx, `
		select count(*) from pg_locks
		 where locktype = 'advisory' and classid = 0 and objid::bigint = $1 and granted`,
		installationLock).Scan(&held); err != nil {
		t.Fatalf("reading the locks the database holds: %v", err)
	}
	if held == 0 {
		t.Fatalf("a transition is holding the lock and the database records no advisory lock %#x; "+
			"a start and a transition would not exclude each other", installationLock)
	}
}
