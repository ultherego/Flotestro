package vuln

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/leases"
)

// A pass writes the assessment of a host under the lease it holds, and the
// lease is asserted by the write itself. A pass that runs or pauses past the
// term loses the lease, another instance finishes a fresher assessment, and
// the first one used to come back and write over it - it had checked the lease
// half an hour earlier and the check said nothing about this moment (audit of
// 6c38561, OBS-01).
func TestAnAssessmentIsWrittenOnlyUnderALeaseThatIsHeld(t *testing.T) {
	ctx := context.Background()
	// No pool is touched: a write that carries nothing to be fenced by is
	// refused before the statement goes out.
	store := NewStore(nil)
	if err := store.SaveAdvisories(ctx, leases.Lease{}, "host", nil, HostState{}); !errors.Is(err, leases.ErrLost) {
		t.Errorf("an assessment written without a lease answered %v, expected ErrLost", err)
	}
	if err := store.RecordEvaluationFailure(ctx, leases.Lease{}, "host", SourceSave,
		time.Now()); !errors.Is(err, leases.ErrLost) {
		t.Errorf("a failure written without a lease answered %v, expected ErrLost", err)
	}
	// A name without a holder is a lease nobody holds, which fences nothing.
	if (leases.Lease{Name: correlatorLease}).Carried() {
		t.Error("a lease with no holder reads as something a write can be fenced by")
	}
	if !(leases.Lease{Name: correlatorLease, Holder: "11111111-1111-1111-1111-111111111111"}).Carried() {
		t.Error("a held lease reads as nothing a write can be fenced by")
	}

	// The condition the statement carries names the three columns that decide,
	// the term among them, and its parameters are the ones Args gives in that
	// order.
	condition := leases.HoldCondition(5)
	for _, want := range []string{"name = $5", "holder = $6::uuid", "token = $7", "lease_until > now()"} {
		if !strings.Contains(condition, want) {
			t.Errorf("the fence does not carry %s: %s", want, condition)
		}
	}
	args := leases.Lease{Name: "a", Holder: "b", Token: 3}.Args()
	if len(args) != 3 || args[0] != "a" || args[1] != "b" || args[2] != int64(3) {
		t.Errorf("the fence's parameters are %v, not the name, the holder and the token", args)
	}
}
