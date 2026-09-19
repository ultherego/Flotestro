package events

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// recorder keeps what would have been notified.
type recorder struct {
	channel string
	payload string
	calls   int
}

func (r *recorder) Exec(_ context.Context, _ string, args ...any) (pgconn.CommandTag, error) {
	r.calls++
	r.channel, _ = args[0].(string)
	r.payload, _ = args[1].(string)
	return pgconn.CommandTag{}, nil
}

// A turn of an installation order goes out on its own channel, comes back as
// the same event, and reaches only the screen that watches that order.
func TestAnEnrollmentTurnTravelsAsOneEvent(t *testing.T) {
	through := &recorder{}
	change := EnrollmentChange{RequestID: "order-1", Change: EnrollmentRedeemed,
		Site: "lab", Environment: "test", Kind: "agent", HostID: "host-1"}
	if err := PublishEnrollment(context.Background(), through, change); err != nil {
		t.Fatal(err)
	}
	if through.channel != enrollmentChannel {
		t.Errorf("the turn went out on %q", through.channel)
	}
	event := parseProgress(through.payload)
	if event.Enrollment == nil || *event.Enrollment != change {
		t.Errorf("the turn came back as %+v", event.Enrollment)
	}
	if event.JobID != "" || event.Outbox != nil {
		t.Errorf("the turn pretends to be something else: %+v", event)
	}
	if !ForEnrollment("order-1")(event) || ForEnrollment("order-2")(event) || ForJob("order-1")(event) {
		t.Error("the filters do not tell the order apart")
	}

	before := through.calls
	if err := PublishEnrollment(context.Background(), through, EnrollmentChange{Change: EnrollmentCreated}); err != nil {
		t.Fatal(err)
	}
	if through.calls != before {
		t.Error("a turn without an order was notified")
	}
	if err := PublishEnrollment(context.Background(), nil, change); err != nil {
		t.Errorf("without a notifier: %v", err)
	}
}
