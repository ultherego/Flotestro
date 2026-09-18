package gateway

import (
	"testing"
	"time"
)

var commandNow = time.Date(2026, 9, 18, 9, 0, 0, 0, time.UTC)

// heldSession is the session of a host as the registry of an instance
// holds it, with the token its claim on the host got.
func heldSession(id, hostID string, token uint64) *Session {
	session := NewSession(id, hostID, "1.0.0", "boot", "10.0.0.7:41000", 1)
	session.FenceToken = token
	return session
}

func addressedCommand(session *Session) Command {
	return Command{
		ID: "8a0f0d12-0000-4000-8000-000000000001", HostID: session.HostID,
		SessionID: session.ID, FencingToken: session.FenceToken,
		Kind: CommandSessionClose, ExpiresAt: commandNow.Add(time.Minute),
	}
}

// TestACommandIsCarriedOutOnTheSessionItNames guards the ordinary case:
// the instance that still holds the very session the order names carries
// it out.
func TestACommandIsCarriedOutOnTheSessionItNames(t *testing.T) {
	session := heldSession("6f1b7b3e-0000-4000-8000-000000000010", "host-1", 7)
	if ok, reason := addressedCommand(session).carriedBy(session, true, commandNow); !ok {
		t.Fatalf("the order addressed to the held session was refused: %s", reason)
	}
}

// TestACommandWhoseSessionIsGoneIsNotCarriedOut guards the property the
// whole table exists for: the ownership row may still name a session the
// registry no longer holds - the stream ended a moment ago, the release
// has not been written yet - and a final task sent into it would be a
// handshake nobody answered, recorded as if the host had cooperated.
func TestACommandWhoseSessionIsGoneIsNotCarriedOut(t *testing.T) {
	session := heldSession("6f1b7b3e-0000-4000-8000-000000000010", "host-1", 7)
	command := addressedCommand(session)
	if ok, reason := command.carriedBy(nil, false, commandNow); ok || reason == "" {
		t.Fatalf("an order was carried out on an instance holding no session of the host: %s", reason)
	}
}

// TestACommandOfAnotherSessionIsNotCarriedOut guards against the host
// reconnecting here in the meantime: the instance holds a session of the
// host, but not the one the decision was taken on.
func TestACommandOfAnotherSessionIsNotCarriedOut(t *testing.T) {
	command := addressedCommand(heldSession("6f1b7b3e-0000-4000-8000-000000000010", "host-1", 7))
	newer := heldSession("6f1b7b3e-0000-4000-8000-000000000011", "host-1", 8)
	if ok, _ := command.carriedBy(newer, true, commandNow); ok {
		t.Fatal("an order was carried out on a session other than the one it named")
	}
}

// TestAStaleFencingTokenIsRefused guards the fence itself: the session
// identifier may be reused in a row written by hand, and the token is what
// says the claim is the same one. A token the host has grown past belongs
// to a claim that was superseded.
func TestAStaleFencingTokenIsRefused(t *testing.T) {
	session := heldSession("6f1b7b3e-0000-4000-8000-000000000010", "host-1", 7)
	command := addressedCommand(session)
	command.FencingToken = 6
	if ok, _ := command.carriedBy(session, true, commandNow); ok {
		t.Fatal("an order carrying a superseded fencing token was carried out")
	}
}

// TestAnExpiredCommandIsNotCarriedOut guards the bound on the wait: an
// order claimed after its moment has passed is a decision acted on late,
// when the host may have moved on and the operator has long been told
// something else.
func TestAnExpiredCommandIsNotCarriedOut(t *testing.T) {
	session := heldSession("6f1b7b3e-0000-4000-8000-000000000010", "host-1", 7)
	command := addressedCommand(session)
	command.ExpiresAt = commandNow.Add(-time.Second)
	if ok, _ := command.carriedBy(session, true, commandNow); ok {
		t.Fatal("an expired order was carried out")
	}
}

// TestOnlyTheKnownKindsAreQueued guards that a kind this release does not
// carry out is refused when the order is written rather than dropped when
// it is read: the instance that gave the order has to learn at once.
func TestOnlyTheKnownKindsAreQueued(t *testing.T) {
	for _, kind := range []string{CommandDecommissionFinal, CommandSessionClose} {
		if !KnownCommandKind(kind) {
			t.Fatalf("the kind %s is not recognised", kind)
		}
	}
	if KnownCommandKind("reboot_everything") {
		t.Fatal("an unknown kind was accepted")
	}
}

// TestASettledResultIsRecognised guards the wait: an empty outcome is a
// command still with its owner, not a command that failed.
func TestASettledResultIsRecognised(t *testing.T) {
	if (CommandResult{}).Settled() {
		t.Fatal("an order without an outcome was read as settled")
	}
	if !(CommandResult{Outcome: CommandNoSession}).Settled() {
		t.Fatal("an order settled as no_session was read as open")
	}
}
