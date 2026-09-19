package notify

import (
	"testing"
	"time"
)

// A silence that names no host now really exists - the panel can write one -
// so the two shapes have to be told apart: a fleet-wide silence covers the
// ordinary alerts of every host, and only a global one reaches the security
// alerts of the installation.
func TestDecideSeparatesTheFleetWideSilenceFromTheGlobalOne(t *testing.T) {
	until := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	fleet := silence{ID: "f1", Until: until, Reason: "network migration"}
	global := silence{ID: "g1", Until: until, Reason: "incident bridge open", Global: true}

	if verdict := Decide(SubjectSecurity, "h1", []silence{fleet}, nil); verdict.Suppressed {
		t.Errorf("a fleet-wide silence that is not global kept back a security alert: %+v", verdict)
	}
	if verdict := Decide("alert.fired", "h1", []silence{fleet}, nil); !verdict.Suppressed || verdict.PolicyID != "f1" {
		t.Errorf("a fleet-wide silence let an ordinary alert of a host through: %+v", verdict)
	}

	// Both in force: the global one is read first, and each alert is kept
	// back by the silence that was written for it.
	both := []silence{global, fleet}
	if verdict := Decide(SubjectSecurity, "h1", both, nil); !verdict.Suppressed || verdict.PolicyID != "g1" {
		t.Errorf("the security alert was not kept back by the global silence: %+v", verdict)
	}
	if verdict := Decide("alert.fired", "h1", both, nil); !verdict.Suppressed || verdict.PolicyID != "f1" {
		t.Errorf("the ordinary alert was not kept back by the fleet-wide silence: %+v", verdict)
	}
}

// A global silence names no host, so it stands whatever host the event
// carries - including an event that names none.
func TestDecideAppliesAGlobalSilenceWithoutAHost(t *testing.T) {
	until := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	global := silence{ID: "g1", Until: until, Reason: "incident bridge open", Global: true}

	verdict := Decide(SubjectSecurity, "", []silence{global}, nil)
	if !verdict.Suppressed || verdict.Reason != SuppressedBySilence {
		t.Errorf("a security alert without a host escaped the global silence: %+v", verdict)
	}
	// The window belongs to a host; it never reaches a security alert.
	window := &maintenance{Until: until, Reason: "kernel patching"}
	if verdict := Decide(SubjectSecurity, "h1", nil, window); verdict.Suppressed {
		t.Errorf("a maintenance window kept back a security alert: %+v", verdict)
	}
}
