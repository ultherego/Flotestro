package agent

import (
	"testing"
	"time"
)

// TestTheRenewalThreshold guards the margin for a failure of the centre. The
// renewal is to start long before the expiry and not in the last hour: an agent
// without a valid certificate has no way back into the fleet, because the
// enrollment token is no longer on the host.
func TestTheRenewalThreshold(t *testing.T) {
	now := time.Now()
	issued := now.Add(-20 * 24 * time.Hour)
	expires := now.Add(10 * 24 * time.Hour)

	// A fresh certificate: two thirds of the period still ahead.
	if needsRenewal(now.Add(25*24*time.Hour), now.Add(-5*24*time.Hour)) {
		t.Error("a fresh certificate needs no renewal")
	}
	// Less than a third of the period is left.
	if !needsRenewal(expires, issued.Add(-10*24*time.Hour)) {
		t.Error("a certificate past two thirds of its period needs a renewal")
	}
	// An already expired certificate all the more so.
	if !needsRenewal(now.Add(-time.Hour), issued) {
		t.Error("an expired certificate needs a renewal")
	}
	// An unknown deadline must not mean "there is still plenty of time".
	if !needsRenewal(time.Time{}, time.Time{}) {
		t.Error("an undetermined deadline needs an attempt to renew")
	}
}

// TestTheCheckIntervalScales with the lifetime of the certificate: a fixed
// interval would be useless with a short deadline and needlessly frequent with
// a long one.
func TestTheCheckIntervalScales(t *testing.T) {
	now := time.Now()

	long := checkInterval(now.Add(365*24*time.Hour), now)
	if long != maxRenewalCheckInterval {
		t.Errorf("for a one-year certificate the interval = %s, expected %s", long, maxRenewalCheckInterval)
	}

	short := checkInterval(now.Add(20*time.Minute), now)
	if short != minRenewalCheckInterval {
		t.Errorf("for a 20-minute certificate the interval = %s, expected %s", short, minRenewalCheckInterval)
	}

	medium := checkInterval(now.Add(24*time.Hour), now)
	if medium != 24*time.Hour/20 {
		t.Errorf("for a one-day certificate the interval = %s", medium)
	}

	// A deadline from a moment ago must not give a zero interval and a polling
	// loop.
	if zero := checkInterval(now, now); zero < minRenewalCheckInterval {
		t.Errorf("the interval %s risks polling in a loop", zero)
	}
}
