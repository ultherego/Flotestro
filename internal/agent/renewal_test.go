package agent

import (
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/pki"
)

// A renewal verified the certificate it brought against the trust the host
// already held and then wrote the whole bundle that came with it. The
// certificate says nothing about the bundle: an answer carrying a correct
// certificate under the existing authority and that authority plus a rogue one
// appended passed, and the host wrote the rogue authority down as one of the
// fleet's - which a relay, trusted to carry the answer and not to decide what
// the host trusts, could do to every host that renews (audit of 6c38561,
// TR-04).
func TestAChangedSetOfAuthoritiesIsAdoptedOnlyOnTheWordOfOne(t *testing.T) {
	fleet, err := pki.EnsureTrust(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	held := fleet.Bundle()

	// The same set, with nobody vouching: an ordinary renewal, which is the
	// overwhelming majority of them.
	if err := adoptableTrust(held, held, nil); err != nil {
		t.Fatalf("a renewal that changes nothing was refused: %v", err)
	}
	// A host with no trust yet has nothing to judge against; that is the
	// enrollment, and it is not this function's question.
	if err := adoptableTrust(nil, held, nil); err != nil {
		t.Fatalf("a host without trust was refused its first bundle: %v", err)
	}

	// Somebody else's authority, appended. It is a valid CA, and the
	// certificate in the same answer verifies under the old trust.
	rogue, err := pki.EnsureTrust(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	foreign := append(append([]byte(nil), held...), rogue.Bundle()...)
	if err := adoptableTrust(held, foreign, nil); err == nil {
		t.Fatal("a foreign authority appended to the bundle was adopted")
	}
	// Vouched for by the authority that wants in, which is the answer vouching
	// for itself.
	byItself, err := rogue.Active().SignTrustBundle(foreign)
	if err != nil {
		t.Fatal(err)
	}
	if err := adoptableTrust(held, foreign, byItself); err == nil {
		t.Fatal("a foreign authority that vouched for itself was adopted")
	}
	// And a signature over another set does not carry this one.
	elsewhere, err := fleet.Active().SignTrustBundle(held)
	if err != nil {
		t.Fatal(err)
	}
	if err := adoptableTrust(held, foreign, elsewhere); err == nil {
		t.Fatal("a signature over the old set was taken as a vouch for the new one")
	}

	// The rotation, which is what this path exists for: the panel prepares an
	// authority, the bundle grows, and the authority in force says so.
	if _, err := fleet.Prepare(); err != nil {
		t.Fatal(err)
	}
	rotated := fleet.Bundle()
	vouch, err := fleet.Active().SignTrustBundle(rotated)
	if err != nil {
		t.Fatal(err)
	}
	if err := adoptableTrust(held, rotated, vouch); err != nil {
		t.Fatalf("a prepared authority of the fleet was refused: %v", err)
	}
	// Without the vouch the same rotation waits: the host keeps the trust it
	// has rather than taking a set on the word of whoever delivered it.
	if err := adoptableTrust(held, rotated, nil); err == nil {
		t.Fatal("a changed bundle was adopted with no authority vouching for it")
	}
	// A set that takes an authority away is a change like any other.
	shrunk := rogue.Bundle()
	if err := adoptableTrust(rotated, shrunk, nil); err == nil {
		t.Fatal("a bundle that drops every authority the host trusts was adopted")
	}
}

// TestTheRenewalThreshold guards the margin for a failure of the centre.
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
