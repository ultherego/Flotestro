package firewall

import (
	"errors"
	"slices"
	"strings"
)

// ErrZoneCaptureEmpty says a captured listing printed no zone at all. It is
// its own error because the alternative is a false pass: two listings with no
// zones have the same fingerprint and nothing between them, so an unreadable
// capture would read as two configurations that agree.
var ErrZoneCaptureEmpty = errors.New("the captured listing names no zone, so it is not an answer about this host")

// ZoneCaptureComparison is what one pair of captured zone listings of a single
// host says: the zones each configuration printed, the fingerprint a zone
// change is guarded with, every difference the panel can name, and whether a
// zone change on that host is refused because of them.
type ZoneCaptureComparison struct {
	// RuntimeZones and PermanentZones are the zone names each configuration
	// printed, in the order it printed them.
	RuntimeZones   []string
	PermanentZones []string
	// RuntimeDigest and PermanentDigest are ZoneListingsDigest of each side.
	RuntimeDigest   string
	PermanentDigest string
	// Drift is every difference between the two, the modelled entries and the
	// fields alike, assembled the way the agent assembles it.
	Drift []Drift
	// Refusal is what the panel would tell an operator who ordered a zone
	// change on this host, or empty when it would take the order.
	Refusal string
}

// CompareZoneCaptures compares the two configurations of one host as
// firewall-cmd printed them, with the same functions the agent uses on the
// host itself: the modelled entries through ParseZones and ZoneDrift, the rest
// of the fields through ZoneFieldDrift. A side that parses to no zone is
// refused rather than compared.
//
// defaultZone is what firewall-cmd --get-default-zone said, because firewalld
// keeps one default for both configurations and ParseZones is given it.
func CompareZoneCaptures(runtime, permanent, defaultZone string) (ZoneCaptureComparison, error) {
	runtimeListings := ZoneListings(runtime)
	permanentListings := ZoneListings(permanent)
	if len(runtimeListings) == 0 {
		return ZoneCaptureComparison{}, &zoneCaptureError{side: "the running configuration", err: ErrZoneCaptureEmpty}
	}
	if len(permanentListings) == 0 {
		return ZoneCaptureComparison{}, &zoneCaptureError{side: "the kept configuration", err: ErrZoneCaptureEmpty}
	}
	drift := ZoneDrift(ParseZones(runtime, defaultZone), ParseZones(permanent, defaultZone), "", "")
	drift = append(drift, ZoneFieldDrift(runtimeListings, permanentListings)...)
	comparison := ZoneCaptureComparison{
		RuntimeZones:    zoneListingNames(runtimeListings),
		PermanentZones:  zoneListingNames(permanentListings),
		RuntimeDigest:   ZoneListingsDigest(runtimeListings),
		PermanentDigest: ZoneListingsDigest(permanentListings),
		Drift:           drift,
		Refusal:         ZoneReloadRefusal(drift),
	}
	return comparison, nil
}

// Agree says whether the two configurations of the host agree, by the same
// definition a zone change is guarded with: the same zones, the same
// fingerprint, and nothing left for a reload to impose.
func (c ZoneCaptureComparison) Agree() bool {
	return slices.Equal(c.RuntimeZones, c.PermanentZones) &&
		c.RuntimeDigest == c.PermanentDigest && len(c.Drift) == 0
}

// Disagreement says in one sentence why the two configurations do not agree,
// or is empty when they do. It names the first difference rather than all of
// them, because the first one is the one to settle.
func (c ZoneCaptureComparison) Disagreement() string {
	if !slices.Equal(c.RuntimeZones, c.PermanentZones) {
		return "it filters with the zones " + strings.Join(c.RuntimeZones, " ") +
			" and keeps the zones " + strings.Join(c.PermanentZones, " ")
	}
	if len(c.Drift) > 0 {
		return c.Drift[0].Detail
	}
	if c.RuntimeDigest != c.PermanentDigest {
		return "the fingerprints differ (filters with " + c.RuntimeDigest +
			", keeps " + c.PermanentDigest + ") and no named difference says why, " +
			"which is a field zoneListingNormalisation has yet to account for"
	}
	return ""
}

// Names says whether any named difference quotes the given text - the port a
// check planted into the kept configuration, say. It reads the whole of each
// difference, because the entry and the sentence are both what the panel tells
// the operator.
func (c ZoneCaptureComparison) Names(text string) bool {
	for _, difference := range c.Drift {
		if strings.Contains(difference.Rule, text) || strings.Contains(difference.Detail, text) {
			return true
		}
	}
	return false
}

// zoneListingNames is the zone names of one listing, in the order printed.
func zoneListingNames(listings []ZoneListing) []string {
	names := make([]string, 0, len(listings))
	for _, listing := range listings {
		names = append(names, listing.Name)
	}
	return names
}

// zoneCaptureError names which of the two captures could not answer, keeping
// the sentinel underneath so a caller can still test for the cause.
type zoneCaptureError struct {
	side string
	err  error
}

func (e *zoneCaptureError) Error() string { return e.side + ": " + e.err.Error() }
func (e *zoneCaptureError) Unwrap() error { return e.err }
