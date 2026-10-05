package firewall

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strconv"
	"strings"
)

// SealFingerprint folds what the host said about its zones into the snapshot's
// fingerprint, and is the only thing that decides what a plan is made against.
//
// A fingerprint taken from the running ruleset alone cannot see a firewalld
// zone change: firewall-cmd --permanent writes the zone file and leaves the
// nftables underneath untouched until a reload. A zone plan therefore passed
// its own precondition while the zone it was about had moved, and the inverse
// it had armed restored the state of a host that no longer existed.
//
// Folding in the running zones alone did not fix that, because the running
// zones are not what --permanent writes either. Both configurations are in
// here, each under its own tag and with its own "was not read" state.
func SealFingerprint(snapshot *Snapshot) {
	// A host that is not firewalld has nothing to add, but it still passes
	// here: one function answers for every adapter, so neither side of the
	// comparison can be computed a second way.
	sum := sha256.New()
	sum.Write([]byte("ruleset\x00" + snapshot.Hash + "\x00"))
	// An unreadable firewall used to leave the fingerprint empty, and an empty
	// expected fingerprint is how a plan says it has no precondition - so a
	// plan made while the host could not be read was applied unguarded.
	if snapshot.UnavailableReason != "" {
		sum.Write([]byte("ruleset-unknown\x00" + snapshot.UnavailableReason + "\x00"))
	}
	// Both configurations are folded in, under tags of their own. The running
	// one alone cannot see a permanent-only change, which is exactly what a
	// zone change writes: a third party's --permanent between the plan and the
	// apply left the fingerprint still, and our reload then activated it.
	writeZones(sum, "zones", snapshot.Zones, snapshot.ZonesReason, snapshot.ZonesDigest)
	writeZones(sum, "permanent-zones", snapshot.PermanentZones, snapshot.PermanentZonesReason,
		snapshot.PermanentZonesDigest)
	snapshot.Hash = hex.EncodeToString(sum.Sum(nil)[:12])
}

// writeZones folds one zone configuration into the fingerprint under its own
// tag: the zones the panel models, and the digest of everything firewalld
// printed about them. Not knowing the configuration is its own state, and must
// not read as a host with no zones: a plan made while it was readable may not
// match a run that could not read it.
func writeZones(sum io.Writer, tag string, zones []Zone, reason, digest string) {
	if reason != "" {
		_, _ = sum.Write([]byte(tag + "-unknown\x00" + reason + "\x00"))
		return
	}
	_, _ = sum.Write([]byte(tag + "\x00" + strconv.Itoa(len(zones)) + "\x00"))
	for _, zone := range zones {
		_, _ = sum.Write([]byte(canonicalZone(zone)))
	}
	// The listing digest carries the fields the zones above do not model, so a
	// rich rule written between the plan and the apply stops the apply.
	_, _ = sum.Write([]byte(tag + "-listing\x00" + digest + "\x00"))
}

// canonicalZone writes one zone in a form where every part is length-prefixed,
// so no arrangement of names, services or ports can read as another.
func canonicalZone(zone Zone) string {
	var out strings.Builder
	field := func(parts ...string) {
		for _, part := range parts {
			out.WriteString(strconv.Itoa(len(part)))
			out.WriteString(":")
			out.WriteString(part)
		}
	}
	field(zone.Name, zone.Target)
	field(strconv.FormatBool(zone.Active), strconv.FormatBool(zone.Default))
	for _, list := range [][]string{zone.Interfaces, zone.Sources, zone.Services, zone.Ports} {
		field(strconv.Itoa(len(list)))
		field(list...)
	}
	return out.String()
}
