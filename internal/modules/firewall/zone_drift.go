package firewall

import (
	"slices"
	"sort"
	"strconv"
	"strings"
)

// The reasons the two firewalld configurations of a host differ. A zone change
// writes the permanent configuration and then reloads, and a reload makes the
// whole permanent configuration the running one - so every difference listed
// here is something our own change would carry along with it.
const (
	// DriftZonePending: the permanent configuration carries the entry and the
	// host is not filtering with it. The next reload - ours or anybody's -
	// brings it into force.
	DriftZonePending = "firewalld_zone_pending"
	// DriftZoneRuntimeOnly: the host filters with the entry and the permanent
	// configuration does not carry it. The next reload takes it away.
	DriftZoneRuntimeOnly = "firewalld_zone_runtime_only"
	// DriftZoneNotComparable: one of the two configurations was not read, so
	// nothing is known about the difference between them. Not knowing is not
	// agreement.
	DriftZoneNotComparable = "firewalld_zone_not_comparable"
)

// ZoneDrift compares what firewalld filters with now against what it keeps for
// its next start, which is also what it would load at the next reload.
//
// Interfaces are left out of the comparison on purpose: NetworkManager binds an
// interface to a zone in the running configuration and the permanent zone file
// need not carry that binding, so an interface difference is the ordinary state
// of such a host and is no evidence of a pending change. So is Active: the
// permanent listing has no notion of a zone being active on an interface.
func ZoneDrift(runtime, permanent []Zone, runtimeReason, permanentReason string) []Drift {
	if runtimeReason != "" || permanentReason != "" {
		unread := Drift{Reason: DriftZoneNotComparable,
			Detail: "the two firewalld configurations of this host cannot be compared, because " +
				unreadConfigurations(runtimeReason, permanentReason) +
				"; a reload may therefore carry a change nobody ordered"}
		return []Drift{unread}
	}
	var drift []Drift
	for _, name := range zoneNames(runtime, permanent) {
		running, inRuntime := zoneNamed(runtime, name)
		kept, inPermanent := zoneNamed(permanent, name)
		switch {
		case !inPermanent:
			drift = append(drift, Drift{Reason: DriftZoneRuntimeOnly, Zone: name, Rule: "zone " + name,
				Detail: "the host has the zone " + name + " now and does not keep it, so a reload " +
					"takes the zone and everything in it away"})
		case !inRuntime:
			drift = append(drift, Drift{Reason: DriftZonePending, Zone: name, Rule: "zone " + name,
				Detail: "the host keeps the zone " + name + " and is not using it, so a reload " +
					"brings the zone and everything in it into force"})
		default:
			drift = append(drift, zoneEntryDrift(name, running, kept)...)
		}
	}
	return drift
}

// zoneEntryDrift compares one zone the two configurations both carry.
func zoneEntryDrift(name string, running, kept Zone) []Drift {
	var drift []Drift
	for _, part := range []struct {
		kind    string
		running []string
		kept    []string
	}{
		{"target", targetEntries(running), targetEntries(kept)},
		{"service", running.Services, kept.Services},
		{"port", running.Ports, kept.Ports},
		{"source", running.Sources, kept.Sources},
	} {
		for _, entry := range part.kept {
			if slices.Contains(part.running, entry) {
				continue
			}
			drift = append(drift, Drift{Reason: DriftZonePending, Zone: name,
				Rule: part.kind + " " + entry,
				Detail: "the zone " + name + " keeps " + part.kind + " " + entry +
					" for its next start and the host is not filtering with it, so a reload brings it into force"})
		}
		for _, entry := range part.running {
			if slices.Contains(part.kept, entry) {
				continue
			}
			drift = append(drift, Drift{Reason: DriftZoneRuntimeOnly, Zone: name,
				Rule: part.kind + " " + entry,
				Detail: "the host filters with " + part.kind + " " + entry + " in the zone " + name +
					" and does not keep it, so a reload takes it away"})
		}
	}
	return drift
}

// targetEntries writes the zone target as a list, so it is compared the same
// way as the entries beside it. An unnamed target is no entry rather than the
// target "".
func targetEntries(zone Zone) []string {
	if zone.Target == "" {
		return nil
	}
	return []string{zone.Target}
}

// zoneNames is every zone name either configuration knows, in one order, so
// two readings of one host describe it the same way.
func zoneNames(runtime, permanent []Zone) []string {
	seen := make(map[string]bool, len(runtime)+len(permanent))
	names := make([]string, 0, len(runtime)+len(permanent))
	for _, list := range [][]Zone{runtime, permanent} {
		for _, zone := range list {
			if seen[zone.Name] {
				continue
			}
			seen[zone.Name] = true
			names = append(names, zone.Name)
		}
	}
	sort.Strings(names)
	return names
}

// zoneNamed finds a zone by name and says whether that configuration has it.
func zoneNamed(zones []Zone, name string) (Zone, bool) {
	for _, zone := range zones {
		if zone.Name == name {
			return zone, true
		}
	}
	return Zone{}, false
}

// unreadConfigurations names which of the two readings failed and why.
func unreadConfigurations(runtimeReason, permanentReason string) string {
	unread := make([]string, 0, 2)
	if permanentReason != "" {
		unread = append(unread, "what it keeps for its next start was not read ("+permanentReason+")")
	}
	if runtimeReason != "" {
		unread = append(unread, "what it filters with now was not read ("+runtimeReason+")")
	}
	return strings.Join(unread, " and ")
}

// PendingZoneDrift picks out the differences a reload would act on. A zone
// change ends in a reload, so these are the changes it would carry although
// nobody in the order asked for them.
func PendingZoneDrift(drift []Drift) []Drift {
	var pending []Drift
	for _, entry := range drift {
		switch entry.Reason {
		case DriftZonePending, DriftZoneRuntimeOnly, DriftZoneNotComparable:
			pending = append(pending, entry)
		}
	}
	return pending
}

// zoneRefusalNamed is how many of the pending differences the refusal spells
// out. The rest are counted: the whole list is in the snapshot the panel shows
// beside the refusal.
const zoneRefusalNamed = 3

// ZoneDriftSummary names what a reload of this host would carry with it, or an
// empty string when the two configurations say the same thing. A few
// differences are named and the rest counted; the whole list travels in the
// snapshot beside the message.
func ZoneDriftSummary(drift []Drift) string {
	pending := PendingZoneDrift(drift)
	if len(pending) == 0 {
		return ""
	}
	named := make([]string, 0, zoneRefusalNamed)
	for _, entry := range pending {
		if len(named) == zoneRefusalNamed {
			break
		}
		named = append(named, zoneDriftPhrase(entry))
	}
	rest := ""
	if len(pending) > zoneRefusalNamed {
		rest = " and " + strconv.Itoa(len(pending)-zoneRefusalNamed) + " more"
	}
	return "this host has " + strconv.Itoa(len(pending)) + " difference(s) between what it filters " +
		"with now and what it keeps for its next start that nobody in this order asked for (" +
		strings.Join(named, "; ") + rest + ")"
}

// ZoneReloadRefusal says why a zone change must not be made on this host now,
// or an empty string when nothing is pending. The reload the change ends with
// replaces the running configuration with the permanent one, so a difference
// between them is a change of somebody else's that our order would activate or
// discard without anybody approving it.
func ZoneReloadRefusal(drift []Drift) string {
	summary := ZoneDriftSummary(drift)
	if summary == "" {
		return ""
	}
	return "a zone change ends with a reload, and a reload makes the whole permanent configuration " +
		"of firewalld the running one: " + summary + ". Settle them on the host first - firewall-cmd " +
		"--runtime-to-permanent keeps what it filters with now, firewall-cmd --reload drops it - " +
		"and order the change again"
}

// zoneDriftPhrase names one difference in a few words. A difference about a
// whole zone already names it, so only an entry inside one is prefixed.
func zoneDriftPhrase(entry Drift) string {
	if entry.Reason == DriftZoneNotComparable {
		return entry.Detail
	}
	where := entry.Rule
	if entry.Zone != "" && !strings.HasPrefix(entry.Rule, "zone ") {
		where = "zone " + entry.Zone + " " + entry.Rule
	}
	if entry.Reason == DriftZonePending {
		return where + " is kept and not in force"
	}
	return where + " is in force and not kept"
}
