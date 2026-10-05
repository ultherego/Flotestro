package firewall

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// DriftZoneFieldDiffers: the two configurations disagree about a field of a
// zone that the panel does not model as a list of its own. It is named rather
// than modelled, because a reload imposes the kept value whether the panel
// understands the field or not.
const DriftZoneFieldDiffers = "firewalld_zone_field_differs"

// ZoneField is one indented "key: value" line of a zone listing.
type ZoneField struct {
	Name string
	// Value is the text on the field's own line.
	Value string
	// Lines are the lines below it that are not fields of their own: the rich
	// rules firewalld prints one per line under "rich rules:". They are kept
	// apart from Value because no modelled list may take them - a continuation
	// under "ports:" would otherwise read as a port the host does not have -
	// while the digest and the comparison cover them either way.
	Lines []string
}

// Text is everything firewalld printed for the field, the lines below it
// included.
func (f ZoneField) Text() string {
	if len(f.Lines) == 0 {
		return f.Value
	}
	if f.Value == "" {
		return strings.Join(f.Lines, "\n")
	}
	return strings.Join(append([]string{f.Value}, f.Lines...), "\n")
}

// ZoneListing is one zone as firewall-cmd printed it: every field, in order,
// including the ones the Zone struct does not model. It is read from the same
// text as Zone and by the same function, so the two cannot disagree about
// where a zone begins or what a field is.
type ZoneListing struct {
	Name string
	// Markers is what the header carried in parentheses: "default, active" in
	// the running listing, "default" in the permanent one.
	Markers string
	Fields  []ZoneField
}

// zoneFieldName is the shape of a field name firewalld prints: lowercase
// words, hyphens and blanks ("target", "icmp-block-inversion", "rich rules").
// A line whose text before the first colon is not of that shape is not a
// field but a continuation of the one above - which is how a rich rule
// carrying an IPv6 address survives being read, colons and all.
var zoneFieldName = regexp.MustCompile(`^[a-z][a-z0-9 -]*$`)

// zoneListingNormalisation is the whole of what the digest and the comparison
// below drop, in one place: a cosmetic difference found on another
// distribution is added here and nowhere else.
//
// Measured on a live Fedora host, the two clean listings of one host
// (testdata/fedora_zones_runtime.txt against fedora_zones_permanent.txt)
// differ in exactly two things and in nothing else:
//
//   - the parenthesised marker on the zone header, "(default, active)" against
//     "(default)". ZoneListings keeps it in Markers and never as a field, and
//     neither the digest nor the comparison reads Markers.
//   - the interfaces field, named below: NetworkManager binds an interface in
//     the running configuration and the permanent zone file need not carry the
//     binding.
var zoneListingNormalisation = []string{"interfaces"}

// zoneFieldsTyped are the fields ZoneDrift already compares entry by entry,
// naming the entry that moved. They are left out of the field comparison so
// one difference is not reported twice - the digest covers them all the same.
var zoneFieldsTyped = []string{"target", "sources", "services", "ports"}

// ZoneListings reads every field of every zone out of the output of
// firewall-cmd --list-all-zones, of either configuration.
func ZoneListings(output string) []ZoneListing {
	var listings []ZoneListing
	var current *ZoneListing

	for _, raw := range strings.Split(output, "\n") {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		// A zone header starts at the beginning of the row; everything about a
		// zone is indented. This is the one place that decides where a zone
		// begins, for the typed zones and for the fields alike.
		if !strings.HasPrefix(raw, " ") && !strings.HasPrefix(raw, "\t") {
			fields := zoneHeader.FindStringSubmatch(strings.TrimSpace(raw))
			if fields == nil {
				current = nil
				continue
			}
			listings = append(listings, ZoneListing{Name: fields[1], Markers: fields[2]})
			current = &listings[len(listings)-1]
			continue
		}
		if current == nil {
			continue
		}
		if name, value, ok := strings.Cut(strings.TrimSpace(raw), ":"); ok &&
			zoneFieldName.MatchString(name) {
			current.Fields = append(current.Fields, ZoneField{Name: name, Value: strings.TrimSpace(value)})
			continue
		}
		// A line that is not a field of its own belongs to the field above it.
		// A zone whose first indented line is such a line has nothing to
		// belong to and is left alone.
		if len(current.Fields) == 0 {
			continue
		}
		last := &current.Fields[len(current.Fields)-1]
		last.Lines = append(last.Lines, strings.TrimSpace(raw))
	}
	return listings
}

// Field returns everything printed for one field of a zone listing, and
// whether it was printed at all. A field firewalld did not print is not a
// field with an empty value.
func (l ZoneListing) Field(name string) (string, bool) {
	field, printed := l.field(name)
	return field.Text(), printed
}

func (l ZoneListing) field(name string) (ZoneField, bool) {
	for _, field := range l.Fields {
		if field.Name == name {
			return field, true
		}
	}
	return ZoneField{}, false
}

// ZoneListingsDigest is the fingerprint of everything firewalld printed about
// the zones of one configuration, less what zoneListingNormalisation drops. A
// change to a field the panel does not model - a rich rule, a forward port, a
// protocol - moves it, so a plan made before such a change does not apply
// after it.
func ZoneListingsDigest(listings []ZoneListing) string {
	sum := sha256.New()
	for _, listing := range listings {
		writeLengthPrefixed(sum, "zone", listing.Name, strconv.Itoa(len(listing.Fields)))
		for _, field := range listing.Fields {
			if zoneFieldNormalised(field.Name) {
				continue
			}
			writeLengthPrefixed(sum, field.Name, field.Text())
		}
	}
	return hex.EncodeToString(sum.Sum(nil)[:12])
}

// ZoneFieldDrift compares the fields of the two configurations that the panel
// does not model, so a difference it cannot describe entry by entry is still
// named. Only zones both configurations carry are compared: a zone only one of
// them has is reported whole by ZoneDrift.
func ZoneFieldDrift(runtime, permanent []ZoneListing) []Drift {
	var drift []Drift
	for _, running := range runtime {
		kept, ok := zoneListingNamed(permanent, running.Name)
		if !ok {
			continue
		}
		for _, field := range zoneFieldsToCompare(running, kept) {
			runningValue, inRunning := comparedText(running, field)
			keptValue, inKept := comparedText(kept, field)
			if inRunning == inKept && runningValue == keptValue {
				continue
			}
			drift = append(drift, Drift{Reason: DriftZoneFieldDiffers, Zone: running.Name,
				Rule: field,
				Detail: "the zone " + running.Name + " differs in " + field +
					": it keeps " + printedAs(keptValue, inKept) + " and filters with " +
					printedAs(runningValue, inRunning) + ", so a reload imposes what it keeps"})
		}
	}
	return drift
}

// zoneFieldsToCompare is every field either configuration printed for a zone,
// in the order the running one printed them, less what is normalised away.
func zoneFieldsToCompare(running, kept ZoneListing) []string {
	var fields []string
	seen := make(map[string]bool, len(running.Fields)+len(kept.Fields))
	for _, listing := range []ZoneListing{running, kept} {
		for _, field := range listing.Fields {
			if seen[field.Name] || zoneFieldNormalised(field.Name) {
				continue
			}
			seen[field.Name] = true
			fields = append(fields, field.Name)
		}
	}
	return fields
}

// comparedText is what the comparison compares for one field. For a field
// ZoneDrift already names entry by entry it is only the lines below it, which
// no modelled list carries: that way one difference is not reported twice, and
// nothing the digest covers is left without a name.
func comparedText(listing ZoneListing, name string) (string, bool) {
	field, printed := listing.field(name)
	if !printed {
		return "", false
	}
	if slices.Contains(zoneFieldsTyped, name) {
		return strings.Join(field.Lines, "\n"), true
	}
	return field.Text(), true
}

// zoneFieldNormalised says whether a field is dropped before the two
// configurations are compared or digested.
func zoneFieldNormalised(name string) bool {
	return slices.Contains(zoneListingNormalisation, name)
}

// zoneListingNamed finds a zone by name in one configuration's listing.
func zoneListingNamed(listings []ZoneListing, name string) (ZoneListing, bool) {
	for _, listing := range listings {
		if listing.Name == name {
			return listing, true
		}
	}
	return ZoneListing{}, false
}

// maxPrintedValue bounds what a difference quotes of a field: a zone's rich
// rules are a page of text, and the whole of both sides belongs in the panel
// rather than in one sentence.
const maxPrintedValue = 80

// printedAs quotes a field value for a message, or says the field was not
// printed at all - which is not the same as printed empty.
func printedAs(value string, printed bool) string {
	if !printed {
		return "nothing of the kind"
	}
	if value == "" {
		return "nothing"
	}
	// A field's rich rules are printed one per line; a message carries them on
	// one line and only as far as it is a sentence.
	shown := strings.ReplaceAll(value, "\n", "; ")
	if len(shown) > maxPrintedValue {
		shown = shown[:maxPrintedValue] + "..."
	}
	return strconv.Quote(shown)
}

// writeLengthPrefixed writes parts into a digest so that no arrangement of
// names and values can read as another.
func writeLengthPrefixed(sum io.Writer, parts ...string) {
	for _, part := range parts {
		_, _ = io.WriteString(sum, strconv.Itoa(len(part))+":"+part)
	}
}
