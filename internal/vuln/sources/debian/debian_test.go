package debian

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/ultherego/flotestro/internal/vuln"
)

// testDump mirrors the shape of a real tracker dump, together with the traps
// that are in it.
const testDump = `{
  "openssl": {
    "CVE-2026-1000": {
      "description": "A flaw in the handling of certificates",
      "scope": "remote",
      "releases": {
        "trixie": {"status": "resolved", "urgency": "high", "fixed_version": "3.5.6-1~deb13u2"},
        "bookworm": {"status": "open", "urgency": "medium", "fixed_version": ""}
      }
    },
    "CVE-2026-1001": {
      "description": "The release was never vulnerable",
      "releases": {
        "trixie": {"status": "resolved", "urgency": "not yet assigned", "fixed_version": "0"}
      }
    }
  },
  "bash": {
    "CVE-2026-2000": {
      "description": "The vendor will not release a fix in this release",
      "releases": {
        "trixie": {"status": "open", "urgency": "unimportant", "fixed_version": "",
                   "nodsa": "Minor issue", "nodsa_reason": "postponed"}
      }
    },
    "CVE-2026-2001": {
      "description": "Not settled yet",
      "releases": {
        "trixie": {"status": "undetermined", "urgency": "not yet assigned"}
      }
    }
  }
}`

func TestParseReadsTheFindingsOfTheChosenRelease(t *testing.T) {
	advisories, err := Parse(strings.NewReader(testDump), []string{"trixie"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(advisories) != 4 {
		t.Fatalf("read %d findings: %+v", len(advisories), advisories)
	}
	for _, advisory := range advisories {
		if advisory.Release != "trixie" {
			t.Errorf("a finding from outside the chosen release: %+v", advisory)
		}
		if advisory.Distribution != "debian" || advisory.Provider != Provider {
			t.Errorf("a finding without a source: %+v", advisory)
		}
	}

	byName := map[string]vuln.Advisory{}
	for _, advisory := range advisories {
		byName[advisory.AdvisoryID] = advisory
	}

	// The fixed version is a version from the numbering of Debian rather than
	// of upstream.
	fixed := byName["CVE-2026-1000"]
	if fixed.Status != vuln.StatusFixed || fixed.FixedVersion != "3.5.6-1~deb13u2" {
		t.Errorf("a fixed finding: %+v", fixed)
	}
	if fixed.VendorSeverity != "high" {
		t.Errorf("severity = %q", fixed.VendorSeverity)
	}

	// The trap of the tracker: "resolved" with the version "0" means "this
	// release was never vulnerable" rather than "fixed in version zero".
	notAffected := byName["CVE-2026-1001"]
	if notAffected.Status != vuln.StatusNotAffected || notAffected.FixedVersion != "" {
		t.Errorf("a 'not affected' finding: %+v", notAffected)
	}

	// nodsa marks a decision of the vendor rather than a missing answer.
	deferred := byName["CVE-2026-2000"]
	if deferred.Status != vuln.StatusDeferred {
		t.Errorf("a deferred finding: %+v", deferred)
	}

	investigated := byName["CVE-2026-2001"]
	if investigated.Status != vuln.StatusUnderInvestigation {
		t.Errorf("a finding under investigation: %+v", investigated)
	}
	// "not yet assigned" is not a severity: it is a missing severity and is to
	// stay one.
	if investigated.VendorSeverity != "" {
		t.Errorf("an unassigned severity was turned into %q", investigated.VendorSeverity)
	}
}

func TestParseSkipsReleasesOutsideTheRange(t *testing.T) {
	advisories, err := Parse(strings.NewReader(testDump), []string{"bookworm"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(advisories) != 1 || advisories[0].Release != "bookworm" {
		t.Fatalf("read %+v", advisories)
	}
	// A host whose release is not in the feed must not get somebody else's
	// findings.
	empty, err := Parse(strings.NewReader(testDump), []string{"buster"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("a release outside the dump returned %d findings", len(empty))
	}
}

func TestTheDigestDependsOnTheContent(t *testing.T) {
	first, _ := Parse(strings.NewReader(testDump), []string{"trixie"})
	second, _ := Parse(strings.NewReader(testDump), []string{"trixie"})
	if Digest(first) != Digest(second) {
		t.Fatal("the same data gave different digests")
	}
	// A change of the fixed version has to change the digest: otherwise the
	// panel would not recompute the fleet after a fix was published.
	changed := append([]vuln.Advisory{}, first...)
	changed[0].FixedVersion += "u3"
	if Digest(changed) == Digest(first) {
		t.Fatal("a change of the fixed version did not change the digest")
	}
}

func TestWeTrimTheDescriptionByCharactersNotBytes(t *testing.T) {
	// Cutting by bytes splits a multi-byte character in half and leaves a
	// sequence that cannot be written to the database - and then the whole
	// import is lost.
	long := strings.Repeat("ą", 400)
	result := shortened(long)
	if !utf8.ValidString(result) {
		t.Fatal("the trimmed description is not valid UTF-8")
	}
	if len([]rune(result)) != 300 {
		t.Fatalf("the trimmed description has %d characters", len([]rune(result)))
	}
	// A byte outside the encoding disappears instead of toppling the import.
	if !utf8.ValidString(shortened("a description with a \xe2\x80 cut character")) {
		t.Fatal("the cut character stayed in the description")
	}
}

// TestACutDumpIsNotTheFullThing guards the property without which half a dump
// would look like the whole feed.
//
// A stream cut in half ends with no further key - the loop then exits
// silently and the panel treats the missing findings as non-existent. A
// finding that is not there means "the package is not vulnerable", so such an
// import turns a network failure into a false "the host is clean".
func TestACutDumpIsNotTheFullThing(t *testing.T) {
	cases := map[string]string{
		"cut in the middle of an entry": `{"openssl": {"CVE-2026-1": {"releases": {"trixie": {"stat`,
		"without the closing": `{"openssl": {"CVE-2026-1": {"releases": ` +
			`{"trixie": {"status": "open"}}}}`,
		"data after the closing": `{"openssl": {}} {"second": {}}`,
		"not an object":          `["openssl"]`,
	}
	for name, content := range cases {
		if _, err := Parse(strings.NewReader(content), []string{"trixie"}); err == nil {
			t.Errorf("%s: the parser accepted an incomplete dump", name)
		}
	}

	// A complete dump goes through - otherwise the check would be useless.
	full := `{"openssl": {"CVE-2026-1": {"releases": {"trixie": ` +
		`{"status": "resolved", "fixed_version": "3.0.12-1"}}}}}`
	advisories, err := Parse(strings.NewReader(full), []string{"trixie"})
	if err != nil {
		t.Fatalf("a complete dump was rejected: %v", err)
	}
	if len(advisories) != 1 || advisories[0].FixedVersion != "3.0.12-1" {
		t.Fatalf("findings = %+v", advisories)
	}
}
