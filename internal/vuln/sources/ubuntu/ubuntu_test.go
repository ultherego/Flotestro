package ubuntu

import (
	"strings"
	"testing"

	"github.com/ultherego/flotestro/internal/vuln"
)

// ovalSample is a slice of the Canonical data with the same shape as a
// production dump: definitions before tests, tests before states.
const ovalSample = `<?xml version="1.0" encoding="utf-8"?>
<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5"
  xmlns:ind-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent"
  xmlns:unix-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#unix"
  xmlns:linux-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
  <definitions>
    <definition id="oval:com.ubuntu.noble:def:100" class="inventory" version="1">
      <metadata><title>Check that Ubuntu 24.04 LTS (noble) is installed.</title></metadata>
      <criteria><criterion test_ref="oval:com.ubuntu.noble:tst:100" comment="unix" /></criteria>
    </definition>
    <definition id="oval:com.ubuntu.noble:def:1" class="vulnerability" version="1">
      <metadata>
        <title>CVE-2026-1111 on Ubuntu 24.04 LTS (noble) - high</title>
        <reference source="CVE" ref_id="CVE-2026-1111" ref_url="https://www.cve.org/CVERecord?id=CVE-2026-1111" />
        <reference source="USN" ref_id="USN-1000-1" ref_url="https://ubuntu.com/security/notices/USN-1000-1" />
        <description>A hole in accountsservice.  Update Instructions:  Run ` + "`sudo pro fix`" + ` accountsservice - 23.13.9-2ubuntu6.1</description>
        <advisory from="security@ubuntu.com">
          <severity>High</severity>
          <public_date>2026-07-21T16:00:00Z</public_date>
          <cve href="https://ubuntu.com/security/CVE-2026-1111" priority="high">CVE-2026-1111</cve>
        </advisory>
      </metadata>
      <criteria>
        <extend_definition applicability_check="true" definition_ref="oval:com.ubuntu.noble:def:100" comment="noble" />
        <criterion test_ref="oval:com.ubuntu.noble:tst:1" comment="accountsservice source package in noble, is affected and has been fixed (note: '23.13.9-2ubuntu6.1')." />
        <criterion test_ref="oval:com.ubuntu.noble:tst:2" comment="accountsservice source package in esm-apps/noble, is affected and has been fixed (note: '23.13.9-2ubuntu6.1~esm1')." />
      </criteria>
    </definition>
    <definition id="oval:com.ubuntu.noble:def:2" class="vulnerability" version="1">
      <metadata>
        <title>CVE-2026-2222 on Ubuntu 24.04 LTS (noble) - medium</title>
        <reference source="CVE" ref_id="CVE-2026-2222" ref_url="https://www.cve.org/CVERecord?id=CVE-2026-2222" />
        <description>A hole in curl without a fix.</description>
        <advisory from="security@ubuntu.com">
          <severity>Medium</severity>
          <public_date>2026-08-01T00:00:00Z</public_date>
          <cve href="https://ubuntu.com/security/CVE-2026-2222" priority="untriaged">CVE-2026-2222</cve>
        </advisory>
      </metadata>
      <criteria>
        <criterion test_ref="oval:com.ubuntu.noble:tst:3" comment="curl source package in noble, might be affected and may need fixing." />
      </criteria>
    </definition>
    <definition id="oval:com.ubuntu.noble:def:3" class="vulnerability" version="1">
      <metadata>
        <title>CVE-2026-3333 on Ubuntu 24.04 LTS (noble) - high</title>
        <reference source="CVE" ref_id="CVE-2026-3333" ref_url="https://www.cve.org/CVERecord?id=CVE-2026-3333" />
        <description>A hole in the kernel.</description>
        <advisory from="security@ubuntu.com">
          <severity>High</severity>
          <public_date>2026-08-02T00:00:00Z</public_date>
          <cve href="https://ubuntu.com/security/CVE-2026-3333" priority="high">CVE-2026-3333</cve>
        </advisory>
      </metadata>
      <criteria>
        <criteria operator="AND">
          <criterion test_ref="oval:com.ubuntu.noble:tst:10" comment="Is kernel 'linux' running?" />
          <criterion test_ref="oval:com.ubuntu.noble:tst:11" comment="'linux' kernel in noble was vulnerable but has been fixed (note: '6.8.0-35.35')." />
        </criteria>
      </criteria>
    </definition>
  </definitions>
  <tests>
    <ind-def:family_test id="oval:com.ubuntu.noble:tst:100" version="1" comment="Is the host part of the unix family?" />
    <linux-def:dpkginfo_test id="oval:com.ubuntu.noble:tst:1" version="1" comment="Does the 'accountsservice' package exist?">
      <linux-def:object object_ref="oval:com.ubuntu.noble:obj:1" />
      <linux-def:state state_ref="oval:com.ubuntu.noble:ste:1" />
    </linux-def:dpkginfo_test>
    <linux-def:dpkginfo_test id="oval:com.ubuntu.noble:tst:2" version="1" comment="Does the 'accountsservice' package exist?">
      <linux-def:object object_ref="oval:com.ubuntu.noble:obj:1" />
      <linux-def:state state_ref="oval:com.ubuntu.noble:ste:2" />
    </linux-def:dpkginfo_test>
    <linux-def:dpkginfo_test id="oval:com.ubuntu.noble:tst:3" version="1" comment="Does the 'curl' package exist?">
      <linux-def:object object_ref="oval:com.ubuntu.noble:obj:3" />
    </linux-def:dpkginfo_test>
    <unix-def:uname_test id="oval:com.ubuntu.noble:tst:10" version="1" comment="Is kernel 'linux' running?">
      <unix-def:object object_ref="oval:com.ubuntu.noble:obj:200" />
    </unix-def:uname_test>
    <ind-def:variable_test id="oval:com.ubuntu.noble:tst:11" version="1" comment="kernel 'linux' version comparison">
      <ind-def:object object_ref="oval:com.ubuntu.noble:obj:210" />
      <ind-def:state state_ref="oval:com.ubuntu.noble:ste:11" />
    </ind-def:variable_test>
  </tests>
  <states>
    <linux-def:dpkginfo_state id="oval:com.ubuntu.noble:ste:1" version="1" comment="less than">
      <linux-def:evr datatype="debian_evr_string" operation="less than">23.13.9-2ubuntu6.1</linux-def:evr>
    </linux-def:dpkginfo_state>
    <linux-def:dpkginfo_state id="oval:com.ubuntu.noble:ste:2" version="1" comment="less than">
      <linux-def:evr datatype="debian_evr_string" operation="less than">23.13.9-2ubuntu6.1~esm1</linux-def:evr>
    </linux-def:dpkginfo_state>
    <ind-def:variable_state id="oval:com.ubuntu.noble:ste:11" version="1" comment="'linux' kernel version">
      <ind-def:value datatype="debian_evr_string" operation="less than">6.8.0-35.35</ind-def:value>
    </ind-def:variable_state>
  </states>
</oval_definitions>
`

func testAdvisories(t *testing.T) map[string]vuln.Advisory {
	t.Helper()
	advisories, err := Parse(strings.NewReader(ovalSample), "noble")
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	byKey := map[string]vuln.Advisory{}
	for _, advisory := range advisories {
		byKey[advisory.AdvisoryID+"/"+advisory.SourcePackage] = advisory
	}
	return byKey
}

func TestAFixCarriesTheSourceVersionAndTheRelease(t *testing.T) {
	advisory := testAdvisories(t)["CVE-2026-1111/accountsservice"]
	if advisory.Status != vuln.StatusFixed {
		t.Fatalf("status = %q, we want %q", advisory.Status, vuln.StatusFixed)
	}
	// Of two pockets the lower version wins: it is from that one that the
	// package carries the fix, so a host with the main version must not come
	// out as vulnerable.
	if advisory.FixedVersion != "23.13.9-2ubuntu6.1~esm1" {
		t.Fatalf("fixed version = %q", advisory.FixedVersion)
	}
	if advisory.Release != "noble" || advisory.Distribution != "ubuntu" {
		t.Fatalf("release = %q, distribution = %q", advisory.Release, advisory.Distribution)
	}
	if advisory.VendorSeverity != "high" {
		t.Fatalf("severity = %q", advisory.VendorSeverity)
	}
	if strings.Contains(advisory.Title, "Update Instructions") {
		t.Fatalf("the title carries update instructions: %q", advisory.Title)
	}
	if advisory.PublishedAt == nil {
		t.Fatal("a finding without a publication date")
	}
}

func TestAPackageWithoutAFixIsOpen(t *testing.T) {
	advisory := testAdvisories(t)["CVE-2026-2222/curl"]
	if advisory.Status != vuln.StatusOpen {
		t.Fatalf("status = %q, we want %q", advisory.Status, vuln.StatusOpen)
	}
	if advisory.FixedVersion != "" {
		t.Fatalf("a finding without a fix carries the version %q", advisory.FixedVersion)
	}
	// "untriaged" is not a severity: the vendor has not scored it yet.
	if advisory.VendorSeverity != "medium" {
		t.Fatalf("severity = %q", advisory.VendorSeverity)
	}
}

func TestTheKernelHasAFindingWithTheVersionOfTheVariant(t *testing.T) {
	byKey := testAdvisories(t)
	advisory, ok := byKey["CVE-2026-3333/linux"]
	if !ok {
		t.Fatal("no finding for the kernel - kernel CVEs disappear from the assessment")
	}
	if advisory.Status != vuln.StatusFixed || advisory.FixedVersion != "6.8.0-35.35" {
		t.Fatalf("kernel: status = %q, version = %q", advisory.Status, advisory.FixedVersion)
	}
	// The "is it running" criterion is not a finding of its own: it carries no
	// version, so there is nothing to speak about.
	if len(byKey) != 3 {
		t.Fatalf("findings = %d, we want 3: %v", len(byKey), byKey)
	}
}

func TestACutDocumentIsNotTheFullThing(t *testing.T) {
	cut := ovalSample[:len(ovalSample)/2]
	if _, err := Parse(strings.NewReader(cut), "noble"); err == nil {
		t.Fatal("a cut document went through as the whole thing")
	}
}

func TestDefinitionsWithoutFindingsAreAnError(t *testing.T) {
	// A syntactically correct document in which the definition points at no
	// test the panel understands. Silence is the worst answer here.
	foreign := `<oval_definitions><definitions>
      <definition id="oval:com.ubuntu.noble:def:1" class="vulnerability" version="1">
        <metadata>
          <reference source="CVE" ref_id="CVE-2026-9999" />
          <description>a new shape of the document</description>
        </metadata>
        <criteria><criterion test_ref="oval:com.ubuntu.noble:tst:999" comment="something new" /></criteria>
      </definition>
    </definitions></oval_definitions>`
	if _, err := Parse(strings.NewReader(foreign), "noble"); err == nil {
		t.Fatal("a document without findings went through as an empty feed")
	}
}

func TestTheETagsOfReleasesAreSeparate(t *testing.T) {
	etags := map[string]string{"noble": `"aaa"`, "jammy": `"bbb"`, "focal": "with a space"}
	joined := JoinETags(etags)
	read := ParseETags(joined)
	if read["noble"] != `"aaa"` || read["jammy"] != `"bbb"` {
		t.Fatalf("etags after reading: %v", read)
	}
	// An etag with a space would fall apart into two entries - better to fetch
	// unconditionally than to fetch conditionally with a wrong value.
	if _, ok := read["focal"]; ok {
		t.Fatalf("an etag with a space went through: %v", read)
	}
}

func TestTheDigestDoesNotDependOnTheOrder(t *testing.T) {
	advisories, err := Parse(strings.NewReader(ovalSample), "noble")
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	reversed := make([]vuln.Advisory, 0, len(advisories))
	for i := len(advisories) - 1; i >= 0; i-- {
		reversed = append(reversed, advisories[i])
	}
	SortAdvisories(reversed)
	if Digest(advisories) != Digest(reversed) {
		t.Fatal("the digest depends on the order - every fetch would start a new snapshot")
	}
}
