package redhat

import (
	"strings"
	"testing"

	"github.com/ultherego/flotestro/internal/vuln"
)

// vexSample has the shape of a production document: the base RHEL next to an
// extended stream and a layered product, fixes in several streams of one
// release and vulnerabilities without a fix.
const vexSample = `{
  "document": {
    "category": "csaf_vex",
    "title": "zlib: a buffer overflow",
    "aggregate_severity": {"text": "Important"},
    "tracking": {"id": "CVE-2026-1234", "initial_release_date": "2026-07-01T10:00:00+00:00"}
  },
  "product_tree": {
    "branches": [
      {
        "category": "vendor",
        "name": "Red Hat",
        "branches": [
          {
            "category": "product_family",
            "name": "Red Hat Enterprise Linux 9",
            "branches": [
              {"category": "product_name", "name": "Red Hat Enterprise Linux 9",
               "product": {"product_id": "red_hat_enterprise_linux_9",
                           "product_identification_helper": {"cpe": "cpe:/o:redhat:enterprise_linux:9"}}},
              {"category": "product_name", "name": "BaseOS 9.6",
               "product": {"product_id": "BaseOS-9.6.0.GA",
                           "product_identification_helper": {"cpe": "cpe:/o:redhat:enterprise_linux:9::baseos"}}},
              {"category": "product_name", "name": "AppStream 9.6",
               "product": {"product_id": "AppStream-9.6.0.GA",
                           "product_identification_helper": {"cpe": "cpe:/a:redhat:enterprise_linux:9::appstream"}}},
              {"category": "product_name", "name": "BaseOS 9.4 EUS",
               "product": {"product_id": "BaseOS-9.4.0.Z.EUS",
                           "product_identification_helper": {"cpe": "cpe:/o:redhat:rhel_eus:9.4::baseos"}}}
            ]
          },
          {
            "category": "product_family",
            "name": "OpenShift",
            "branches": [
              {"category": "product_name", "name": "OpenShift 4.13",
               "product": {"product_id": "8Base-RHOSE-4.13",
                           "product_identification_helper": {"cpe": "cpe:/a:redhat:openshift:4.13::el8"}}}
            ]
          }
        ]
      }
    ],
    "relationships": [
      {"category": "default_component_of",
       "full_product_name": {"product_id": "BaseOS-9.6.0.GA:zlib-0:1.2.11-40.el9.x86_64"},
       "product_reference": "zlib-0:1.2.11-40.el9.x86_64",
       "relates_to_product_reference": "BaseOS-9.6.0.GA"},
      {"category": "default_component_of",
       "full_product_name": {"product_id": "AppStream-9.6.0.GA:zlib-0:1.2.11-41.el9.x86_64"},
       "product_reference": "zlib-0:1.2.11-41.el9.x86_64",
       "relates_to_product_reference": "AppStream-9.6.0.GA"},
      {"category": "default_component_of",
       "full_product_name": {"product_id": "BaseOS-9.4.0.Z.EUS:zlib-0:1.2.11-30.el9_4.x86_64"},
       "product_reference": "zlib-0:1.2.11-30.el9_4.x86_64",
       "relates_to_product_reference": "BaseOS-9.4.0.Z.EUS"},
      {"category": "default_component_of",
       "full_product_name": {"product_id": "BaseOS-9.6.0.GA:zlib-0:1.2.11-40.el9.src"},
       "product_reference": "zlib-0:1.2.11-40.el9.src",
       "relates_to_product_reference": "BaseOS-9.6.0.GA"},
      {"category": "default_component_of",
       "full_product_name": {"product_id": "8Base-RHOSE-4.13:podman-3:4.4.1-19.el8.x86_64"},
       "product_reference": "podman-3:4.4.1-19.el8.x86_64",
       "relates_to_product_reference": "8Base-RHOSE-4.13"}
    ]
  },
  "vulnerabilities": [
    {
      "cve": "CVE-2026-1234",
      "title": "zlib: a buffer overflow during decompression",
      "release_date": "2026-07-01T10:00:00+00:00",
      "product_status": {
        "fixed": [
          "BaseOS-9.6.0.GA:zlib-0:1.2.11-40.el9.x86_64",
          "AppStream-9.6.0.GA:zlib-0:1.2.11-41.el9.x86_64",
          "BaseOS-9.4.0.Z.EUS:zlib-0:1.2.11-30.el9_4.x86_64",
          "BaseOS-9.6.0.GA:zlib-0:1.2.11-40.el9.src",
          "8Base-RHOSE-4.13:podman-3:4.4.1-19.el8.x86_64"
        ],
        "known_affected": [
          "red_hat_enterprise_linux_9:curl",
          "red_hat_enterprise_linux_9:emacs",
          "confidential_compute:openshift-sandboxed/osc-operator"
        ],
        "known_not_affected": ["red_hat_enterprise_linux_9:nano"],
        "under_investigation": ["red_hat_enterprise_linux_9:vim"]
      },
      "remediations": [
        {"category": "vendor_fix",
         "product_ids": ["BaseOS-9.6.0.GA:zlib-0:1.2.11-40.el9.x86_64"],
         "url": "https://access.redhat.com/errata/RHSA-2026:1111"},
        {"category": "no_fix_planned",
         "product_ids": ["red_hat_enterprise_linux_9:emacs"],
         "url": "https://access.redhat.com/security/cve/CVE-2026-1234"}
      ]
    }
  ]
}`

func sampleAdvisories(t *testing.T) map[string]vuln.Advisory {
	t.Helper()
	advisories, err := Advisories([]byte(vexSample), nil)
	if err != nil {
		t.Fatalf("reading the document: %v", err)
	}
	byKey := map[string]vuln.Advisory{}
	for _, advisory := range advisories {
		byKey[advisory.Release+"/"+advisory.SourcePackage] = advisory
	}
	return byKey
}

func TestAFixCarriesTheVersionFromTheNEVRA(t *testing.T) {
	advisory := sampleAdvisories(t)["9/zlib"]
	if advisory.Status != vuln.StatusFixed {
		t.Fatalf("status = %q, we want %q", advisory.Status, vuln.StatusFixed)
	}
	// Of two streams of the same release the lower version stays: it is from
	// that one that the package carries the fix.
	if advisory.FixedVersion != "1.2.11-40.el9" {
		t.Fatalf("fixed version = %q", advisory.FixedVersion)
	}
	if advisory.AdvisoryID != "RHSA-2026:1111" {
		t.Fatalf("the finding is named %q instead of the erratum of the vendor", advisory.AdvisoryID)
	}
	if advisory.Distribution != Distribution || advisory.Provider != Provider {
		t.Fatalf("distribution = %q, provider = %q", advisory.Distribution, advisory.Provider)
	}
	if len(advisory.CVEIDs) != 1 || advisory.CVEIDs[0] != "CVE-2026-1234" {
		t.Fatalf("CVE numbers = %v", advisory.CVEIDs)
	}
	if advisory.VendorSeverity != "important" {
		t.Fatalf("severity = %q - we record the vocabulary of the vendor", advisory.VendorSeverity)
	}
	if advisory.PublishedAt == nil {
		t.Fatal("a finding without a publication date")
	}
}

func TestTheStatesWithoutAFixHaveAnswersOfTheirOwn(t *testing.T) {
	byKey := sampleAdvisories(t)
	if byKey["9/curl"].Status != vuln.StatusOpen {
		t.Errorf("curl: status = %q", byKey["9/curl"].Status)
	}
	// "We will not fix it" is a verdict of the vendor rather than a missing
	// answer - and the host is still vulnerable.
	if byKey["9/emacs"].Status != vuln.StatusDeferred {
		t.Errorf("emacs: status = %q, we want %q", byKey["9/emacs"].Status, vuln.StatusDeferred)
	}
	if byKey["9/vim"].Status != vuln.StatusUnderInvestigation {
		t.Errorf("vim: status = %q, we want %q", byKey["9/vim"].Status, vuln.StatusUnderInvestigation)
	}
	// The "not affected" state is not written down: the correlator makes no
	// finding out of it anyway, and Red Hat lists thousands of packages per
	// CVE in it.
	if _, ok := byKey["9/nano"]; ok {
		t.Error("a 'not affected' finding takes space in the snapshot")
	}
}

func TestForeignProductsDoNotReachTheAssessment(t *testing.T) {
	for key, advisory := range sampleAdvisories(t) {
		if advisory.Release != "9" {
			t.Errorf("%s: the release %q from outside the base RHEL", key, advisory.Release)
		}
		if advisory.SourcePackage == "podman" {
			t.Error("a package of a layered product reached the assessment of the base RHEL")
		}
		if strings.Contains(advisory.SourcePackage, "/") {
			t.Errorf("a container component reached the assessment: %q", advisory.SourcePackage)
		}
		if advisory.Architecture != "" {
			t.Errorf("%s: a finding per architecture %q - the vendor builds the fix once",
				key, advisory.Architecture)
		}
	}
	// The EUS stream has fixes of its own and is available to some customers:
	// a base host must not be assessed with them.
	if version := sampleAdvisories(t)["9/zlib"].FixedVersion; strings.Contains(version, "el9_4") {
		t.Errorf("the assessment took a version from the EUS stream: %q", version)
	}
}

func TestReleaseFromCPE(t *testing.T) {
	cases := map[string]string{
		"cpe:/o:redhat:enterprise_linux:9":            "9",
		"cpe:/a:redhat:enterprise_linux:9::appstream": "9",
		"cpe:/o:redhat:enterprise_linux:10":           "10",
		"cpe:/o:redhat:rhel_eus:9.4::baseos":          "",
		"cpe:/o:redhat:rhel_aus:8.6::baseos":          "",
		"cpe:/a:redhat:openshift:4.13::el8":           "",
		"cpe:/a:redhat:enterprise_linux:9::crb":       "9",
		"":                                            "",
	}
	for cpe, want := range cases {
		if got := ReleaseFromCPE(cpe); got != want {
			t.Errorf("%q: release = %q, want %q", cpe, got, want)
		}
	}
}

func TestSplitNEVRA(t *testing.T) {
	cases := []struct {
		nevra, name, arch, version string
		ok                         bool
	}{
		{"zlib-0:1.2.11-40.el9.x86_64", "zlib", "x86_64", "1.2.11-40.el9", true},
		{"kernel-rt-0:5.14.0-284.el9.x86_64", "kernel-rt", "x86_64", "5.14.0-284.el9", true},
		// A non-zero epoch belongs to the version and has to be written down
		// the way the host writes it - otherwise the comparison comes out the
		// other way round.
		{"podman-3:4.4.1-19.el9.aarch64", "podman", "aarch64", "3:4.4.1-19.el9", true},
		{"zlib-0:1.2.11-40.el9.noarch", "zlib", "noarch", "1.2.11-40.el9", true},
		{"zlib", "", "", "", false},
		{"zlib-1.2.11-40.el9.x86_64", "", "", "", false},
	}
	for _, c := range cases {
		name, arch, version, ok := SplitNEVRA(c.nevra)
		if ok != c.ok || name != c.name || arch != c.arch || version != c.version {
			t.Errorf("%q -> (%q, %q, %q, %v)", c.nevra, name, arch, version, ok)
		}
	}
}
