package redhat

import (
	"strings"
	"testing"

	"github.com/ultherego/flotestro/internal/vuln"
)

// przykladVEX ma ksztalt dokumentu produkcyjnego: bazowy RHEL obok strumienia
// rozszerzonego i produktu warstwowego, poprawki w kilku strumieniach jednego
// wydania i podatnosci bez poprawki.
const przykladVEX = `{
  "document": {
    "category": "csaf_vex",
    "title": "zlib: przepelnienie bufora",
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
      "title": "zlib: przepelnienie bufora przy dekompresji",
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

func ustaleniaPrzykladu(t *testing.T) map[string]vuln.Advisory {
	t.Helper()
	ustalenia, err := Ustalenia([]byte(przykladVEX), nil)
	if err != nil {
		t.Fatalf("czytanie dokumentu: %v", err)
	}
	wedlug := map[string]vuln.Advisory{}
	for _, ustalenie := range ustalenia {
		wedlug[ustalenie.Release+"/"+ustalenie.SourcePackage] = ustalenie
	}
	return wedlug
}

func TestPoprawkaMaWersjeZNEVRA(t *testing.T) {
	ustalenie := ustaleniaPrzykladu(t)["9/zlib"]
	if ustalenie.Status != vuln.StatusNaprawione {
		t.Fatalf("status = %q, chcemy %q", ustalenie.Status, vuln.StatusNaprawione)
	}
	// Z dwoch strumieni tego samego wydania zostaje nizsza wersja: od niej
	// pakiet zawiera poprawke.
	if ustalenie.FixedVersion != "1.2.11-40.el9" {
		t.Fatalf("wersja naprawiona = %q", ustalenie.FixedVersion)
	}
	if ustalenie.AdvisoryID != "RHSA-2026:1111" {
		t.Fatalf("ustalenie nazwane %q zamiast errata producenta", ustalenie.AdvisoryID)
	}
	if ustalenie.Distribution != Dystrybucja || ustalenie.Provider != Dostawca {
		t.Fatalf("dystrybucja = %q, dostawca = %q", ustalenie.Distribution, ustalenie.Provider)
	}
	if len(ustalenie.CVEIDs) != 1 || ustalenie.CVEIDs[0] != "CVE-2026-1234" {
		t.Fatalf("numery CVE = %v", ustalenie.CVEIDs)
	}
	if ustalenie.VendorSeverity != "important" {
		t.Fatalf("waga = %q - zapisujemy slownik producenta", ustalenie.VendorSeverity)
	}
	if ustalenie.PublishedAt == nil {
		t.Fatal("ustalenie bez daty publikacji")
	}
}

func TestStanyBezPoprawkiMajaSwojeOdpowiedzi(t *testing.T) {
	wedlug := ustaleniaPrzykladu(t)
	if wedlug["9/curl"].Status != vuln.StatusOtwarte {
		t.Errorf("curl: status = %q", wedlug["9/curl"].Status)
	}
	// "Nie naprawimy" jest rozstrzygnieciem producenta, a nie brakiem
	// odpowiedzi - i host nadal jest podatny.
	if wedlug["9/emacs"].Status != vuln.StatusOdroczone {
		t.Errorf("emacs: status = %q, chcemy %q", wedlug["9/emacs"].Status, vuln.StatusOdroczone)
	}
	if wedlug["9/vim"].Status != vuln.StatusBadane {
		t.Errorf("vim: status = %q, chcemy %q", wedlug["9/vim"].Status, vuln.StatusBadane)
	}
	// Stanu "nie dotyczy" nie zapisujemy: korelator i tak nie robi z niego
	// znaleziska, a Red Hat wymienia w nim tysiace pakietow na CVE.
	if _, jest := wedlug["9/nano"]; jest {
		t.Error("ustalenie 'nie dotyczy' zajmuje miejsce w snapshocie")
	}
}

func TestObceProduktyNieTrafiajaDoOceny(t *testing.T) {
	for klucz, ustalenie := range ustaleniaPrzykladu(t) {
		if ustalenie.Release != "9" {
			t.Errorf("%s: wydanie %q spoza bazowego RHEL-a", klucz, ustalenie.Release)
		}
		if ustalenie.SourcePackage == "podman" {
			t.Error("pakiet produktu warstwowego trafil do oceny bazowego RHEL-a")
		}
		if strings.Contains(ustalenie.SourcePackage, "/") {
			t.Errorf("komponent kontenerowy trafil do oceny: %q", ustalenie.SourcePackage)
		}
		if ustalenie.Architecture != "" {
			t.Errorf("%s: ustalenie na architekture %q - producent buduje poprawke raz",
				klucz, ustalenie.Architecture)
		}
	}
	// Strumien EUS ma wlasne wersje poprawek i przysluguje czesci klientow:
	// host bazowy nie moze byc nimi oceniany.
	if wersja := ustaleniaPrzykladu(t)["9/zlib"].FixedVersion; strings.Contains(wersja, "el9_4") {
		t.Errorf("ocena wziela wersje ze strumienia EUS: %q", wersja)
	}
}

func TestWydanieZCPE(t *testing.T) {
	przypadki := map[string]string{
		"cpe:/o:redhat:enterprise_linux:9":            "9",
		"cpe:/a:redhat:enterprise_linux:9::appstream": "9",
		"cpe:/o:redhat:enterprise_linux:10":           "10",
		"cpe:/o:redhat:rhel_eus:9.4::baseos":          "",
		"cpe:/o:redhat:rhel_aus:8.6::baseos":          "",
		"cpe:/a:redhat:openshift:4.13::el8":           "",
		"cpe:/a:redhat:enterprise_linux:9::crb":       "9",
		"":                                            "",
	}
	for cpe, chcemy := range przypadki {
		if mamy := WydanieZCPE(cpe); mamy != chcemy {
			t.Errorf("%q: wydanie = %q, chcemy %q", cpe, mamy, chcemy)
		}
	}
}

func TestRozbijNEVRA(t *testing.T) {
	przypadki := []struct {
		nevra, nazwa, arch, wersja string
		ok                         bool
	}{
		{"zlib-0:1.2.11-40.el9.x86_64", "zlib", "x86_64", "1.2.11-40.el9", true},
		{"kernel-rt-0:5.14.0-284.el9.x86_64", "kernel-rt", "x86_64", "5.14.0-284.el9", true},
		// Epoka niezerowa nalezy do wersji i musi byc zapisana tak samo jak
		// na hoscie - inaczej porownanie wychodzi odwrotnie.
		{"podman-3:4.4.1-19.el9.aarch64", "podman", "aarch64", "3:4.4.1-19.el9", true},
		{"zlib-0:1.2.11-40.el9.noarch", "zlib", "noarch", "1.2.11-40.el9", true},
		{"zlib", "", "", "", false},
		{"zlib-1.2.11-40.el9.x86_64", "", "", "", false},
	}
	for _, przypadek := range przypadki {
		nazwa, arch, wersja, ok := RozbijNEVRA(przypadek.nevra)
		if ok != przypadek.ok || nazwa != przypadek.nazwa || arch != przypadek.arch ||
			wersja != przypadek.wersja {
			t.Errorf("%q -> (%q, %q, %q, %v)", przypadek.nevra, nazwa, arch, wersja, ok)
		}
	}
}
