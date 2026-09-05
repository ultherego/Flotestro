//go:build integration

package integration

import (
	"net/http"
	"testing"
	"time"
)

type podatnoscView struct {
	Provider         string   `json:"provider"`
	AdvisoryID       string   `json:"advisory_id"`
	CVEIDs           []string `json:"cve_ids"`
	SourcePackage    string   `json:"source_package"`
	BinaryPackage    string   `json:"binary_package"`
	Architecture     string   `json:"architecture"`
	InstalledVersion string   `json:"installed_version"`
	FixedVersion     string   `json:"fixed_version"`
	State            string   `json:"state"`
	ReasonCode       string   `json:"reason_code"`
	Remediation      string   `json:"remediation"`
	VendorSeverity   string   `json:"vendor_severity"`
	SnapshotDigest   string   `json:"snapshot_digest"`
	InventoryDigest  string   `json:"inventory_digest"`
	Comparator       string   `json:"comparator_version"`
}

type stanOcenyView struct {
	Distribution    string     `json:"distribution"`
	Release         string     `json:"release"`
	Provider        string     `json:"provider"`
	PackagesTotal   int        `json:"packages_total"`
	PackagesCovered int        `json:"packages_covered"`
	Affected        int        `json:"affected"`
	AffectedFixable int        `json:"affected_fixable"`
	AffectedNoFix   int        `json:"affected_no_fix"`
	Unknown         int        `json:"unknown"`
	CoverageReason  string     `json:"coverage_reason"`
	EvaluatedAt     *time.Time `json:"evaluated_at"`
}

type raportPodatnosciView struct {
	State        stanOcenyView   `json:"state"`
	Findings     []podatnoscView `json:"findings"`
	PackageState struct {
		Digest       string `json:"digest"`
		PackageCount int    `json:"package_count"`
		Reason       string `json:"unavailable_reason"`
	} `json:"package_state"`
	Snapshot *struct {
		Provider      string   `json:"provider"`
		Digest        string   `json:"digest"`
		AdvisoryCount int      `json:"advisory_count"`
		Releases      []string `json:"releases"`
	} `json:"snapshot"`
	CoveragePercent float64 `json:"coverage_percent"`
}

// podatnosciHosta czyta ocene hosta.
func podatnosciHosta(h *harness, hostID string) raportPodatnosciView {
	h.t.Helper()
	var raport raportPodatnosciView
	h.get("/api/v1/hosts/"+hostID+"/vulnerabilities", &raport)
	return raport
}

// TestOcenaPodatnosciOpisujePokrycie pilnuje wlasciwosci, dla ktorej ten modul
// w ogole ma sens: zero znalezisk nie moze znaczyc "host czysty", gdy naprawde
// znaczy "nie bylo czym ocenic".
func TestOcenaPodatnosciOpisujePokrycie(t *testing.T) {
	h := newHarness(t)
	for _, rodzina := range []string{"debian", "rhel"} {
		host := h.hostByFamily(rodzina)
		raport := podatnosciHosta(h, host.ID)
		stan := raport.State

		if stan.CoverageReason != "" {
			// Ocena niepelna musi miec powod - i to jest poprawny wynik,
			// o ile powod jest widoczny.
			t.Logf("%s: ocena niepelna (%s)", rodzina, stan.CoverageReason)
			continue
		}
		if stan.EvaluatedAt == nil {
			t.Errorf("%s: brak znacznika oceny mimo pelnego pokrycia", rodzina)
			continue
		}
		if stan.PackagesTotal == 0 {
			t.Errorf("%s: ocena bez pakietow", rodzina)
			continue
		}
		if raport.PackageState.PackageCount != stan.PackagesTotal {
			t.Errorf("%s: ocena liczy %d pakietow, lista ma %d",
				rodzina, stan.PackagesTotal, raport.PackageState.PackageCount)
		}
		// Ocena musi wskazywac dane, ktore ja rozstrzygnely.
		if raport.Snapshot == nil || raport.Snapshot.Digest == "" {
			t.Errorf("%s: ocena bez wskazania danych zrodlowych", rodzina)
		}
		if raport.CoveragePercent <= 0 {
			t.Errorf("%s: pokrycie = %.1f%%", rodzina, raport.CoveragePercent)
		}
	}
}

// TestUstalenieWiazeSieZDanymiIWersjami pilnuje, ze kazde znalezisko da sie
// odtworzyc: mowi, co bylo zainstalowane, co naprawia, ktore dane i ktora
// regula porownania o tym zdecydowaly.
func TestUstalenieWiazeSieZDanymiIWersjami(t *testing.T) {
	h := newHarness(t)
	znalezione := 0
	for _, rodzina := range []string{"debian", "rhel"} {
		host := h.hostByFamily(rodzina)
		raport := podatnosciHosta(h, host.ID)
		for _, ustalenie := range raport.Findings {
			znalezione++
			if ustalenie.State == "unknown" && ustalenie.ReasonCode == "" {
				t.Errorf("%s: stan nieustalony bez kodu powodu: %+v", rodzina, ustalenie)
			}
			if ustalenie.State == "affected" {
				if ustalenie.InstalledVersion == "" {
					t.Errorf("%s: ustalenie bez wersji zainstalowanej: %+v", rodzina, ustalenie)
				}
				if ustalenie.Comparator == "" {
					t.Errorf("%s: ustalenie bez reguly porownania: %+v", rodzina, ustalenie)
				}
				if ustalenie.SnapshotDigest == "" {
					t.Errorf("%s: ustalenie bez wskazania danych zrodlowych: %+v", rodzina, ustalenie)
				}
				if ustalenie.InventoryDigest == "" {
					t.Errorf("%s: ustalenie bez wskazania listy pakietow: %+v", rodzina, ustalenie)
				}
				// Poprawka bez wersji naprawionej musi byc opisana jako
				// niedostepna, a nie jako czekajaca na plan.
				if ustalenie.FixedVersion == "" && ustalenie.Remediation != "unavailable" {
					t.Errorf("%s: podatnosc bez poprawki opisana jako %q: %+v",
						rodzina, ustalenie.Remediation, ustalenie)
				}
			}
			if znalezione > 200 {
				return
			}
		}
	}
	if znalezione == 0 {
		t.Skip("flota testowa nie ma ustalen do sprawdzenia")
	}
}

// TestOcenaPodatnosciWymagaUprawnienia pilnuje, ze lista podatnosci floty nie
// jest publiczna: to material rozpoznawczy o tej instalacji.
func TestOcenaPodatnosciWymagaUprawnienia(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	operatorToken := h.createPrincipal(uniqueSubject("bez-podatnosci"),
		[]map[string]string{{"role": "approver", "site": host.Site, "environment": host.Environment}})
	bezPrawa := h.withToken(operatorToken)

	bezPrawa.do(http.MethodGet, "/api/v1/vulnerabilities", nil, nil, http.StatusForbidden)
	bezPrawa.do(http.MethodGet, "/api/v1/hosts/"+host.ID+"/vulnerabilities",
		nil, nil, http.StatusForbidden)
}
