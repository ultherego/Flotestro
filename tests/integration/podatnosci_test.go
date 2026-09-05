//go:build integration

package integration

import (
	"net/http"
	"regexp"
	"testing"
	"time"
)

type podatnoscView struct {
	Provider            string   `json:"provider"`
	AdvisoryID          string   `json:"advisory_id"`
	CVEIDs              []string `json:"cve_ids"`
	SourcePackage       string   `json:"source_package"`
	BinaryPackage       string   `json:"binary_package"`
	Architecture        string   `json:"architecture"`
	InstalledVersion    string   `json:"installed_version"`
	ComparisonVersion   string   `json:"comparison_version"`
	ComparisonBasis     string   `json:"comparison_basis"`
	FixedVersion        string   `json:"fixed_version"`
	State               string   `json:"state"`
	ReasonCode          string   `json:"reason_code"`
	VendorFix           string   `json:"vendor_fix"`
	RepositoryCandidate string   `json:"repository_candidate"`
	Transaction         string   `json:"transaction"`
	PackageOrigin       string   `json:"package_origin"`
	VendorSeverity      string   `json:"vendor_severity"`
	SnapshotDigest      string   `json:"snapshot_digest"`
	InventoryDigest     string   `json:"inventory_digest"`
	AdvisoryDigest      string   `json:"advisory_digest"`
	Comparator          string   `json:"comparator_version"`
}

type stanOcenyView struct {
	Distribution          string     `json:"distribution"`
	Release               string     `json:"release"`
	Provider              string     `json:"provider"`
	PackagesTotal         int        `json:"packages_total"`
	PackagesCovered       int        `json:"packages_covered"`
	Affected              int        `json:"affected"`
	AffectedWithVendorFix int        `json:"affected_with_vendor_fix"`
	AffectedNoFix         int        `json:"affected_no_fix"`
	Unknown               int        `json:"unknown"`
	AffectedPackages      int        `json:"affected_packages"`
	UniqueAdvisories      int        `json:"unique_advisories"`
	UniqueCVEs            int        `json:"unique_cves"`
	CoverageReason        string     `json:"coverage_reason"`
	AdvisoriesReason      string     `json:"advisories_reason"`
	EvaluatedAt           *time.Time `json:"evaluated_at"`
}

type raportPodatnosciView struct {
	State        stanOcenyView   `json:"state"`
	Findings     []podatnoscView `json:"findings"`
	PackageState struct {
		Digest       string     `json:"digest"`
		PackageCount int        `json:"package_count"`
		CollectedAt  *time.Time `json:"collected_at"`
		Reason       string     `json:"unavailable_reason"`
	} `json:"package_state"`
	AdvisoryState struct {
		Digest        string     `json:"digest"`
		AdvisoryCount int        `json:"advisory_count"`
		CollectedAt   *time.Time `json:"collected_at"`
		Reason        string     `json:"unavailable_reason"`
	} `json:"advisory_state"`
	Snapshot *struct {
		Provider      string   `json:"provider"`
		Digest        string   `json:"digest"`
		AdvisoryCount int      `json:"advisory_count"`
		Releases      []string `json:"releases"`
	} `json:"snapshot"`
	CoveragePercent float64 `json:"coverage_percent"`
	FullyAssessed   bool    `json:"fully_assessed"`
}

type flotaPodatnosciView struct {
	Affected              int `json:"affected"`
	AffectedWithVendorFix int `json:"affected_with_vendor_fix"`
	AffectedNoFix         int `json:"affected_no_fix"`
	Unknown               int `json:"unknown"`
	UniqueCVEs            int `json:"unique_cves"`
	UniqueAdvisories      int `json:"unique_advisories"`
	PackageInstances      int `json:"affected_package_instances"`
	HostsAffected         int `json:"hosts_affected"`
	HostsTotal            int `json:"hosts_total"`
	HostsAssessed         int `json:"hosts_assessed"`
	Items                 []struct {
		HostID          string  `json:"host_id"`
		CoveragePercent float64 `json:"coverage_percent"`
		FullyAssessed   bool    `json:"fully_assessed"`
		PackagesTotal   int     `json:"packages_total"`
		PackagesCovered int     `json:"packages_covered"`
	} `json:"items"`
}

var wzorzecCVE = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

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
//
// Test nie przepuszcza oceny niepelnej. Flota testowa ma feed Debiana
// i metadane Fedory, wiec ocena musi sie udac; "niepelna, ale z powodem" bylo
// wygodne dla testu i bezuzyteczne jako sprawdzenie.
func TestOcenaPodatnosciOpisujePokrycie(t *testing.T) {
	h := newHarness(t)
	for _, rodzina := range []string{"debian", "rhel"} {
		host := h.hostByFamily(rodzina)
		raport := podatnosciHosta(h, host.ID)
		stan := raport.State

		if stan.CoverageReason != "" {
			t.Fatalf("%s: ocena niepelna (%s) - flota testowa ma czym ocenic",
				rodzina, stan.CoverageReason)
		}
		if stan.EvaluatedAt == nil {
			t.Fatalf("%s: brak znacznika oceny mimo pelnego pokrycia", rodzina)
		}
		if stan.PackagesTotal == 0 {
			t.Fatalf("%s: ocena bez pakietow", rodzina)
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
		// "Wszystko sprawdzone" ma znaczyc wszystko. Host, w ktorym feed nie
		// objal choc jednego pakietu, nie jest w pelni oceniony - nawet gdy
		// nic tej oceny nie zablokowalo.
		pelna := stan.PackagesCovered == stan.PackagesTotal && stan.Unknown == 0
		if raport.FullyAssessed != pelna {
			t.Errorf("%s: pelna ocena = %v przy %d/%d pakietow i %d nieustalonych",
				rodzina, raport.FullyAssessed, stan.PackagesCovered,
				stan.PackagesTotal, stan.Unknown)
		}
		if !pelna && raport.CoveragePercent >= 100 {
			t.Errorf("%s: pokrycie %d/%d pokazane jako %.1f%%", rodzina,
				stan.PackagesCovered, stan.PackagesTotal, raport.CoveragePercent)
		}
	}
}

// TestUstalenieWiazeSieZDanymiIWersjami pilnuje, ze kazde znalezisko da sie
// odtworzyc: mowi, co bylo zainstalowane, co naprawde porownano, co naprawia,
// ktore dane i ktora regula porownania o tym zdecydowaly.
func TestUstalenieWiazeSieZDanymiIWersjami(t *testing.T) {
	h := newHarness(t)
	// Kazda rodzina ma swoja podstawe porownania: Debian prowadzi
	// bezpieczenstwo po pakiecie zrodlowym, Fedora po binarnym.
	podstawy := map[string]string{"debian": "source", "rhel": "binary"}

	for _, rodzina := range []string{"debian", "rhel"} {
		host := h.hostByFamily(rodzina)
		raport := podatnosciHosta(h, host.ID)
		if len(raport.Findings) == 0 {
			t.Fatalf("%s: zaden pakiet nie dal sie ocenic - to nie jest wynik", rodzina)
		}
		podatnych := 0
		for _, ustalenie := range raport.Findings {
			if ustalenie.State == "unknown" && ustalenie.ReasonCode == "" {
				t.Errorf("%s: stan nieustalony bez kodu powodu: %+v", rodzina, ustalenie)
			}
			// Kazde znalezisko mowi, czyj jest pakiet: bez tego pakiet
			// z obcego repozytorium liczylby sie jako objety ustaleniami
			// producenta dystrybucji.
			if ustalenie.PackageOrigin == "" {
				t.Errorf("%s: znalezisko bez pochodzenia pakietu: %+v", rodzina, ustalenie)
			}
			// Trzecia os nalezy do planu pakietowego, a planu nikt tu nie
			// liczyl - panel nie ma prawa obiecywac, ze transakcja przejdzie.
			if ustalenie.Transaction != "unknown" {
				t.Errorf("%s: transakcja = %q bez planu: %+v",
					rodzina, ustalenie.Transaction, ustalenie)
			}
			if ustalenie.State != "affected" {
				continue
			}
			podatnych++
			if ustalenie.InstalledVersion == "" {
				t.Errorf("%s: ustalenie bez wersji zainstalowanej: %+v", rodzina, ustalenie)
			}
			if ustalenie.ComparisonVersion == "" || ustalenie.ComparisonBasis != podstawy[rodzina] {
				t.Errorf("%s: porownano %q na podstawie %q, oczekiwano podstawy %q",
					rodzina, ustalenie.ComparisonVersion, ustalenie.ComparisonBasis,
					podstawy[rodzina])
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
			// niewydana przez producenta, a nie jako czekajaca na plan.
			if ustalenie.FixedVersion == "" && ustalenie.VendorFix != "unavailable" {
				t.Errorf("%s: podatnosc bez poprawki opisana jako %q: %+v",
					rodzina, ustalenie.VendorFix, ustalenie)
			}
			if ustalenie.FixedVersion != "" && ustalenie.VendorFix != "known" {
				t.Errorf("%s: poprawka %q opisana jako %q: %+v", rodzina,
					ustalenie.FixedVersion, ustalenie.VendorFix, ustalenie)
			}
			if podatnych > 200 {
				break
			}
		}
		if podatnych == 0 {
			t.Errorf("%s: ani jedno ustalenie producenta nie dotyczy tego hosta - "+
				"to jest wynik nieprawdopodobny, a nie czysty host", rodzina)
		}
	}
}

// TestDebianOcenaMaKonkretneCVE pilnuje, ze ocena Debiana naprawde niesie
// ustalenia trackera, a nie sama strukture.
//
// Trixie ma otwarte podatnosci bez poprawki w pakietach bazowych - kazdej
// instalacji dotyczy ich kilkanascie. Zero znalezisk znaczyloby, ze feed
// dojechal pusty albo korelacja nie zlapala pakietu zrodlowego.
func TestDebianOcenaMaKonkretneCVE(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	raport := podatnosciHosta(h, host.ID)

	zCVE, bezPoprawki := 0, 0
	pakiety := map[string]bool{}
	for _, ustalenie := range raport.Findings {
		if ustalenie.State != "affected" {
			continue
		}
		pakiety[ustalenie.SourcePackage] = true
		for _, numer := range ustalenie.CVEIDs {
			if wzorzecCVE.MatchString(numer) {
				zCVE++
			}
		}
		if ustalenie.FixedVersion == "" {
			bezPoprawki++
		}
	}
	if zCVE == 0 {
		t.Fatalf("ocena Debiana bez ani jednego numeru CVE (%d znalezisk)",
			len(raport.Findings))
	}
	if bezPoprawki == 0 {
		t.Error("ocena Debiana bez ani jednej podatnosci bez poprawki - " +
			"trixie takich ma, wiec czegos nie widzimy")
	}
	// Ustalenia trackera dotycza pakietow zrodlowych, a jeden zrodlowy daje
	// kilka binarnych: korelacja po samej nazwie binarnej gubilaby wiekszosc.
	if len(pakiety) < 2 {
		t.Errorf("ocena dotyczy %d pakietow zrodlowych", len(pakiety))
	}
	if raport.State.UniqueCVEs == 0 || raport.State.UniqueAdvisories == 0 {
		t.Errorf("liczniki unikatow puste przy %d znaleziskach: %+v",
			raport.State.Affected, raport.State)
	}
	if raport.State.AffectedPackages > raport.State.Affected {
		t.Errorf("instancji pakietow (%d) wiecej niz znalezisk (%d)",
			raport.State.AffectedPackages, raport.State.Affected)
	}
}

// TestFedoraCzytaUstaleniaZMetadanychHosta pilnuje, ze dla rodziny RPM panel
// ma wlasny, osobny cykl odczytu ustalen producenta - i mowi, kiedy je czytal.
func TestFedoraCzytaUstaleniaZMetadanychHosta(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("rhel")
	raport := podatnosciHosta(h, host.ID)

	if raport.AdvisoryState.CollectedAt == nil {
		t.Fatalf("panel nie zapisal, kiedy czytal ustalenia producenta: %+v",
			raport.AdvisoryState)
	}
	if raport.AdvisoryState.Reason != "" {
		t.Fatalf("ustalenia producenta niedostepne: %s", raport.AdvisoryState.Reason)
	}
	if raport.AdvisoryState.AdvisoryCount == 0 || raport.AdvisoryState.Digest == "" {
		t.Errorf("ustalenia hosta bez tresci albo bez odcisku: %+v", raport.AdvisoryState)
	}
	// Ocena musi sie do tego zestawu odwolywac: bez odcisku nie wiadomo,
	// ktore ustalenia ja rozstrzygnely.
	if raport.State.EvaluatedAt != nil && raport.State.Affected > 0 {
		for _, ustalenie := range raport.Findings {
			if ustalenie.State == "affected" && ustalenie.AdvisoryDigest == "" {
				t.Errorf("znalezisko bez wskazania zestawu ustalen: %+v", ustalenie)
				break
			}
		}
	}
}

// TestFlotaLiczyUnikatyOsobno pilnuje, zeby jedna liczba nie udawala
// odpowiedzi na cztery rozne pytania.
func TestFlotaLiczyUnikatyOsobno(t *testing.T) {
	h := newHarness(t)
	var widok flotaPodatnosciView
	h.get("/api/v1/vulnerabilities", &widok)

	if widok.HostsTotal == 0 || len(widok.Items) == 0 {
		t.Fatal("ekran floty bez hostow")
	}
	if widok.Affected == 0 {
		t.Fatal("cala flota bez ani jednej podatnosci - to nie jest wynik")
	}
	// Jedno advisory niesie kilka CVE i dotyka kilku pakietow, wiec te liczby
	// nigdy sie nie zgadzaja - ale zadna nie moze byc pusta ani wieksza od
	// liczby znalezisk.
	for nazwa, liczba := range map[string]int{
		"unikatowych CVE":      widok.UniqueCVEs,
		"ustalen producenta":   widok.UniqueAdvisories,
		"instancji pakietow":   widok.PackageInstances,
		"hostow z podatnoscia": widok.HostsAffected,
	} {
		if liczba == 0 {
			t.Errorf("licznik %s pusty przy %d znaleziskach", nazwa, widok.Affected)
		}
	}
	if widok.HostsAffected > widok.HostsTotal {
		t.Errorf("hostow z podatnoscia %d na %d", widok.HostsAffected, widok.HostsTotal)
	}
	if widok.Affected != widok.AffectedWithVendorFix+widok.AffectedNoFix {
		t.Errorf("%d znalezisk to nie %d z poprawka i %d bez",
			widok.Affected, widok.AffectedWithVendorFix, widok.AffectedNoFix)
	}
	// Pokrycie na ekranie floty musi byc tak samo uczciwe jak na hoscie:
	// niepelne pokrycie nie moze zaokraglic sie do stu procent.
	for _, pozycja := range widok.Items {
		if pozycja.PackagesTotal == 0 {
			continue
		}
		pelna := pozycja.PackagesCovered == pozycja.PackagesTotal
		if pelna != pozycja.FullyAssessed && pozycja.CoveragePercent > 0 {
			t.Errorf("host %s: pelna ocena = %v przy %d/%d pakietow",
				pozycja.HostID[:8], pozycja.FullyAssessed,
				pozycja.PackagesCovered, pozycja.PackagesTotal)
		}
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
