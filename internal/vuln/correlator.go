package vuln

import (
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/packages"
	"github.com/ultherego/flotestro/internal/vuln/version"
)

// WersjaKomparatora opisuje regule porownania wersji uzyta przy ocenie.
//
// Zapisujemy ja przy kazdym ustaleniu, bo zmiana reguly zmienia odpowiedz:
// bez tego nie da sie powiedziec, czy stare ustalenie liczono tak samo.
const WersjaKomparatora = "deb/dpkg-1,rpm/rpmvercmp-1"

// Wejscie jest wszystkim, z czego liczy sie ocena jednego hosta.
type Wejscie struct {
	HostID   string
	Hostname string
	// Distribution i Release opisuja host tak, jak nazywa go jego producent:
	// "debian"/"trixie", "fedora"/"42". Feed mowi tym samym jezykiem.
	Distribution string
	Release      string
	Packages     []packages.InstalledPackage
	// InventoryDigest wiaze ocene z konkretnym obrazem listy pakietow,
	// a AdvisoryDigest - z konkretnym zestawem ustalen producenta.
	InventoryDigest string
	AdvisoryDigest  string
	// AdvisoriesReason mowi, dlaczego nie ma ustalen producenta albo dlaczego
	// sa stare. Dotyczy dystrybucji, dla ktorych rozstrzygaja metadane
	// repozytoriow samego hosta.
	AdvisoriesReason string
	// ListaNieaktualna oznacza, ze host zglasza inny odcisk listy niz ten,
	// ktory panel ma u siebie.
	ListaNieaktualna bool
	// BrakListy oznacza hosta, ktorego listy panel jeszcze nie pobral.
	BrakListy bool
}

// Ocena jest wynikiem korelacji dla jednego hosta.
type Ocena struct {
	Findings []Assessment
	Stan     StanHosta
}

// Ocen koreluje pakiety hosta z ustaleniami producenta dystrybucji.
//
// Reguly sa trzy i wszystkie sluza jednemu: panel nie moze powiedziec
// "bezpieczny", gdy naprawde znaczy "nie wiem".
//
// Po pierwsze, brak danych nie jest brakiem podatnosci - host bez feedu,
// z feedem nieswiezym albo z wydaniem spoza feedu dostaje stan nieustalony
// z kodem powodu, a nie zero znalezisk.
//
// Po drugie, rozstrzyga producent: jego "not affected" jest odpowiedzia, jego
// "under investigation" jest brakiem odpowiedzi, a wersja naprawiona jest
// wersja z jego numeracji, nie z upstreamu.
//
// Po trzecie, ocena mowi tylko o tym, czy pakiet jest podatny. Czy poprawke da
// sie teraz zainstalowac, rozstrzyga plan pakietowy hosta - nie advisory.
func Ocen(wejscie Wejscie, snapshot Snapshot, ustalenia map[string][]Advisory,
	maksymalnyWiekFeedu time.Duration, teraz time.Time) Ocena {
	stan := StanHosta{
		HostID: wejscie.HostID, Hostname: wejscie.Hostname,
		Distribution: wejscie.Distribution, Release: wejscie.Release,
		Provider: snapshot.Provider, SnapshotDigest: snapshot.Digest,
		InventoryDigest:  wejscie.InventoryDigest,
		AdvisoryDigest:   wejscie.AdvisoryDigest,
		AdvisoriesReason: wejscie.AdvisoriesReason,
		PackagesTotal:    len(wejscie.Packages),
		EvaluatedAt:      &teraz,
	}

	// Kolejnosc powodow ma znaczenie: mowimy o najpowazniejszej przeszkodzie,
	// a nie o pierwszej napotkanej.
	switch {
	case wejscie.BrakListy:
		stan.CoverageReason = RodzajBrakListy
		return Ocena{Stan: stan}
	case wejscie.AdvisoriesReason != "" && wejscie.AdvisoriesReason != RodzajUstaleniaNieswieze:
		// Host, ktorego metadanych repozytoriow panel nie odczytal, nie jest
		// hostem bez ustalen producenta: jest hostem, o ktorym nikt nie
		// sprawdzil, czy jakies ma.
		stan.CoverageReason = wejscie.AdvisoriesReason
		return Ocena{Stan: stan}
	case snapshot.Digest == "":
		stan.CoverageReason = RodzajBrakFeedu
		return Ocena{Stan: stan}
	case !ObejmujeWydanie(snapshot, wejscie.Release):
		stan.CoverageReason = RodzajWydanieNieobslugiwane
		return Ocena{Stan: stan}
	}
	if snapshot.Nieswiezy(maksymalnyWiekFeedu, teraz) {
		// Nieswiezy feed nie zatrzymuje oceny: dane sprzed doby sa lepsze niz
		// ich brak. Ale operator ma wiedziec, ze patrzy na wczorajszy obraz.
		stan.CoverageReason = RodzajFeedNieswiezy
	}
	if wejscie.ListaNieaktualna && stan.CoverageReason == "" {
		stan.CoverageReason = RodzajListaNieaktualna
	}
	if wejscie.AdvisoriesReason != "" && stan.CoverageReason == "" {
		stan.CoverageReason = wejscie.AdvisoriesReason
	}

	var wynik []Assessment
	for _, pakiet := range wejscie.Packages {
		if powod := PowodPominiecia(pakiet, wejscie.Distribution); powod != "" {
			// Pakiet spoza dystrybucji: przebudowany lokalnie albo z obcego
			// repozytorium. Producent o nim nic nie mowi i nie ma prawa
			// mowic - to jest stan nieustalony, a nie pakiet bezpieczny.
			wynik = append(wynik, ustalenieNieznane(wejscie, snapshot, pakiet, powod, teraz))
			continue
		}
		stan.PackagesCovered++

		for _, ustalenie := range ustalenia[KluczKorelacji(pakiet, wejscie.Distribution)] {
			if ustalenie.BinaryPackage != "" && ustalenie.BinaryPackage != pakiet.Name {
				continue
			}
			// Poprawka dla innej architektury nie naprawia tego pakietu:
			// producent wydaje je osobno i osobno je numeruje.
			if ustalenie.Architecture != "" && pakiet.Architecture != "" &&
				ustalenie.Architecture != pakiet.Architecture {
				continue
			}
			ocena := ocenPakiet(wejscie, snapshot, pakiet, ustalenie, teraz)
			if ocena.State == StateNotAffected {
				// Ustalen "nie dotyczy" nie zapisujemy: byloby ich miliony,
				// a niosa tyle samo, co ich brak przy pelnym pokryciu.
				continue
			}
			wynik = append(wynik, ocena)
		}
	}

	// Liczniki unikatow: jedno advisory niesie kilka CVE i kilka pakietow,
	// wiec "1354 znalezisk" nie mowi, ile to naprawde roznych spraw.
	pakiety := map[string]bool{}
	sprawy := map[string]bool{}
	cve := map[string]bool{}
	for _, ustalenie := range wynik {
		switch ustalenie.State {
		case StateAffected:
			stan.Affected++
			pakiety[ustalenie.BinaryPackage+"\x1f"+ustalenie.Architecture+"\x1f"+
				ustalenie.InstalledVersion] = true
			if ustalenie.AdvisoryID != "" {
				sprawy[ustalenie.AdvisoryID] = true
			}
			for _, numer := range ustalenie.CVEIDs {
				cve[numer] = true
			}
			// Podatnosc z poprawka jest do zainstalowania dzis; podatnosc bez
			// poprawki jest do oceny ryzyka. Sklejone w jedna liczbe daja
			// sciane, ktorej nikt nie przeczyta - a w niej gina te, ktore
			// naprawde da sie zamknac.
			if ustalenie.VendorFix == VendorFixKnown {
				stan.AffectedWithVendorFix++
			} else {
				stan.AffectedNoFix++
			}
		case StateUnknown:
			stan.Unknown++
		}
	}
	stan.AffectedPackages = len(pakiety)
	stan.UniqueAdvisories = len(sprawy)
	stan.UniqueCVEs = len(cve)
	return Ocena{Findings: wynik, Stan: stan}
}

// ocenPakiet rozstrzyga jeden pakiet wobec jednego ustalenia producenta.
func ocenPakiet(wejscie Wejscie, snapshot Snapshot, pakiet packages.InstalledPackage,
	ustalenie Advisory, teraz time.Time) Assessment {
	wersjaPorownania, podstawa := WersjaPorownania(pakiet, wejscie.Distribution)
	ocena := Assessment{
		HostID: wejscie.HostID, InventoryDigest: wejscie.InventoryDigest,
		AdvisoryDigest: wejscie.AdvisoryDigest,
		Provider:       ustalenie.Provider, SnapshotDigest: snapshot.Digest,
		AdvisoryID: ustalenie.AdvisoryID, CVEIDs: ustalenie.CVEIDs,
		Distribution: wejscie.Distribution, Release: wejscie.Release,
		SourcePackage: ustalenie.SourcePackage, BinaryPackage: pakiet.Name,
		Architecture:      pakiet.Architecture,
		InstalledVersion:  WersjaPakietu(pakiet, wejscie.Distribution),
		ComparisonVersion: wersjaPorownania, ComparisonBasis: podstawa,
		FixedVersion: ustalenie.FixedVersion, VendorSeverity: ustalenie.VendorSeverity,
		ComparatorVersion: WersjaKomparatora, EvaluatedAt: teraz,
		PackageOrigin:       KlasaPochodzenia(pakiet, wejscie.Distribution),
		VendorFix:           VendorFixUnknown,
		RepositoryCandidate: CandidateUnknown,
		// Czy transakcje da sie wykonac, wie wylacznie plan pakietowy hosta:
		// on widzi wstrzymania, wykluczenia i konflikty. Dopoki go nie ma,
		// panel nie ma prawa niczego obiecywac.
		Transaction: TransactionUnknown,
	}

	switch ustalenie.Status {
	case StatusNieDotyczy:
		// Producent to rozstrzygnal - i to jest odpowiedz, a nie brak wiedzy.
		ocena.State = StateNotAffected
		return ocena
	case StatusBadane:
		ocena.State = StateUnknown
		ocena.ReasonCode = RodzajProducentBada
		return ocena
	case StatusOtwarte, StatusOdroczone:
		// Podatnosc bez poprawki: pakiet jest podatny i nie ma czym tego
		// naprawic. To wazniejsza wiadomosc niz podatnosc z poprawka.
		ocena.State = StateAffected
		ocena.VendorFix = VendorFixUnavailable
		ocena.RepositoryCandidate = CandidateAbsent
		return ocena
	}

	if ustalenie.FixedVersion == "" {
		ocena.State = StateAffected
		ocena.VendorFix = VendorFixUnavailable
		ocena.RepositoryCandidate = CandidateAbsent
		return ocena
	}
	wynik, ok := Porownaj(wejscie.Distribution, wersjaPorownania, ustalenie.FixedVersion)
	if !ok {
		ocena.State = StateUnknown
		ocena.ReasonCode = RodzajWersjaNieczytelna
		return ocena
	}
	ocena.VendorFix = VendorFixKnown
	if wynik < 0 {
		ocena.State = StateAffected
		// Ustalenie odczytane z metadanych samego hosta znaczy, ze poprawka
		// jest widoczna w repozytorium, z ktorego host bierze pakiety. To
		// nadal nie znaczy, ze transakcja przejdzie - o tym mowi plan.
		if ustalenie.FromHostRepositories {
			ocena.RepositoryCandidate = CandidateVisible
		}
		return ocena
	}
	ocena.State = StateNotAffected
	return ocena
}

// ustalenieNieznane opisuje pakiet, o ktorym producent nie ma prawa nic mowic.
func ustalenieNieznane(wejscie Wejscie, snapshot Snapshot, pakiet packages.InstalledPackage,
	powod string, teraz time.Time) Assessment {
	return Assessment{
		HostID: wejscie.HostID, InventoryDigest: wejscie.InventoryDigest,
		Provider: snapshot.Provider, SnapshotDigest: snapshot.Digest,
		Distribution: wejscie.Distribution, Release: wejscie.Release,
		SourcePackage: zrodloPakietu(pakiet), BinaryPackage: pakiet.Name,
		Architecture:     pakiet.Architecture,
		InstalledVersion: WersjaPakietu(pakiet, wejscie.Distribution),
		State:            StateUnknown, ReasonCode: powod,
		VendorFix: VendorFixUnknown, RepositoryCandidate: CandidateUnknown,
		Transaction: TransactionUnknown, ComparatorVersion: WersjaKomparatora,
		PackageOrigin:  KlasaPochodzenia(pakiet, wejscie.Distribution),
		AdvisoryDigest: wejscie.AdvisoryDigest, EvaluatedAt: teraz,
	}
}

// KlasaPochodzenia mowi, czyj jest pakiet.
//
// Producent dystrybucji ma prawo wypowiadac sie wylacznie o swoich pakietach.
// Pakiet z obcego repozytorium albo zbudowany lokalnie ma wersje, ktorej jego
// ustalenia nie opisuja - liczenie takiego pakietu jako objetego dawaloby
// pokrycie "sto procent" tam, gdzie panel nie wie nic.
func KlasaPochodzenia(pakiet packages.InstalledPackage, dystrybucja string) string {
	if rodzinaRPM(dystrybucja) {
		// RPM niesie producenta w metadanych pakietu.
		switch {
		case pakiet.Vendor == "":
			return PochodzenieNieznane
		case producentDystrybucji(pakiet.Vendor, dystrybucja):
			return PochodzenieDystrybucja
		default:
			return PochodzenieObce
		}
	}
	// APT nie zapisuje producenta przy pakiecie: pochodzenie bierze sie
	// z repozytorium, z ktorego wersja przyszla, i zbiera je agent.
	switch pakiet.OriginClass {
	case PochodzenieDystrybucja, PochodzenieObce, PochodzenieLokalne:
		return pakiet.OriginClass
	}
	return PochodzenieNieznane
}

// PowodPominiecia mowi, dlaczego pakiet nie podlega ocenie producenta.
func PowodPominiecia(pakiet packages.InstalledPackage, dystrybucja string) string {
	if zrodloPakietu(pakiet) == "" {
		return RodzajBrakZrodla
	}
	if KlasaPochodzenia(pakiet, dystrybucja) != PochodzenieDystrybucja {
		return RodzajPochodzenieNieznane
	}
	return ""
}

// producentDystrybucji rozpoznaje producenta pakietu.
func producentDystrybucji(vendor, dystrybucja string) bool {
	maly := strings.ToLower(vendor)
	switch dystrybucja {
	case "fedora":
		return strings.Contains(maly, "fedora")
	case "rhel", "centos":
		return strings.Contains(maly, "red hat") || strings.Contains(maly, "centos")
	case "almalinux":
		return strings.Contains(maly, "alma")
	case "rocky":
		return strings.Contains(maly, "rocky")
	}
	return false
}

// KluczKorelacji zwraca klucz, po ktorym szuka sie ustalen dla pakietu.
//
// Debian i Ubuntu prowadza bezpieczenstwo po pakiecie zrodlowym: jedno
// ustalenie dotyczy wszystkich binarnych z tego samego zrodla. Fedora mowi
// w updateinfo o pakietach binarnych, bo tam ustalenie jest lista konkretnych
// wersji do zainstalowania.
func KluczKorelacji(pakiet packages.InstalledPackage, dystrybucja string) string {
	if rodzinaRPM(dystrybucja) {
		return pakiet.Name
	}
	return zrodloPakietu(pakiet)
}

// zrodloPakietu zwraca nazwe pakietu zrodlowego.
func zrodloPakietu(pakiet packages.InstalledPackage) string {
	if pakiet.SourceName != "" {
		return pakiet.SourceName
	}
	return pakiet.Name
}

// WersjaPakietu sklada wersje pakietu binarnego - te, ktora widzi operator.
func WersjaPakietu(pakiet packages.InstalledPackage, dystrybucja string) string {
	if rodzinaRPM(dystrybucja) {
		return pakiet.EVR()
	}
	return pakiet.WersjaDeb()
}

// WersjaPorownania zwraca wersje, ktora nalezy porownac z ustaleniem, oraz to,
// skad ona pochodzi.
//
// Debian i Ubuntu prowadza bezpieczenstwo po pakiecie zrodlowym i podaja
// wersje zrodlowa - a wersja binarna bywa inna: przebudowa binarna dokleja
// sufiks ("+b9"), wiec binarna jest wyzsza od zrodlowej przy tym samym kodzie.
// Porownanie binarnej z ustaleniem zrodlowym potrafi wiec uznac pakiet za
// naprawiony, choc poprawki w nim nie ma.
//
// Gdy wersji zrodlowej nie znamy, porownujemy binarna i mowimy o tym wprost:
// to jest przyblizenie, a nie ta sama odpowiedz.
func WersjaPorownania(pakiet packages.InstalledPackage, dystrybucja string) (string, string) {
	if rodzinaRPM(dystrybucja) {
		return pakiet.EVR(), PodstawaBinarna
	}
	if pakiet.SourceVersion != "" {
		return pakiet.SourceVersion, PodstawaZrodlowa
	}
	return pakiet.WersjaDeb(), PodstawaBinarna
}

// Podstawy porownania wersji.
const (
	PodstawaZrodlowa = "source"
	PodstawaBinarna  = "binary"
)

// Porownaj porownuje wersje regulami wlasciwymi dla dystrybucji.
func Porownaj(dystrybucja, zainstalowana, naprawiona string) (int, bool) {
	if strings.TrimSpace(zainstalowana) == "" || strings.TrimSpace(naprawiona) == "" {
		return 0, false
	}
	if rodzinaRPM(dystrybucja) {
		return version.PorownajRPM(zainstalowana, naprawiona), true
	}
	return version.PorownajDeb(zainstalowana, naprawiona), true
}

func rodzinaRPM(dystrybucja string) bool {
	switch dystrybucja {
	case "fedora", "rhel", "centos", "almalinux", "rocky", "opensuse", "sles":
		return true
	}
	return false
}

// ObejmujeWydanie mowi, czy snapshot obejmuje wydanie hosta.
func ObejmujeWydanie(snapshot Snapshot, wydanie string) bool {
	if wydanie == "" {
		return false
	}
	for _, objete := range snapshot.Releases {
		if objete == wydanie {
			return true
		}
	}
	return false
}
