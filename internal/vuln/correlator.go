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
	// InventoryDigest wiaze ocene z konkretnym obrazem listy pakietow.
	InventoryDigest string
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
		InventoryDigest: wejscie.InventoryDigest,
		PackagesTotal:   len(wejscie.Packages),
		EvaluatedAt:     &teraz,
	}

	// Kolejnosc powodow ma znaczenie: mowimy o najpowazniejszej przeszkodzie,
	// a nie o pierwszej napotkanej.
	switch {
	case wejscie.BrakListy:
		stan.CoverageReason = RodzajBrakListy
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

	for _, ustalenie := range wynik {
		switch ustalenie.State {
		case StateAffected:
			stan.Affected++
			// Podatnosc z poprawka jest do zainstalowania dzis; podatnosc bez
			// poprawki jest do oceny ryzyka. Sklejone w jedna liczbe daja
			// sciane, ktorej nikt nie przeczyta - a w niej gina te, ktore
			// naprawde da sie zamknac.
			if ustalenie.FixedVersion != "" {
				stan.AffectedFixable++
			} else {
				stan.AffectedNoFix++
			}
		case StateUnknown:
			stan.Unknown++
		}
	}
	return Ocena{Findings: wynik, Stan: stan}
}

// ocenPakiet rozstrzyga jeden pakiet wobec jednego ustalenia producenta.
func ocenPakiet(wejscie Wejscie, snapshot Snapshot, pakiet packages.InstalledPackage,
	ustalenie Advisory, teraz time.Time) Assessment {
	ocena := Assessment{
		HostID: wejscie.HostID, InventoryDigest: wejscie.InventoryDigest,
		Provider: ustalenie.Provider, SnapshotDigest: snapshot.Digest,
		AdvisoryID: ustalenie.AdvisoryID, CVEIDs: ustalenie.CVEIDs,
		Distribution: wejscie.Distribution, Release: wejscie.Release,
		SourcePackage: ustalenie.SourcePackage, BinaryPackage: pakiet.Name,
		Architecture: pakiet.Architecture, InstalledVersion: WersjaPakietu(pakiet, wejscie.Distribution),
		FixedVersion: ustalenie.FixedVersion, VendorSeverity: ustalenie.VendorSeverity,
		ComparatorVersion: WersjaKomparatora, EvaluatedAt: teraz,
		Remediation: RemediationUnknown,
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
		ocena.Remediation = RemediationUnavailable
		return ocena
	}

	if ustalenie.FixedVersion == "" {
		ocena.State = StateAffected
		ocena.Remediation = RemediationUnavailable
		return ocena
	}
	wynik, ok := Porownaj(wejscie.Distribution, ocena.InstalledVersion, ustalenie.FixedVersion)
	if !ok {
		ocena.State = StateUnknown
		ocena.ReasonCode = RodzajWersjaNieczytelna
		return ocena
	}
	if wynik < 0 {
		ocena.State = StateAffected
		// Czy poprawke da sie zainstalowac teraz, rozstrzyga plan pakietowy
		// hosta: advisory mowi tylko, ze taka wersja istnieje. Wyjatkiem jest
		// ustalenie odczytane z metadanych samego hosta - wtedy poprawka lezy
		// w repozytorium, z ktorego host bierze pakiety, i to jest odpowiedz,
		// a nie domysl.
		ocena.Remediation = RemediationUnknown
		if ustalenie.FromHostRepositories {
			ocena.Remediation = RemediationAvailable
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
		Remediation: RemediationUnknown, ComparatorVersion: WersjaKomparatora,
		EvaluatedAt: teraz,
	}
}

// PowodPominiecia mowi, dlaczego pakiet nie podlega ocenie producenta.
//
// Pakiet przebudowany lokalnie albo pobrany z obcego repozytorium ma wersje,
// ktorej producent dystrybucji nie zna. Udawanie, ze ustalenia dotycza takiego
// pakietu, dawaloby falszywe alarmy albo - gorzej - falszywe "bezpieczny".
func PowodPominiecia(pakiet packages.InstalledPackage, dystrybucja string) string {
	if zrodloPakietu(pakiet) == "" {
		return RodzajBrakZrodla
	}
	switch dystrybucja {
	case "fedora", "rhel", "centos", "almalinux", "rocky":
		// RPM niesie producenta w metadanych: pakiet spoza dystrybucji
		// rozpoznajemy po nim, a nie po nazwie.
		if pakiet.Vendor == "" {
			return RodzajPochodzenieNieznane
		}
		if !producentDystrybucji(pakiet.Vendor, dystrybucja) {
			return RodzajPochodzenieNieznane
		}
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

// WersjaPakietu sklada wersje pakietu w postaci uzywanej przez dystrybucje.
func WersjaPakietu(pakiet packages.InstalledPackage, dystrybucja string) string {
	if rodzinaRPM(dystrybucja) {
		return pakiet.EVR()
	}
	return pakiet.WersjaDeb()
}

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
