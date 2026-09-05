package vuln

import "time"

// Stan oceny pojedynczego pakietu wobec ustalenia trackera.
//
// Trzy stany, nie dwa. "Nie wiadomo" jest odpowiedzia, a nie brakiem
// odpowiedzi: host, ktorego dystrybucji feed nie obejmuje, nie jest hostem
// bezpiecznym - jest hostem, o ktorym panel nie ma prawa nic powiedziec.
type AssessmentState string

const (
	StateAffected    AssessmentState = "affected"
	StateNotAffected AssessmentState = "not_affected"
	StateUnknown     AssessmentState = "unknown"
)

// Naprawa ma trzy osie, bo sa to trzy rozne pytania i trzy rozne zrodla
// odpowiedzi. Sklejone w jedno slowo obiecywaly wiecej, niz panel sprawdzil:
// "dostepna" znaczylo tylko tyle, ze producent gdzies wydal nowsza wersje.
//
// VendorFix mowi, czy producent w ogole wydal poprawke. Odpowiada advisory.
// RepositoryCandidate mowi, czy ta wersja jest widoczna w repozytoriach hosta.
// Odpowiadaja metadane repozytoriow - i tylko dla nich, dla ktorych je mamy.
// Transaction mowi, czy da sie ja teraz zainstalowac. Odpowiada wylacznie plan
// pakietowy hosta: dopiero on widzi wstrzymania, wykluczenia, konflikty
// modulow i rozwiazanie zaleznosci.
type VendorFixState string

const (
	VendorFixKnown       VendorFixState = "known"
	VendorFixUnavailable VendorFixState = "unavailable"
	VendorFixUnknown     VendorFixState = "unknown"
)

type RepositoryCandidateState string

const (
	CandidateVisible RepositoryCandidateState = "visible"
	CandidateAbsent  RepositoryCandidateState = "absent"
	CandidateUnknown RepositoryCandidateState = "unknown"
)

type TransactionState string

const (
	TransactionInstallable TransactionState = "installable"
	TransactionBlocked     TransactionState = "blocked"
	TransactionUnknown     TransactionState = "unknown"
)

// Klasy pochodzenia pakietu. Producent dystrybucji ma prawo mowic wylacznie
// o swoich pakietach: przebudowany lokalnie albo wziety z obcego repozytorium
// ma wersje, ktorej jego ustalenia nie opisuja.
const (
	PochodzenieDystrybucja = "vendor_distribution"
	PochodzenieObce        = "third_party_repository"
	PochodzenieLokalne     = "local_package"
	PochodzenieNieznane    = "origin_unknown"
)

// Kody powodu dla stanu nieustalonego. Kazdy "unknown" musi miec powod:
// bez niego nie da sie odroznic dziury w danych od dziury w hoscie.
const (
	// RodzajBrakFeedu oznacza brak snapshotu dla tej dystrybucji.
	RodzajBrakFeedu = "feed_missing"
	// RodzajFeedNieswiezy oznacza snapshot starszy niz dopuszcza polityka.
	RodzajFeedNieswiezy = "feed_stale"
	// RodzajWydanieNieobslugiwane oznacza wydanie spoza feedu.
	RodzajWydanieNieobslugiwane = "release_unsupported"
	// RodzajPochodzenieNieznane oznacza pakiet, ktorego producenta nie da sie
	// ustalic - na przyklad przebudowany lokalnie albo z obcego repozytorium.
	RodzajPochodzenieNieznane = "package_origin_unknown"
	// RodzajBrakZrodla oznacza pakiet bez znanego pakietu zrodlowego.
	RodzajBrakZrodla = "source_package_unknown"
	// RodzajProducentBada oznacza ustalenie, ktorego producent jeszcze nie
	// rozstrzygnal.
	RodzajProducentBada = "vendor_investigating"
	// RodzajWersjaNieczytelna oznacza wersje, ktorej nie da sie porownac.
	RodzajWersjaNieczytelna = "version_unparseable"
	// RodzajDystrybucjaEOL oznacza wydanie po koncu wsparcia: producent nie
	// wydaje juz poprawek, wiec brak ustalenia nie znaczy "bezpieczne".
	RodzajDystrybucjaEOL = "distribution_eol"
	// RodzajBrakListy oznacza hosta, ktorego listy pakietow panel jeszcze nie
	// pobral. To najczestszy powod pustej oceny i najgrozniejszy do
	// przemilczenia.
	RodzajBrakListy = "package_list_missing"
	// RodzajListaNieaktualna oznacza liste starsza niz stan zgloszony przez
	// hosta w inwentarzu.
	RodzajListaNieaktualna = "package_list_stale"
	// RodzajBrakUstalen oznacza hosta, ktorego metadanych repozytoriow panel
	// jeszcze nie odczytal. Dla rodziny RPM to one sa zrodlem rozstrzygajacym,
	// wiec ich brak jest brakiem oceny, a nie hostem czystym.
	RodzajBrakUstalen = "host_advisories_missing"
	// RodzajUstaleniaNieczytelne oznacza metadane, ktorych nie dalo sie
	// rozpoznac. Blad odczytu nie moze wygladac jak host bez ustalen.
	RodzajUstaleniaNieczytelne = "host_advisories_unreadable"
	// RodzajUstaleniaNieswieze oznacza ustalenia starsze, niz dopuszcza
	// polityka odswiezania.
	RodzajUstaleniaNieswieze = "host_advisories_stale"
)

// Assessment jest jednym ustaleniem: co panel wie o jednym pakiecie na jednym
// hoscie wobec jednego ustalenia trackera.
type Assessment struct {
	HostID string `json:"host_id"`
	// InventoryDigest wiaze ustalenie z konkretnym obrazem listy pakietow,
	// a AdvisoryDigest - z konkretnym zestawem ustalen producenta. Dwa
	// odciski, bo to dwa niezalezne zrodla: zestaw ustalen zmienia sie takze
	// wtedy, gdy na hoscie nie zmienil sie ani jeden pakiet.
	InventoryDigest string `json:"inventory_digest,omitempty"`
	AdvisoryDigest  string `json:"advisory_digest,omitempty"`

	// Provider i SnapshotDigest mowia, ktore dane rozstrzygnely. Bez nich
	// nie da sie odtworzyc, dlaczego panel powiedzial to, co powiedzial.
	Provider       string   `json:"provider"`
	SnapshotDigest string   `json:"snapshot_digest,omitempty"`
	AdvisoryID     string   `json:"advisory_id,omitempty"`
	CVEIDs         []string `json:"cve_ids,omitempty"`

	Distribution  string `json:"distribution"`
	Release       string `json:"release,omitempty"`
	SourcePackage string `json:"source_package,omitempty"`
	BinaryPackage string `json:"binary_package,omitempty"`
	Architecture  string `json:"architecture,omitempty"`

	// InstalledVersion jest wersja pakietu binarnego - ta, ktora widzi
	// operator na hoscie.
	InstalledVersion string `json:"installed_version,omitempty"`
	// ComparisonVersion jest wersja, ktora naprawde porownano z ustaleniem,
	// a ComparisonBasis mowi, skad ona pochodzi. Debian prowadzi
	// bezpieczenstwo po pakiecie zrodlowym, a wersja binarna bywa inna niz
	// zrodlowa (przebudowa binarna dokleja sufiks) - porownanie binarnej
	// z zrodlowa potrafi zakwalifikowac podatnosc odwrotnie, niz trzeba.
	ComparisonVersion string `json:"comparison_version,omitempty"`
	ComparisonBasis   string `json:"comparison_basis,omitempty"`
	FixedVersion      string `json:"fixed_version,omitempty"`

	State      AssessmentState `json:"state"`
	ReasonCode string          `json:"reason_code,omitempty"`
	// Trzy osie naprawy: co wydal producent, co widac w repozytoriach hosta
	// i co da sie naprawde zainstalowac. Ostatnia rozstrzyga tylko plan
	// pakietowy, wiec dopoki go nie ma, zostaje nieustalona.
	VendorFix           VendorFixState           `json:"vendor_fix"`
	RepositoryCandidate RepositoryCandidateState `json:"repository_candidate"`
	Transaction         TransactionState         `json:"transaction"`
	VendorSeverity      string                   `json:"vendor_severity,omitempty"`
	// PackageOrigin mowi, czyj jest ten pakiet. Bez tego pakiet z obcego
	// repozytorium liczylby sie jako objety ustaleniami producenta.
	PackageOrigin string `json:"package_origin,omitempty"`

	// ComparatorVersion opisuje regule porownania wersji, ktora uzyto.
	ComparatorVersion string    `json:"comparator_version,omitempty"`
	EvaluatedAt       time.Time `json:"evaluated_at"`
}

// Ustalone mowi, czy ustalenie jest rozstrzygniete.
func (a Assessment) Ustalone() bool { return a.State != StateUnknown }

// Wymaga mowi, czy ustalenie wymaga dzialania.
func (a Assessment) Wymaga() bool { return a.State == StateAffected }

// Advisory jest jednym ustaleniem trackera dystrybucji.
//
// To producent dystrybucji mowi, ktora wersja jest naprawiona - i tylko on.
// Feed upstreamowy moze pozniej dolozyc CVSS i opis, ale nie moze zmienic tej
// odpowiedzi: poprawki backportowane maja numery wersji, ktorych zaden zakres
// z NVD nie obejmuje.
type Advisory struct {
	Provider   string   `json:"provider"`
	AdvisoryID string   `json:"advisory_id"`
	CVEIDs     []string `json:"cve_ids,omitempty"`

	Distribution string `json:"distribution"`
	Release      string `json:"release"`
	// SourcePackage jest kluczem korelacji: tracker mowi o pakiecie
	// zrodlowym, a host ma pakiety binarne.
	SourcePackage string `json:"source_package"`
	// BinaryPackage zawezaja ustalenie do jednego pakietu binarnego; puste
	// oznacza cale zrodlo.
	BinaryPackage string `json:"binary_package,omitempty"`
	// Architecture zawezaja ustalenie do jednej architektury. Producent
	// wydaje osobne pakiety dla kazdej, a poprawka dla i686 nie naprawia
	// pakietu x86_64 - i nie moze byc do niego przypisana.
	Architecture string `json:"architecture,omitempty"`
	// FixedVersion pusta oznacza ustalenie bez poprawki: pakiet jest podatny
	// i nie ma czym tego naprawic.
	FixedVersion string `json:"fixed_version,omitempty"`
	// Status jest stanem ustalenia u producenta.
	Status         string     `json:"status"`
	VendorSeverity string     `json:"vendor_severity,omitempty"`
	Title          string     `json:"title,omitempty"`
	URL            string     `json:"url,omitempty"`
	PublishedAt    *time.Time `json:"published_at,omitempty"`
	// FromHostRepositories oznacza ustalenie odczytane z metadanych
	// repozytoriow samego hosta. Wtedy poprawka jest osiagalna z definicji:
	// host widzi ja w repozytorium, z ktorego bierze pakiety.
	FromHostRepositories bool `json:"from_host_repositories,omitempty"`
}

// Statusy ustalen u producenta.
const (
	// StatusNaprawione oznacza wersje, od ktorej pakiet nie jest podatny.
	StatusNaprawione = "fixed"
	// StatusOtwarte oznacza podatnosc bez poprawki.
	StatusOtwarte = "open"
	// StatusNieDotyczy oznacza pakiet, ktorego ustalenie nie dotyczy w tym
	// wydaniu - producent to rozstrzygnal, wiec to nie jest "nie wiadomo".
	StatusNieDotyczy = "not_affected"
	// StatusBadane oznacza ustalenie, ktorego producent jeszcze nie zamknal.
	StatusBadane = "under_investigation"
	// StatusOdroczone oznacza podatnosc, ktorej producent nie zamierza
	// naprawiac w tym wydaniu.
	StatusOdroczone = "deferred"
)

// Snapshot jest jednym pobraniem feedu.
//
// Snapshot ma odcisk i wiek: ocena bez wskazania, ktore dane ja
// rozstrzygnely, nie da sie powtorzyc ani obronic.
type Snapshot struct {
	ID       string `json:"id,omitempty"`
	Provider string `json:"provider"`
	// Digest jest odciskiem kanonicznej postaci danych. Powtorzone pobranie
	// tych samych danych daje ten sam odcisk i nie tworzy nowego snapshotu.
	Digest string `json:"digest"`
	// Releases wylicza wydania objete tym snapshotem. To z tego bierze sie
	// odpowiedz "tego wydania feed nie obejmuje".
	Releases      []string  `json:"releases,omitempty"`
	AdvisoryCount int       `json:"advisory_count"`
	FetchedAt     time.Time `json:"fetched_at"`
	// SourceModifiedAt jest data, ktora podal serwer feedu.
	SourceModifiedAt *time.Time `json:"source_modified_at,omitempty"`
	// ETag pozwala nie pobierac danych, ktore sie nie zmienily.
	ETag   string `json:"etag,omitempty"`
	Active bool   `json:"active"`
	// Error opisuje nieudane pobranie. Snapshot z bledem nie zastepuje
	// poprzedniego: lepiej ocenic starszymi danymi i powiedziec, ze sa
	// starsze, niz nie ocenic wcale.
	Error string `json:"error,omitempty"`
}

// Nieswiezy mowi, czy snapshot jest starszy, niz dopuszcza polityka.
func (s Snapshot) Nieswiezy(maksymalnyWiek time.Duration, teraz time.Time) bool {
	if s.FetchedAt.IsZero() {
		return true
	}
	return teraz.Sub(s.FetchedAt) > maksymalnyWiek
}
