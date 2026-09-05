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

// Stan naprawy odpowiada na inne pytanie niz stan podatnosci: nie "czy jest
// dziura", tylko "czy da sie ja teraz zalatac na tym hoscie". Advisory moze
// mowic "naprawione od wersji X", a repozytoria hosta tej wersji nie miec.
type RemediationState string

const (
	RemediationAvailable   RemediationState = "available"
	RemediationUnavailable RemediationState = "unavailable"
	RemediationBlocked     RemediationState = "blocked"
	RemediationUnknown     RemediationState = "unknown"
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
)

// Assessment jest jednym ustaleniem: co panel wie o jednym pakiecie na jednym
// hoscie wobec jednego ustalenia trackera.
type Assessment struct {
	HostID string `json:"host_id"`
	// InventoryDigest wiaze ustalenie z konkretnym obrazem listy pakietow.
	// Ocena bez tego wiazania nie da sie powtorzyc ani uniewaznic.
	InventoryDigest string `json:"inventory_digest,omitempty"`

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

	InstalledVersion string `json:"installed_version,omitempty"`
	FixedVersion     string `json:"fixed_version,omitempty"`

	State      AssessmentState `json:"state"`
	ReasonCode string          `json:"reason_code,omitempty"`
	// Remediation mowi, czy poprawke da sie zainstalowac teraz. Rozstrzyga
	// o tym plan pakietowy hosta, a nie advisory.
	Remediation    RemediationState `json:"remediation"`
	VendorSeverity string           `json:"vendor_severity,omitempty"`

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
