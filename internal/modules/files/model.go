// Package files zarzadza plikami konfiguracyjnymi hosta.
//
// To nie jest menedzer plikow roota. Panel, ktory potrafi zapisac dowolna
// sciezke, potrafi podmienic /etc/shadow i klucze prywatne - dlatego zakres
// jest wyliczony, a kazdy zapis ma znany stan przed i po.
package files

import "time"

// Rozmiar, powyzej ktorego panel nie pobiera tresci pliku.
//
// Modul jest do konfiguracji, a nie do przenoszenia danych: plik wiekszy niz
// to prawie na pewno nie jest konfiguracja, a jego tresc w bazie panelu
// bylaby kopia czegos, czego nikt tam nie chcial.
const MaksymalnyRozmiar = 1 << 20

// Plik opisuje jeden plik konfiguracyjny.
type Plik struct {
	Path string `json:"path"`
	// SHA256 jest odciskiem tresci. Pusty oznacza plik, ktorego nie udalo
	// sie odczytac - i wtedy powod niesie UnavailableReason.
	SHA256     string     `json:"sha256,omitempty"`
	SizeBytes  int64      `json:"size_bytes"`
	Mode       string     `json:"mode,omitempty"`
	Owner      string     `json:"owner,omitempty"`
	Group      string     `json:"group,omitempty"`
	ModifiedAt *time.Time `json:"modified_at,omitempty"`
	// Managed oznacza plik, ktory panel zna i ma dla niego stan docelowy.
	Managed bool `json:"managed"`
	// DesiredSHA256 jest odciskiem stanu docelowego. Rozny od SHA256 oznacza
	// drift: ktos zmienil plik poza panelem.
	DesiredSHA256 string `json:"desired_sha256,omitempty"`
	// Exists rozroznia plik usuniety od nieodczytanego.
	Exists            bool   `json:"exists"`
	UnavailableReason string `json:"unavailable_reason,omitempty"`
}

// Tresc to plik wraz z zawartoscia.
type Tresc struct {
	Plik
	Content string `json:"content"`
	// Truncated mowi, ze tresc jest urwana. Urwana tresc bez oznaczenia
	// wygladalaby jak caly plik - i tak trafilaby z powrotem na host.
	Truncated bool `json:"truncated"`
}

// Snapshot to obraz plikow zarzadzanych na hoscie.
type Snapshot struct {
	Files      []Plik    `json:"files,omitempty"`
	ObservedAt time.Time `json:"observed_at"`
	// UnavailableReason mowi, dlaczego stanu nie ustalono.
	UnavailableReason string `json:"unavailable_reason,omitempty"`
}

// Zapis opisuje zlecona zmiane pliku.
type Zapis struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	Mode    string `json:"mode,omitempty"`
	Owner   string `json:"owner,omitempty"`
	Group   string `json:"group,omitempty"`
	// ExpectedSHA256 wiaze zapis z trescia, ktora operator ogladal. Pusty
	// oznacza plik, ktorego jeszcze nie ma; wartosc niezgodna ze stanem hosta
	// zatrzymuje zapis, zamiast nadpisac cudza zmiane.
	ExpectedSHA256 string `json:"expected_sha256,omitempty"`
	// Validator wskazuje sprawdzenie tresci przed zapisem.
	Validator string `json:"validator,omitempty"`
}
