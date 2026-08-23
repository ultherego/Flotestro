package firewall

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// KatalogRejestru trzyma stan regul panelu i plany ich wycofania.
//
// Katalog nalezy do roota. Rejestr jest lista regul w postaci, ktora panel
// rozumie - nie skryptem nft. Plik, ktorym da sie sterowac wykonaniem, bylby
// furtka do roota nawet dla roota-omylki.
const (
	KatalogRejestru = "/var/lib/flotestro-helper/zapora"
	PlikRejestru    = "reguly.json"
)

// Rejestr to reguly, ktore panel uwaza za swoje.
//
// Uchwyt nadaje jadro i zmienia sie przy kazdym przeladowaniu tablicy, wiec
// nie nadaje sie na tozsamosc reguly. Rejestr jest zrodlem prawdy o tym, co
// panel zalozyl, i pozwala odtworzyc tablice od zera - takze przy wycofaniu.
type Rejestr struct {
	Rules     []RuleSpec `json:"rules"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// WczytajRejestr czyta rejestr regul. Brak pliku oznacza host, na ktorym
// panel jeszcze niczego nie zalozyl - i to nie jest blad.
func WczytajRejestr(katalog string) (Rejestr, error) {
	dane, err := os.ReadFile(filepath.Join(katalog, PlikRejestru))
	if os.IsNotExist(err) {
		return Rejestr{}, nil
	}
	if err != nil {
		return Rejestr{}, err
	}
	var rejestr Rejestr
	if err := json.Unmarshal(dane, &rejestr); err != nil {
		return Rejestr{}, err
	}
	return rejestr, nil
}

// ZapiszRejestr zapisuje rejestr regul.
func ZapiszRejestr(katalog string, rejestr Rejestr) error {
	if err := os.MkdirAll(katalog, 0o700); err != nil {
		return err
	}
	dane, err := json.Marshal(rejestr)
	if err != nil {
		return err
	}
	sciezka := filepath.Join(katalog, PlikRejestru)
	// Zapis atomowy: rejestr odczytany w polowie nie odtworzylby tablicy,
	// a wlasnie wtedy jest potrzebny.
	tymczasowy := sciezka + ".nowy"
	if err := os.WriteFile(tymczasowy, dane, 0o600); err != nil {
		return err
	}
	return os.Rename(tymczasowy, sciezka)
}

// Ustaw dodaje albo zastepuje regule o tej samej nazwie.
//
// Ta sama nazwa oznacza te sama regule: powtorzenie operacji z tym samym
// payloadem niczego nie dubluje.
func (r Rejestr) Ustaw(regula RuleSpec) Rejestr {
	nowy := Rejestr{Rules: make([]RuleSpec, 0, len(r.Rules)+1)}
	zastapiona := false
	for _, istniejaca := range r.Rules {
		if istniejaca.ID == regula.ID {
			nowy.Rules = append(nowy.Rules, regula)
			zastapiona = true
			continue
		}
		nowy.Rules = append(nowy.Rules, istniejaca)
	}
	if !zastapiona {
		nowy.Rules = append(nowy.Rules, regula)
	}
	return nowy
}

// Usun kasuje regule o podanej nazwie.
func (r Rejestr) Usun(id string) (Rejestr, bool) {
	nowy := Rejestr{Rules: make([]RuleSpec, 0, len(r.Rules))}
	znaleziona := false
	for _, regula := range r.Rules {
		if regula.ID == id {
			znaleziona = true
			continue
		}
		nowy.Rules = append(nowy.Rules, regula)
	}
	return nowy, znaleziona
}

// ArgumentyPrzebudowy sklada polecenia odtwarzajace tablice panelu z rejestru.
//
// Tablica jest budowana od zera, a nie poprawiana: kolejnosc regul decyduje
// o tym, ktora zadziala pierwsza, wiec dopisywanie na koniec dawaloby inny
// skutek niz to, co operator widzial w planie.
func ArgumentyPrzebudowy(rejestr Rejestr) ([][]string, error) {
	kroki := ArgumentyZalozeniaTablicy()
	// Flush czysci reguly, zostawiajac lancuchy: lancuch usuniety i zalozony
	// na nowo gubi zaczepienie w sciezce pakietu na czas przebudowy.
	kroki = append(kroki, []string{SciezkaNft, "flush", "table", RodzinaFlotestro, TabelaFlotestro})
	for _, regula := range rejestr.Rules {
		argumenty, err := ArgumentyReguly(regula)
		if err != nil {
			return nil, fmt.Errorf("regula %s: %w", regula.ID, err)
		}
		kroki = append(kroki, argumenty)
	}
	return kroki, nil
}

// ArgumentyUsunieciaTablicy kasuje cala tablice panelu.
//
// Uzywane, gdy panel nie ma juz zadnej reguly: pusta tablica z zaczepionymi
// lancuchami niczego nie filtruje, ale zostawia w wykazie obiekt, ktorego
// nikt nie potrzebuje.
func ArgumentyUsunieciaTablicy() []string {
	return []string{SciezkaNft, "delete", "table", RodzinaFlotestro, TabelaFlotestro}
}
