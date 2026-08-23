package network

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// KatalogWycofan trzyma plany wycofania zmian sieci.
//
// Katalog nalezy do roota i tylko root ma do niego dostep. Plan nie zawiera
// polecen do uruchomienia, tylko ustawienia profilu - argumenty sklada z nich
// ten sam kod, ktory sklada je przy zapisie. Plik, ktorym da sie sterowac
// wykonaniem, bylby furtka do roota nawet dla roota-omylki.
const KatalogWycofan = "/var/lib/flotestro-helper/wycofania"

// PlanWycofania opisuje stan, do ktorego host ma wrocic, gdy zmiana sieci
// odetnie go od panelu.
//
// Wycofanie jest uzbrajane przed zmiana i rozbrajane dopiero po tym, jak
// agent potwierdzi, ze nadal rozmawia z panelem. Odwrotna kolejnosc
// zostawialaby okno, w ktorym host jest juz odciety, a nic go nie ratuje.
type PlanWycofania struct {
	ID string `json:"id"`
	// Profil jest stanem sprzed zmiany, odczytanym z NetworkManagera.
	Profil Profil `json:"profile"`
	// Interfejs i Zarzadzajacy mowia, czego zmiana dotyczyla. Zmiana
	// interfejsu zarzadzania jest tym przypadkiem, dla ktorego to wszystko
	// powstalo.
	Interfejs    string    `json:"interface"`
	Zarzadzajacy bool      `json:"management"`
	Utworzony    time.Time `json:"created_at"`
	// Termin jest chwila, po ktorej wycofanie ma sie wykonac.
	Termin time.Time `json:"deadline"`
	Powod  string    `json:"reason,omitempty"`
}

// SciezkaPlanu zwraca plik planu o podanym identyfikatorze.
func SciezkaPlanu(katalog, id string) (string, error) {
	if !PoprawnyIdentyfikatorPlanu(id) {
		return "", fmt.Errorf("nieprawidlowy identyfikator planu %q", id)
	}
	return filepath.Join(katalog, id+".json"), nil
}

// PoprawnyIdentyfikatorPlanu dopuszcza wylacznie znaki, ktore nie moga
// wyprowadzic sciezki poza katalog planow.
func PoprawnyIdentyfikatorPlanu(id string) bool {
	if len(id) == 0 || len(id) > 64 {
		return false
	}
	for _, znak := range id {
		if (znak < 'a' || znak > 'z') && (znak < '0' || znak > '9') && znak != '-' {
			return false
		}
	}
	return true
}

// ZapiszPlan zapisuje plan wycofania.
func ZapiszPlan(katalog string, plan PlanWycofania) error {
	if err := os.MkdirAll(katalog, 0o700); err != nil {
		return err
	}
	sciezka, err := SciezkaPlanu(katalog, plan.ID)
	if err != nil {
		return err
	}
	dane, err := json.Marshal(plan)
	if err != nil {
		return err
	}
	// Zapis atomowy: plan czytany w polowie jest planem, ktory nie przywroci
	// niczego, a wlasnie wtedy jest potrzebny.
	tymczasowy := sciezka + ".nowy"
	if err := os.WriteFile(tymczasowy, dane, 0o600); err != nil {
		return err
	}
	return os.Rename(tymczasowy, sciezka)
}

// WczytajPlan czyta plan wycofania.
func WczytajPlan(katalog, id string) (PlanWycofania, error) {
	sciezka, err := SciezkaPlanu(katalog, id)
	if err != nil {
		return PlanWycofania{}, err
	}
	dane, err := os.ReadFile(sciezka)
	if err != nil {
		return PlanWycofania{}, err
	}
	var plan PlanWycofania
	if err := json.Unmarshal(dane, &plan); err != nil {
		return PlanWycofania{}, err
	}
	return plan, nil
}

// OdlozNieudanyPlan odklada plan, ktorego wycofanie sie nie powiodlo.
//
// Plan, ktorego zegar juz wybil, jest martwy niezaleznie od wyniku: nikt go
// wiecej nie wykona. Zostawiony w katalogu planow wygladalby jak wycofanie
// wciaz czekajace na swoja chwile, wiec odkladamy go obok - jako slad tego,
// czego host nie zdolal przywrocic.
func OdlozNieudanyPlan(katalog, id string) error {
	sciezka, err := SciezkaPlanu(katalog, id)
	if err != nil {
		return err
	}
	return os.Rename(sciezka, sciezka+".nieudane")
}

// UsunPlan kasuje plan wycofania.
func UsunPlan(katalog, id string) error {
	sciezka, err := SciezkaPlanu(katalog, id)
	if err != nil {
		return err
	}
	if err := os.Remove(sciezka); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// KrokiWycofania sklada polecenia przywracajace stan sprzed zmiany.
//
// Argumenty powstaja z ustawien profilu tym samym kodem, ktory sklada je przy
// zapisie: plan nie moze wyrazic polecenia, ktorego ten modul nie zna.
func KrokiWycofania(plan PlanWycofania) ([][]string, error) {
	profil := plan.Profil
	if profil.Polaczenie == "" {
		return nil, fmt.Errorf("plan wycofania bez profilu polaczenia")
	}
	// Profil sprzed zmiany moze byc pusty w polach, ktorych NetworkManager
	// nie mial ustawionych - i wlasnie taki ma wrocic.
	if profil.Metoda == "" {
		profil.Metoda = "auto"
	}
	if profil.Metoda == "manual" && len(profil.Adresy) == 0 {
		return nil, fmt.Errorf("plan wycofania z metoda manual bez adresow")
	}
	return ArgumentyProfilu(profil)
}

// NazwaJednostkiWycofania zwraca nazwe przejsciowej jednostki systemd, ktora
// wykona wycofanie. Jedna jednostka na plan: druga zmiana nie moze po cichu
// przejac zegara pierwszej.
func NazwaJednostkiWycofania(id string) string {
	return "flotestro-wycofanie-" + id
}
