package files

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

// Walidator opisuje sprawdzenie tresci przed zapisem.
//
// Sprawdzenie ma sens wylacznie wtedy, gdy dotyczy tego, co plik naprawde
// znaczy: JSON z bledem skladni nie zostanie wczytany przez zadna usluge,
// a plik jednostki systemd z literowka w nazwie sekcji jest ignorowany po
// cichu. Walidator, ktorego host nie ma, nie jest powodem do zapisu bez
// sprawdzenia - jest powodem do powiedzenia tego wprost.
type Walidator struct {
	Nazwa string
	// Polecenie sprawdza plik na hoscie. Puste oznacza walidator wbudowany,
	// wykonywany bez uruchamiania czegokolwiek.
	Polecenie []string
	// Wbudowany sprawdza tresc w pamieci.
	Wbudowany func(tresc string) error
}

// walidatory wylicza znane sprawdzenia. Klucz jest nazwa uzywana w zleceniu.
var walidatory = map[string]Walidator{
	"json": {Nazwa: "json", Wbudowany: walidujJSON},
	"ini":  {Nazwa: "ini", Wbudowany: walidujINI},
	"systemd-unit": {
		Nazwa:     "systemd-unit",
		Polecenie: []string{"/usr/bin/systemd-analyze", "verify"},
	},
	"nginx": {
		Nazwa: "nginx",
		// nginx sprawdza cala konfiguracje, a nie pojedynczy plik: fragment
		// bez kontekstu nie jest poprawna konfiguracja sam w sobie.
		Polecenie: []string{"/usr/sbin/nginx", "-t"},
	},
	"chrony": {
		Nazwa:     "chrony",
		Polecenie: []string{"/usr/sbin/chronyd", "-Q", "-f"},
	},
}

// WybierzWalidator dobiera sprawdzenie do sciezki, gdy zlecenie go nie podalo.
func WybierzWalidator(sciezka, wskazany string) (Walidator, bool, error) {
	if wskazany != "" {
		walidator, znany := walidatory[wskazany]
		if !znany {
			return Walidator{}, false, fmt.Errorf("nieznany walidator %q", wskazany)
		}
		return walidator, true, nil
	}
	switch {
	case strings.HasSuffix(sciezka, ".json"):
		return walidatory["json"], true, nil
	case strings.HasPrefix(sciezka, "/etc/systemd/system/") &&
		(strings.HasSuffix(sciezka, ".service") || strings.HasSuffix(sciezka, ".timer")):
		return walidatory["systemd-unit"], true, nil
	case strings.HasPrefix(sciezka, "/etc/nginx/"):
		return walidatory["nginx"], true, nil
	case strings.HasPrefix(filepath.Base(sciezka), "chrony"):
		return walidatory["chrony"], true, nil
	}
	return Walidator{}, false, nil
}

// walidujJSON sprawdza skladnie JSON.
func walidujJSON(tresc string) error {
	var cel any
	if err := json.Unmarshal([]byte(tresc), &cel); err != nil {
		return fmt.Errorf("plik nie jest poprawnym JSON: %w", err)
	}
	return nil
}

// walidujINI sprawdza podstawowa skladnie plikow klucz-wartosc.
//
// Nie udajemy pelnego parsera: sprawdzamy to, co psuje pliki najczesciej -
// wiersz, ktory nie jest ani sekcja, ani komentarzem, ani przypisaniem.
func walidujINI(tresc string) error {
	for numer, linia := range strings.Split(tresc, "\n") {
		przyciety := strings.TrimSpace(linia)
		if przyciety == "" || strings.HasPrefix(przyciety, "#") || strings.HasPrefix(przyciety, ";") {
			continue
		}
		if strings.HasPrefix(przyciety, "[") && strings.HasSuffix(przyciety, "]") {
			continue
		}
		if !strings.Contains(przyciety, "=") {
			return fmt.Errorf("wiersz %d nie jest przypisaniem ani sekcja: %q", numer+1, przyciety)
		}
	}
	return nil
}
