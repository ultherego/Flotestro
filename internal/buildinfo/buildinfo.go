// Package buildinfo mowi, z czego powstala ta binarka.
//
// Wersja sama nie wystarcza, gdy pakiet zachowuje sie inaczej niz powinien:
// pierwsze pytanie brzmi wtedy "z ktorego commita to jest" i musi dac sie
// odpowiedziec na hoscie, bez dostepu do maszyny wydania. Dlatego commit
// i data budowania sa wpisywane w binarke tak samo jak wersja.
//
// Wersja protokolu jest tu obok nich swiadomie: to ona rozstrzyga, czy stary
// agent w ogole dogada sie z panelem, a operator patrzacy na host powinien
// widziec komplet w jednym miejscu.
package buildinfo

import (
	"runtime"
	"runtime/debug"
	"strings"
)

// Wartosci wpisywane przy budowaniu wydania przez -ldflags -X.
//
// Domyslne mowia wprost, ze nikt ich nie wpisal. "nieznany" jest lepszy niz
// zmyslona wartosc: pakiet zbudowany recznie ma wygladac inaczej niz wydanie.
var (
	Wersja = "0.1.0"
	Commit = ""
	Data   = ""
)

// ProtokolAgenta zmienia sie przy kazdej niezgodnej zmianie kontraktu miedzy
// agentem a centrala.
const ProtokolAgenta = 1

// Opis sklada jedna linie dla polecenia "version".
func Opis(nazwa string) string {
	linia := nazwa + " " + Wersja
	if commit := KrotkiCommit(); commit != "" {
		linia += " (" + commit
		if Data != "" {
			linia += ", " + Data
		}
		linia += ")"
	}
	return linia + " [" + runtime.GOOS + "/" + runtime.GOARCH + ", " + runtime.Version() + "]"
}

// KrotkiCommit skraca odcisk commita do postaci czytelnej w jednej linii.
//
// Gdy wydanie nie wpisalo commita, probujemy odczytac go z metadanych
// budowania: przy zwyklym "go build" jest tam i wystarcza, zeby powiedziec,
// z czego powstala ta binarka.
func KrotkiCommit() string {
	commit := Commit
	if commit == "" {
		commit = commitZMetadanych()
	}
	if len(commit) > 12 {
		return commit[:12]
	}
	return commit
}

func commitZMetadanych() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	for _, ustawienie := range info.Settings {
		if ustawienie.Key == "vcs.revision" {
			return strings.TrimSpace(ustawienie.Value)
		}
	}
	return ""
}
