package packages

import (
	"strings"
)

// maksymalnaDlugoscPowodu ogranicza komunikat w wyniku zadania. Dluzszy tekst
// i tak nie zmiesci sie w liscie operacji, a operator potrzebuje zdania,
// nie transkryptu.
const maksymalnaDlugoscPowodu = 400

// znacznikiBledu rozpoznaja linie, ktore niosa przyczyne. Lista jest wspolna
// dla apta i dnf-a: obie rodziny pisza po angielsku niezaleznie od locale,
// bo narzedzia uruchamiamy z LC_ALL=C.
var znacznikiBledu = []string{
	"error", "e: ", "problem", "failed", "failure", "cannot", "conflict",
	"no match", "nothing provides", "sub-process", "unmet dependencies",
}

// opisBledu wybiera z wyjscia narzedzia linie, ktore naprawde mowia, co poszlo
// nie tak.
//
// Pierwsza linia nie jest przyczyna. Dnf wypisuje na stderr paski postepu,
// wiec branie pierwszej linii dawalo operatorowi komunikat w rodzaju
// "[1/36] Verify package files 100% | 33 B/s" - prawdziwy, bezuzyteczny
// i nie do odroznienia od sukcesu.
func opisBledu(stderr, stdout string) string {
	linie := append(uzyteczneLinie(stderr), uzyteczneLinie(stdout)...)
	if len(linie) == 0 {
		return ""
	}

	// Linia ze znacznikiem bledu i to, co po niej nastepuje: dnf pisze
	// "Error: Transaction failed", a szczegoly dopiero nizej.
	for i, linia := range linie {
		if maZnacznikBledu(linia) {
			return zlacz(linie[i:])
		}
	}
	// Bez znacznika liczy sie koniec wyjscia, nie poczatek.
	if len(linie) > 3 {
		linie = linie[len(linie)-3:]
	}
	return zlacz(linie)
}

// uzyteczneLinie odsiewa paski postepu i puste linie.
func uzyteczneLinie(tekst string) []string {
	var wynik []string
	for _, linia := range strings.Split(tekst, "\n") {
		linia = strings.TrimSpace(linia)
		if linia == "" || liniaPostepu(linia) {
			continue
		}
		wynik = append(wynik, linia)
	}
	return wynik
}

// liniaPostepu rozpoznaje pasek postepu. Dnf sklada go z procentow i kolumn
// oddzielonych pionowa kreska; apt uzywa nawiasow z procentami.
func liniaPostepu(linia string) bool {
	if strings.Contains(linia, "%") && strings.Contains(linia, "|") {
		return true
	}
	// Linie w rodzaju "Progress: [ 12%]" oraz "(Reading database ... 45%".
	obciete := strings.TrimLeft(linia, "([ ")
	return strings.HasPrefix(obciete, "Progress") || strings.HasPrefix(obciete, "Reading database")
}

func maZnacznikBledu(linia string) bool {
	male := strings.ToLower(linia)
	for _, znacznik := range znacznikiBledu {
		if strings.Contains(male, znacznik) {
			return true
		}
	}
	return false
}

// zlacz sklada linie w jedno zdanie i przycina do limitu.
func zlacz(linie []string) string {
	tekst := strings.Join(linie, " / ")
	if len(tekst) > maksymalnaDlugoscPowodu {
		// Przyciecie jest widoczne: urwany komunikat bez znaku moglby wygladac
		// na pelna tresc bledu.
		return tekst[:maksymalnaDlugoscPowodu] + "…"
	}
	return tekst
}

// objawyUszkodzonegoPobrania rozpoznaja awarie, ktore maja dokladnie jedna
// poprawna odpowiedz: pobrany plik jest uszkodzony i trzeba go pobrac jeszcze
// raz. Taka awaria nie jest decyzja operatora i nie ma powodu, zeby czekala
// na czlowieka.
var objawyUszkodzonegoPobrania = []string{
	"cannot be verified",
	"failed to verify",
	"checksum",
	"digest mismatch",
	"hash sum mismatch",
	"corrupted",
	"is corrupt",
	"unexpected end of file",
	"is not the expected size",
	"package does not match intended download",
}

// UszkodzonePobranie mowi, czy transakcja padla przez uszkodzony plik
// w pamieci podrecznej.
//
// Granica jest tu swiadoma. Sam naprawiamy wylacznie to, co ma jedna
// poprawna odpowiedz. Pytanie konfiguracyjne pakietu - na ktory dysk
// zainstalowac bootloader, czy podmienic plik konfiguracyjny - jest decyzja
// operatora i panel nie moze jej podjac za niego, choc technicznie moglby.
func UszkodzonePobranie(stderr, stdout string) bool {
	tekst := strings.ToLower(stderr + "\n" + stdout)
	for _, objaw := range objawyUszkodzonegoPobrania {
		if strings.Contains(tekst, objaw) {
			return true
		}
	}
	return false
}
