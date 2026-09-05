// Package version porownuje wersje pakietow regulami ich wlasnych menedzerow.
//
// To jest miejsce, w ktorym najlatwiej o cichy blad o powaznych skutkach.
// Wersje pakietow nie sa SemVerem i nie da sie ich porownac leksykalnie:
// "1.10" jest nowsze od "1.9", "1.0~rc1" starsze od "1.0", a epoka "1:2.0"
// bije wszystko bez epoki. Zla odpowiedz w te strone oznacza podatnosc uznana
// za naprawiona - czyli host, o ktorym panel mowi, ze jest bezpieczny.
package version

import (
	"strconv"
	"strings"
)

// PorownajDeb porownuje wersje wedlug reguly Debiana (deb-version(7)).
//
// Zwraca liczbe ujemna, zero albo dodatnia - tak jak dpkg --compare-versions.
func PorownajDeb(a, b string) int {
	epokaA, upstreamA, rewizjaA := rozbijDeb(a)
	epokaB, upstreamB, rewizjaB := rozbijDeb(b)

	if wynik := porownajLiczby(epokaA, epokaB); wynik != 0 {
		return wynik
	}
	if wynik := porownajCzescDeb(upstreamA, upstreamB); wynik != 0 {
		return wynik
	}
	return porownajCzescDeb(rewizjaA, rewizjaB)
}

// rozbijDeb dzieli wersje na epoke, czesc upstream i rewizje Debiana.
func rozbijDeb(wersja string) (epoka int, upstream, rewizja string) {
	wersja = strings.TrimSpace(wersja)
	if dwukropek := strings.Index(wersja, ":"); dwukropek >= 0 {
		// Epoka nieczytelna jest traktowana jak zero: taki zapis nie
		// pochodzi z dpkg i nie ma prawa wygrac porownania.
		epoka, _ = strconv.Atoi(wersja[:dwukropek])
		wersja = wersja[dwukropek+1:]
	}
	if myslnik := strings.LastIndex(wersja, "-"); myslnik >= 0 {
		return epoka, wersja[:myslnik], wersja[myslnik+1:]
	}
	return epoka, wersja, ""
}

func porownajLiczby(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// porownajCzescDeb porownuje jeden czlon wersji Debiana.
//
// Algorytm jest dokladnie ten z dpkg: naprzemiennie porownujemy fragmenty
// nieliczbowe wedlug wlasnego porzadku znakow i fragmenty liczbowe jako
// liczby. Tylda jest mniejsza od wszystkiego, takze od konca napisu - dlatego
// "1.0~rc1" jest starsze niz "1.0".
func porownajCzescDeb(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		// Fragment nieliczbowy.
		for (i < len(a) && !cyfra(a[i])) || (j < len(b) && !cyfra(b[j])) {
			znakA, znakB := 0, 0
			if i < len(a) {
				znakA = porzadekDeb(a[i])
			}
			if j < len(b) {
				znakB = porzadekDeb(b[j])
			}
			if znakA != znakB {
				return porownajLiczby(znakA, znakB)
			}
			i++
			j++
		}
		// Wiodace zera nie zmieniaja wartosci liczby.
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		poczatekA, poczatekB := i, j
		for i < len(a) && cyfra(a[i]) {
			i++
		}
		for j < len(b) && cyfra(b[j]) {
			j++
		}
		liczbaA, liczbaB := a[poczatekA:i], b[poczatekB:j]
		if len(liczbaA) != len(liczbaB) {
			return porownajLiczby(len(liczbaA), len(liczbaB))
		}
		if wynik := strings.Compare(liczbaA, liczbaB); wynik != 0 {
			return wynik
		}
	}
	return 0
}

func cyfra(znak byte) bool { return znak >= '0' && znak <= '9' }

// porzadekDeb nadaje znakom porzadek uzywany przez dpkg.
//
// Tylda jest mniejsza od pustego miejsca, litery ida przed reszta znakow,
// a wszystko inne po nich - wedlug kodu ASCII przesunietego tak, zeby nie
// wpasc miedzy litery.
func porzadekDeb(znak byte) int {
	switch {
	case znak == '~':
		return -1
	case cyfra(znak):
		return 0
	case (znak >= 'a' && znak <= 'z') || (znak >= 'A' && znak <= 'Z'):
		return int(znak)
	default:
		return int(znak) + 256
	}
}
