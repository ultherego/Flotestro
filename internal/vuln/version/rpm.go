package version

import (
	"strings"
)

// PorownajRPM porownuje pelne wersje RPM w postaci EVR (epoka:wersja-wydanie).
//
// Zwraca liczbe ujemna, zero albo dodatnia - tak jak rpmvercmp z librpm.
func PorownajRPM(a, b string) int {
	epokaA, wersjaA, wydanieA := rozbijEVR(a)
	epokaB, wersjaB, wydanieB := rozbijEVR(b)

	if wynik := PorownajOdcinekRPM(epokaA, epokaB); wynik != 0 {
		return wynik
	}
	if wynik := PorownajOdcinekRPM(wersjaA, wersjaB); wynik != 0 {
		return wynik
	}
	// Wydanie porownujemy tylko wtedy, gdy obie strony je maja: advisory
	// czesto podaje sama wersje, a wtedy "2.4.6" i "2.4.6-1" znacza to samo
	// pytanie, a nie dwie rozne wersje.
	if wydanieA == "" || wydanieB == "" {
		return 0
	}
	return PorownajOdcinekRPM(wydanieA, wydanieB)
}

// rozbijEVR dzieli wersje RPM na epoke, wersje i wydanie.
func rozbijEVR(evr string) (epoka, wersja, wydanie string) {
	evr = strings.TrimSpace(evr)
	epoka = "0"
	if dwukropek := strings.Index(evr, ":"); dwukropek >= 0 {
		epoka = evr[:dwukropek]
		if strings.TrimSpace(epoka) == "" {
			epoka = "0"
		}
		evr = evr[dwukropek+1:]
	}
	if myslnik := strings.Index(evr, "-"); myslnik >= 0 {
		return epoka, evr[:myslnik], evr[myslnik+1:]
	}
	return epoka, evr, ""
}

// PorownajOdcinekRPM realizuje rpmvercmp dla jednego odcinka wersji.
//
// Algorytm librpm: napisy dzielimy na ciagi cyfr, ciagi liter i reszte;
// separatory sa pomijane, ciag cyfr jest zawsze nowszy od ciagu liter,
// a tylda jest mniejsza od wszystkiego. Znak "^" oznacza wersje posrednia
// i jest wiekszy od konca napisu, ale mniejszy od kazdego innego znaku.
func PorownajOdcinekRPM(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		// Separatory pomijamy po obu stronach.
		for i < len(a) && !alfanumeryczny(a[i]) && a[i] != '~' && a[i] != '^' {
			i++
		}
		for j < len(b) && !alfanumeryczny(b[j]) && b[j] != '~' && b[j] != '^' {
			j++
		}

		// Tylda: mniejsza od wszystkiego, takze od konca napisu.
		if (i < len(a) && a[i] == '~') || (j < len(b) && b[j] == '~') {
			switch {
			case i >= len(a) || a[i] != '~':
				return 1
			case j >= len(b) || b[j] != '~':
				return -1
			}
			i++
			j++
			continue
		}
		// Daszek: wiekszy od konca napisu, mniejszy od kazdego innego znaku.
		if (i < len(a) && a[i] == '^') || (j < len(b) && b[j] == '^') {
			switch {
			case i >= len(a):
				return -1
			case j >= len(b):
				return 1
			case a[i] != '^':
				return 1
			case b[j] != '^':
				return -1
			}
			i++
			j++
			continue
		}

		if i >= len(a) || j >= len(b) {
			break
		}

		poczatekA, poczatekB := i, j
		liczbowy := cyfra(a[i])
		if liczbowy {
			for i < len(a) && cyfra(a[i]) {
				i++
			}
			for j < len(b) && cyfra(b[j]) {
				j++
			}
		} else {
			for i < len(a) && litera(a[i]) {
				i++
			}
			for j < len(b) && litera(b[j]) {
				j++
			}
		}
		odcinekA, odcinekB := a[poczatekA:i], b[poczatekB:j]
		if odcinekB == "" {
			// Ciag cyfr jest zawsze nowszy od ciagu liter.
			if liczbowy {
				return 1
			}
			return -1
		}
		if liczbowy {
			odcinekA = strings.TrimLeft(odcinekA, "0")
			odcinekB = strings.TrimLeft(odcinekB, "0")
			if len(odcinekA) != len(odcinekB) {
				if len(odcinekA) > len(odcinekB) {
					return 1
				}
				return -1
			}
		}
		if wynik := strings.Compare(odcinekA, odcinekB); wynik != 0 {
			if wynik > 0 {
				return 1
			}
			return -1
		}
	}

	switch {
	case i >= len(a) && j >= len(b):
		return 0
	case i >= len(a):
		return -1
	default:
		return 1
	}
}

func litera(znak byte) bool {
	return (znak >= 'a' && znak <= 'z') || (znak >= 'A' && znak <= 'Z')
}

func alfanumeryczny(znak byte) bool { return cyfra(znak) || litera(znak) }
