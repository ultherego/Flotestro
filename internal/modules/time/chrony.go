package czas

import (
	"strconv"
	"strings"
	"time"
)

// trybyZrodla i staneZrodla tlumacza znaki chronyego na slowa.
//
// Operator nie ma pamietac, ze "^*" znaczy "wybrany serwer", a "x" - "zrodlo,
// ktore klamie". Znak zostaje w wyniku tylko wtedy, gdy nie znamy jego
// znaczenia: nieznany stan nie jest tu stanem pustym.
var trybyZrodla = map[string]string{
	"^": "server",
	"=": "peer",
	"#": "local clock",
}

var stanyZrodla = map[string]string{
	"*": "selected",
	"+": "candidate",
	"-": "not combined",
	"?": "unreachable",
	"x": "false ticker",
	"~": "too variable",
}

// ParsujTracking czyta wyjscie "chronyc -c tracking".
//
// Tryb CSV jest tu wyborem swiadomym: zwykle wyjscie chronyego jest tabelka
// dla czlowieka, a jej naglowki i jednostki zmieniaja sie miedzy wersjami.
// Kolejnosc pol w CSV jest czescia kontraktu narzedzia.
func ParsujTracking(wyjscie string) Snapshot {
	snapshot := Snapshot{Service: DemonChrony}
	linia := strings.TrimSpace(wyjscie)
	if linia == "" {
		return snapshot
	}
	pola := strings.Split(strings.Split(linia, "\n")[0], ",")
	if len(pola) < 14 {
		return snapshot
	}

	// Referencja "0.0.0.0" albo pusty identyfikator oznaczaja demona, ktory
	// jeszcze nie wybral zrodla. To nie jest zrodlo o nazwie zerowej.
	nazwa := strings.TrimSpace(pola[1])
	if nazwa != "" && nazwa != "0.0.0.0" && pola[0] != "00000000" {
		snapshot.ReferenceName = nazwa
	}
	if stratum, err := strconv.ParseUint(strings.TrimSpace(pola[2]), 10, 32); err == nil && stratum > 0 {
		wartosc := uint32(stratum)
		snapshot.Stratum = &wartosc
	}
	if sekundy, err := strconv.ParseFloat(strings.TrimSpace(pola[3]), 64); err == nil && sekundy > 0 {
		chwila := time.Unix(int64(sekundy), 0).UTC()
		snapshot.LastSyncAt = &chwila
	}
	snapshot.OffsetSeconds = liczba(pola[4])
	snapshot.FrequencyPPM = liczba(pola[7])
	snapshot.RootDelaySeconds = liczba(pola[10])
	snapshot.RootDispersionSeconds = liczba(pola[11])
	snapshot.LeapStatus = strings.TrimSpace(pola[13])

	// Demon bez wybranego zrodla nie jest zsynchronizowany, choc dziala.
	zsynchronizowany := snapshot.ReferenceName != "" && snapshot.Stratum != nil
	snapshot.Synchronized = &zsynchronizowany
	return snapshot
}

// ParsujZrodla czyta wyjscie "chronyc -c sources".
func ParsujZrodla(wyjscie string) []Zrodlo {
	var zrodla []Zrodlo
	for _, linia := range strings.Split(wyjscie, "\n") {
		linia = strings.TrimSpace(linia)
		if linia == "" {
			continue
		}
		pola := strings.Split(linia, ",")
		if len(pola) < 10 {
			continue
		}
		zrodlo := Zrodlo{
			Address:      strings.TrimSpace(pola[2]),
			Mode:         nazwaLubZnak(trybyZrodla, pola[0]),
			State:        nazwaLubZnak(stanyZrodla, pola[1]),
			Reachability: strings.TrimSpace(pola[5]),
		}
		if zrodlo.Address == "" {
			continue
		}
		if stratum, err := strconv.ParseUint(strings.TrimSpace(pola[3]), 10, 32); err == nil {
			wartosc := uint32(stratum)
			zrodlo.Stratum = &wartosc
		}
		// Chrony podaje odstep odpytywania jako logarytm dwojkowy sekund.
		if poll, err := strconv.Atoi(strings.TrimSpace(pola[4])); err == nil && poll >= 0 && poll < 24 {
			sekundy := 1 << uint(poll)
			zrodlo.PollSeconds = &sekundy
		}
		if ostatnie, err := strconv.ParseInt(strings.TrimSpace(pola[6]), 10, 64); err == nil {
			zrodlo.LastRxSeconds = &ostatnie
		}
		zrodlo.OffsetSeconds = liczba(pola[7])
		zrodlo.ErrorSeconds = liczba(pola[9])
		zrodla = append(zrodla, zrodlo)
	}
	return zrodla
}

// KatalogDropIn wskazuje katalog, do ktorego panel dopisze serwery.
//
// Panel nie przepisuje glownego pliku chronyego: sa w nim decyzje o platformie
// (klucze, dostep, sterowniki zegarow), ktorych zmiana nie nalezy do operacji
// "ustaw serwery czasu". Zamiast tego czytamy, ktory katalog demon sam wlacza,
// i piszemy tylko tam. Host bez takiego katalogu dostaje odmowe z powodem,
// a nie plik, ktorego chrony nigdy nie przeczyta.
func KatalogDropIn(konfiguracja string) (katalog, rodzaj string) {
	for _, linia := range strings.Split(konfiguracja, "\n") {
		linia = strings.TrimSpace(linia)
		if linia == "" || strings.HasPrefix(linia, "#") || strings.HasPrefix(linia, "!") ||
			strings.HasPrefix(linia, ";") || strings.HasPrefix(linia, "%") {
			continue
		}
		dyrektywa, reszta, ok := strings.Cut(linia, " ")
		if !ok {
			continue
		}
		sciezka := strings.TrimSpace(reszta)
		switch strings.ToLower(dyrektywa) {
		case "confdir":
			// Dyrektywa przyjmuje kilka katalogow rozdzielonych spacja;
			// piszemy do pierwszego, bo to on ma pierwszenstwo.
			if pierwszy := pierwszaSciezka(sciezka); pierwszy != "" {
				return pierwszy, RodzajKonfiguracji
			}
		case "sourcedir":
			if pierwszy := pierwszaSciezka(sciezka); pierwszy != "" && !strings.HasPrefix(pierwszy, "/run") {
				// Katalog w /run znika po restarcie - to miejsce na zrodla
				// z DHCP, a nie na stan docelowy panelu.
				return pierwszy, RodzajZrodel
			}
		case "include":
			// Wzorzec "include /etc/chrony.d/*.conf" wskazuje katalog
			// konfiguracji tak samo jak confdir, tylko starsza skladnia.
			if katalog := katalogZeWzorca(pierwszaSciezka(sciezka)); katalog != "" {
				return katalog, RodzajKonfiguracji
			}
		}
	}
	return "", ""
}

// ParsujSerwery czyta serwery czasu z pliku konfiguracyjnego chronyego.
func ParsujSerwery(tresc, zrodlo string, zarzadzany bool) []Serwer {
	var serwery []Serwer
	for _, linia := range strings.Split(tresc, "\n") {
		linia = strings.TrimSpace(linia)
		if linia == "" || strings.HasPrefix(linia, "#") || strings.HasPrefix(linia, ";") {
			continue
		}
		dyrektywa, reszta, ok := strings.Cut(linia, " ")
		if !ok {
			continue
		}
		dyrektywa = strings.ToLower(dyrektywa)
		if dyrektywa != "server" && dyrektywa != "pool" && dyrektywa != "peer" {
			continue
		}
		pola := strings.Fields(reszta)
		if len(pola) == 0 {
			continue
		}
		serwery = append(serwery, Serwer{
			Address: pola[0],
			Source:  zrodlo,
			Pool:    dyrektywa == "pool",
			Managed: zarzadzany,
		})
	}
	return serwery
}

// ParsujNTPZTimesyncd czyta liste serwerow z pliku timesyncd.
func ParsujNTPZTimesyncd(tresc, zrodlo string, zarzadzany bool) []Serwer {
	var serwery []Serwer
	for _, linia := range strings.Split(tresc, "\n") {
		linia = strings.TrimSpace(linia)
		if linia == "" || strings.HasPrefix(linia, "#") || strings.HasPrefix(linia, ";") {
			continue
		}
		klucz, wartosc, ok := strings.Cut(linia, "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(klucz), "NTP") {
			continue
		}
		for _, adres := range strings.Fields(wartosc) {
			serwery = append(serwery, Serwer{Address: adres, Source: zrodlo, Managed: zarzadzany})
		}
	}
	return serwery
}

func pierwszaSciezka(wartosc string) string {
	pola := strings.Fields(wartosc)
	if len(pola) == 0 {
		return ""
	}
	return pola[0]
}

// katalogZeWzorca zamienia "/etc/chrony.d/*.conf" na katalog.
func katalogZeWzorca(wzorzec string) string {
	if !strings.Contains(wzorzec, "*") {
		return ""
	}
	katalog := wzorzec[:strings.LastIndex(wzorzec, "/")+1]
	return strings.TrimSuffix(katalog, "/")
}

func nazwaLubZnak(slownik map[string]string, pole string) string {
	znak := strings.TrimSpace(pole)
	if nazwa, ok := slownik[znak]; ok {
		return nazwa
	}
	return znak
}

// liczba czyta pole zmiennoprzecinkowe. Pole nieczytelne zostaje pustym
// wskaznikiem: brak pomiaru nie jest pomiarem rownym zeru.
func liczba(pole string) *float64 {
	wartosc, err := strconv.ParseFloat(strings.TrimSpace(pole), 64)
	if err != nil {
		return nil
	}
	return &wartosc
}
