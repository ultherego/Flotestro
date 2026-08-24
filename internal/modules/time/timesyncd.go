package czas

import (
	"strconv"
	"strings"
)

// StanTimesyncd to stan demona systemd-timesyncd.
//
// timesyncd nie podaje przesuniecia zegara: mowi, z kim rozmawial i co dostal
// w odpowiedzi, ale nie liczy tego, o ile spoznia sie host. Dlatego pole
// przesuniecia zostaje puste, a panel mierzy je wlasnym zapytaniem - to jest
// cala roznica miedzy "demon dziala" a "zegar jest dobry".
type StanTimesyncd struct {
	ServerName    string
	ServerAddress string
	Servers       []Serwer
	Stratum       *uint32
	RootDelay     *float64
	RootDispersio *float64
	LeapStatus    string
	FrequencyPPM  *float64
}

// ParsujTimedatectl czyta wyjscie "timedatectl show".
//
// Czasu hosta stad nie bierzemy: agent stoi na tym samym hoscie, wiec jego
// wlasny zegar jest tym samym zegarem, a "TimeUSec" jest tekstem dla czlowieka
// i zmienia postac ze strefa oraz jezykiem.
func ParsujTimedatectl(wyjscie string) Snapshot {
	snapshot := Snapshot{}
	for _, linia := range strings.Split(wyjscie, "\n") {
		klucz, wartosc, ok := strings.Cut(strings.TrimSpace(linia), "=")
		if !ok {
			continue
		}
		wartosc = strings.TrimSpace(wartosc)
		switch klucz {
		case "Timezone":
			snapshot.Timezone = wartosc
		case "LocalRTC":
			snapshot.RTCInLocalTime = tak(wartosc)
		case "NTP":
			snapshot.NTPEnabled = tak(wartosc)
		case "NTPSynchronized":
			snapshot.Synchronized = tak(wartosc)
		}
	}
	return snapshot
}

// ParsujTimesync czyta wyjscie "timedatectl show-timesync --all".
func ParsujTimesync(wyjscie, zrodlo string) StanTimesyncd {
	stan := StanTimesyncd{}
	for _, linia := range strings.Split(wyjscie, "\n") {
		klucz, wartosc, ok := strings.Cut(strings.TrimSpace(linia), "=")
		if !ok {
			continue
		}
		wartosc = strings.TrimSpace(wartosc)
		switch klucz {
		case "ServerName":
			stan.ServerName = wartosc
		case "ServerAddress":
			stan.ServerAddress = wartosc
		case "SystemNTPServers", "LinkNTPServers", "RuntimeNTPServers", "FallbackNTPServers":
			// Zrodlo wpisu jest tu odpowiedzia na pytanie "skad on sie wzial":
			// serwer z lacza pochodzi z DHCP, zapasowy - z kompilacji systemd.
			pochodzenie := zrodlo
			switch klucz {
			case "LinkNTPServers":
				pochodzenie = "DHCP"
			case "RuntimeNTPServers":
				pochodzenie = "runtime"
			case "FallbackNTPServers":
				pochodzenie = "systemd fallback"
			}
			for _, adres := range strings.Fields(wartosc) {
				stan.Servers = append(stan.Servers, Serwer{Address: adres, Source: pochodzenie})
			}
		case "Frequency":
			// Systemd podaje czestotliwosc w jednostkach 2^-16 ppm.
			if surowa, err := strconv.ParseFloat(wartosc, 64); err == nil {
				ppm := surowa / 65536
				stan.FrequencyPPM = &ppm
			}
		case "NTPMessage":
			czytajKomunikatNTP(wartosc, &stan)
		}
	}
	return stan
}

// czytajKomunikatNTP rozbiera pole NTPMessage={ Leap=0, Stratum=2, ... }.
func czytajKomunikatNTP(wartosc string, stan *StanTimesyncd) {
	wartosc = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(wartosc), "{"), "}"))
	for _, pole := range strings.Split(wartosc, ",") {
		klucz, dane, ok := strings.Cut(strings.TrimSpace(pole), "=")
		if !ok {
			continue
		}
		dane = strings.TrimSpace(dane)
		switch klucz {
		case "Leap":
			stan.LeapStatus = stanSekundyPrzestepnej(dane)
		case "Stratum":
			if stratum, err := strconv.ParseUint(dane, 10, 32); err == nil && stratum > 0 {
				liczba := uint32(stratum)
				stan.Stratum = &liczba
			}
		case "RootDelay":
			stan.RootDelay = trwanie(dane)
		case "RootDispersion":
			stan.RootDispersio = trwanie(dane)
		}
	}
}

// stanSekundyPrzestepnej tlumaczy pole Leap na slowo.
func stanSekundyPrzestepnej(wartosc string) string {
	switch wartosc {
	case "0":
		return "Normal"
	case "1":
		return "Insert second"
	case "2":
		return "Delete second"
	case "3":
		return "Not synchronised"
	}
	return wartosc
}

// trwanie czyta czas w postaci, w ktorej pisze go systemd: "1.907ms",
// "5s", "1min 4s". Wartosc nieczytelna zostaje pustym wskaznikiem.
func trwanie(wartosc string) *float64 {
	wartosc = strings.TrimSpace(wartosc)
	if wartosc == "" {
		return nil
	}
	suma := 0.0
	rozpoznane := false
	for _, czlon := range strings.Fields(wartosc) {
		liczba, jednostka := rozdzielJednostke(czlon)
		if jednostka == "" {
			continue
		}
		wspolczynnik, ok := jednostki[jednostka]
		if !ok {
			continue
		}
		suma += liczba * wspolczynnik
		rozpoznane = true
	}
	if !rozpoznane {
		return nil
	}
	return &suma
}

var jednostki = map[string]float64{
	"us": 1e-6, "µs": 1e-6, "ms": 1e-3, "s": 1, "min": 60, "h": 3600,
}

func rozdzielJednostke(czlon string) (float64, string) {
	granica := 0
	for granica < len(czlon) {
		znak := czlon[granica]
		if (znak >= '0' && znak <= '9') || znak == '.' || znak == '-' || znak == '+' {
			granica++
			continue
		}
		break
	}
	liczba, err := strconv.ParseFloat(czlon[:granica], 64)
	if err != nil {
		return 0, ""
	}
	return liczba, strings.TrimSpace(czlon[granica:])
}

// tak zamienia odpowiedz narzedzia na wartosc logiczna. Odpowiedz, ktorej nie
// rozumiemy, zostaje pustym wskaznikiem, a nie falszem.
func tak(wartosc string) *bool {
	switch strings.ToLower(wartosc) {
	case "yes", "true", "1", "on":
		prawda := true
		return &prawda
	case "no", "false", "0", "off":
		falsz := false
		return &falsz
	}
	return nil
}
