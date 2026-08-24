package czas

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"math"
	"net"
	"time"
)

// Pytanie SNTP jest tu wlasnym kodem, a nie wywolaniem narzedzia, z trzech
// powodow. Po pierwsze nie wymaga roota i nie zmienia niczego na hoscie, wiec
// test serwera moze isc bez helpera. Po drugie zaden host nie ma na pewno
// ntpdate ani sntp, a chronyd -Q dziala tylko tam, gdzie jest chrony. Po
// trzecie mierzymy dokladnie to, o co pyta operator: czy ten serwer odpowiada
// i o ile rozni sie od niego zegar hosta.
const (
	portNTP = "123"
	// erpokaNTP to roznica miedzy epoka NTP (1900) a epoka uniksowa (1970).
	epokaNTP = 2208988800
	// ulamekSekundy skaluje 32-bitowa czesc ulamkowa znacznika.
	ulamekSekundy = 1 << 32
)

// Zapytaj zadaje jedno pytanie SNTP i opisuje odpowiedz.
//
// Wynik nigdy nie klamie o tym, czego nie zmierzyl: serwer nieosiagalny ma
// puste przesuniecie, a nie przesuniecie zerowe.
func Zapytaj(ctx context.Context, serwer string, timeout time.Duration) Pomiar {
	pomiar := Pomiar{Server: serwer}
	if err := WalidujSerwer(serwer); err != nil {
		pomiar.Error = err.Error()
		return pomiar
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	dialer := net.Dialer{Timeout: timeout}
	polaczenie, err := dialer.DialContext(ctx, "udp", net.JoinHostPort(serwer, portNTP))
	if err != nil {
		pomiar.Error = err.Error()
		return pomiar
	}
	defer func() { _ = polaczenie.Close() }()
	if adres, ok := polaczenie.RemoteAddr().(*net.UDPAddr); ok {
		pomiar.Address = adres.IP.String()
	}
	if err := polaczenie.SetDeadline(time.Now().Add(timeout)); err != nil {
		pomiar.Error = err.Error()
		return pomiar
	}

	zapytanie := make([]byte, 48)
	// LI = 0, wersja 4, tryb 3 (klient).
	zapytanie[0] = 0x23
	// Znacznik nadania jest losowy, a nie zegarowy: odpowiedz odsyla go
	// nietkniety, wiec tylko my potrafimy rozpoznac wlasne pytanie. Zegar
	// hosta zostaje po naszej stronie, gdzie i tak jest dokladniejszy.
	nadanie := make([]byte, 8)
	if _, err := rand.Read(nadanie); err != nil {
		pomiar.Error = err.Error()
		return pomiar
	}
	copy(zapytanie[40:48], nadanie)

	t1 := time.Now()
	if _, err := polaczenie.Write(zapytanie); err != nil {
		pomiar.Error = err.Error()
		return pomiar
	}
	odpowiedz := make([]byte, 48)
	n, err := polaczenie.Read(odpowiedz)
	t4 := time.Now()
	if err != nil {
		pomiar.Error = "serwer nie odpowiedzial: " + err.Error()
		return pomiar
	}
	if n < 48 {
		pomiar.Error = "odpowiedz krotsza niz pakiet NTP"
		return pomiar
	}
	// Odpowiedz musi odeslac nasz znacznik nadania. Bez tego sprawdzenia
	// wystarczylby pakiet z boku, zeby panel uwierzyl w cudzy czas.
	for i := 0; i < 8; i++ {
		if odpowiedz[24+i] != nadanie[i] {
			pomiar.Error = "odpowiedz nie pasuje do pytania"
			return pomiar
		}
	}
	if tryb := odpowiedz[0] & 0x07; tryb != 4 {
		pomiar.Error = "odpowiedz nie jest odpowiedzia serwera"
		return pomiar
	}
	stratum := uint32(odpowiedz[1])
	if stratum == 0 {
		// Stratum 0 niesie komunikat odmowy ("kiss of death") w polu
		// referencji: serwer odpowiedzial, ale kaze przestac pytac.
		pomiar.Error = "serwer odmowil obslugi: " + string(odpowiedz[12:16])
		return pomiar
	}
	if stratum > 15 {
		pomiar.Error = "serwer zglasza sie jako niezsynchronizowany"
		return pomiar
	}

	t2 := znacznik(odpowiedz[32:40])
	t3 := znacznik(odpowiedz[40:48])
	przesuniecie := (t2.Sub(t1).Seconds() + t3.Sub(t4).Seconds()) / 2
	opoznienie := t4.Sub(t1).Seconds() - t3.Sub(t2).Seconds()
	if opoznienie < 0 {
		opoznienie = 0
	}

	pomiar.Reachable = true
	pomiar.Stratum = &stratum
	pomiar.OffsetSeconds = &przesuniecie
	pomiar.DelaySeconds = &opoznienie
	pomiar.LeapStatus = stanSekundyPrzestepnej(string(rune('0' + (odpowiedz[0] >> 6))))
	return pomiar
}

// ZapytajWiele odpytuje kolejno wskazane serwery.
func ZapytajWiele(ctx context.Context, serwery []string, timeout time.Duration) []Pomiar {
	pomiary := make([]Pomiar, 0, len(serwery))
	for _, serwer := range serwery {
		pomiary = append(pomiary, Zapytaj(ctx, serwer, timeout))
	}
	return pomiary
}

// Osiagalne liczy serwery, ktore odpowiedzialy.
func Osiagalne(pomiary []Pomiar) int {
	liczba := 0
	for _, pomiar := range pomiary {
		if pomiar.Reachable {
			liczba++
		}
	}
	return liczba
}

// NajlepszyPomiar wybiera odpowiedz o najkrotszej drodze.
//
// Przesuniecie zmierzone przez wolne lacze jest mniej wiarygodne niz to samo
// przesuniecie zmierzone przez szybkie, wiec skok czasu oceniamy po pomiarze
// o najmniejszym opoznieniu, a nie po pierwszym z brzegu.
func NajlepszyPomiar(pomiary []Pomiar) *Pomiar {
	var najlepszy *Pomiar
	for i := range pomiary {
		if !pomiary[i].Reachable || pomiary[i].OffsetSeconds == nil {
			continue
		}
		if najlepszy == nil || mniejszeOpoznienie(pomiary[i], *najlepszy) {
			najlepszy = &pomiary[i]
		}
	}
	return najlepszy
}

func mniejszeOpoznienie(kandydat, obecny Pomiar) bool {
	if kandydat.DelaySeconds == nil {
		return false
	}
	if obecny.DelaySeconds == nil {
		return true
	}
	return *kandydat.DelaySeconds < *obecny.DelaySeconds
}

// Skok mowi, czy zmierzone przesuniecie przestawi zegar skokiem.
func Skok(pomiar *Pomiar) bool {
	return pomiar != nil && pomiar.OffsetSeconds != nil &&
		math.Abs(*pomiar.OffsetSeconds) >= ProgSkokuSekund
}

// znacznik zamienia 64-bitowy znacznik NTP na czas.
//
// Licznik sekund przepelni sie w 2036 roku i wtedy trzeba bedzie rozroznic
// ery; do tego czasu odejmowanie epoki wystarcza i nie udajemy, ze robimy
// wiecej.
func znacznik(pole []byte) time.Time {
	sekundy := binary.BigEndian.Uint32(pole[0:4])
	ulamek := binary.BigEndian.Uint32(pole[4:8])
	nanosekundy := int64(float64(ulamek) / ulamekSekundy * 1e9)
	return time.Unix(int64(sekundy)-epokaNTP, nanosekundy)
}
