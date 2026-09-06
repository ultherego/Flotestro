// Package endpoints wybiera brame, z ktora agent probuje sie polaczyc.
//
// Agent utrzymuje jedna aktywna sesje, ale zna uporzadkowana liste bram.
// Wybor nie jest samym "wez nastepna z listy": rodzaj bledu rozstrzyga, czy
// w ogole warto probowac dalej. Zerwane TCP znaczy "sprobuj gdzie indziej
// za chwile"; nieznane CA znaczy "ta brama jest zle skonfigurowana i szybkie
// przelaczanie w kolko niczego nie naprawi"; odwolany certyfikat znaczy
// "przestan probowac, bo problem nie jest po stronie sieci".
//
// Backoff ma pelny jitter, bo dziesiec tysiecy agentow nie moze wrocic
// w tej samej sekundzie po awarii centrali - to ta sekunda przewraca ja
// ponownie.
package endpoints

import (
	"crypto/rand"
	"errors"
	"math/big"
	"strings"
	"time"
)

// Klasa opisuje rodzaj niepowodzenia polaczenia.
type Klasa string

const (
	// KlasaSieci to zerwane albo odrzucone polaczenie. Zwykla awaria: warto
	// sprobowac nastepnej bramy zaraz.
	KlasaSieci Klasa = "network"
	// KlasaKonfiguracji to nieznane CA albo nazwa, ktorej certyfikat nie
	// poswiadcza. Szybkie przelaczanie niczego nie naprawi, bo problem jest
	// w konfiguracji, a nie w laczu.
	KlasaKonfiguracji Klasa = "configuration_error"
	// KlasaTozsamosci to certyfikat nieznany albo odwolany. Agent ma
	// przestac probowac: kolejne proby nie sa awaria lacza, tylko dobijaniem
	// sie tozsamoscia, ktora zostala cofnieta.
	KlasaTozsamosci Klasa = "identity_rejected"
)

// ErrTozsamoscOdrzucona konczy prace menedzera: zadna brama nie wpusci
// certyfikatu, ktory panel odwolal.
var ErrTozsamoscOdrzucona = errors.New("tozsamosc agenta odrzucona przez centrale")

// Domyslne granice backoffu.
const (
	MinBackoff = 2 * time.Second
	MaxBackoff = 5 * time.Minute
	// BackoffKonfiguracji jest dluzszy: blad konfiguracji naprawia czlowiek,
	// a nie ponowienie. Krotki backoff zamienilby to w petle w dzienniku.
	BackoffKonfiguracji = 15 * time.Minute
)

// Stan opisuje jedna brame.
type Stan struct {
	URL           string
	Bledy         int
	Klasa         Klasa
	NastepnaProba time.Time
	OstatniSukces time.Time
}

// Menedzer prowadzi wybor bramy.
type Menedzer struct {
	bramy      []*Stan
	minBackoff time.Duration
	maxBackoff time.Duration
	// odrzucona zapamietuje, ze centrala odmowila tozsamosci. Stan globalny,
	// a nie per brama: tozsamosc jest jedna dla calej floty.
	odrzucona bool
}

// Nowy tworzy menedzera dla podanej listy bram w kolejnosci priorytetu.
func Nowy(adresy []string, minBackoff, maxBackoff time.Duration) *Menedzer {
	if minBackoff <= 0 {
		minBackoff = MinBackoff
	}
	if maxBackoff < minBackoff {
		maxBackoff = MaxBackoff
	}
	menedzer := &Menedzer{minBackoff: minBackoff, maxBackoff: maxBackoff}
	widziane := map[string]bool{}
	for _, adres := range adresy {
		if adres == "" || widziane[adres] {
			continue
		}
		widziane[adres] = true
		menedzer.bramy = append(menedzer.bramy, &Stan{URL: adres})
	}
	return menedzer
}

// Bramy zwraca stan wszystkich bram w kolejnosci priorytetu.
func (m *Menedzer) Bramy() []Stan {
	kopia := make([]Stan, 0, len(m.bramy))
	for _, brama := range m.bramy {
		kopia = append(kopia, *brama)
	}
	return kopia
}

// Wybierz zwraca pierwsza brame gotowa do proby.
//
// Kolejnosc listy jest priorytetem, a nie sugestia: agent wraca na brame
// pierwsza, gdy tylko jej okno ponowienia minie. Bez tego cala flota
// zostawalaby na bramie zapasowej dlugo po tym, jak glowna wrocila.
func (m *Menedzer) Wybierz(teraz time.Time) (*Stan, error) {
	if m.odrzucona {
		return nil, ErrTozsamoscOdrzucona
	}
	for _, brama := range m.bramy {
		if !teraz.Before(brama.NastepnaProba) {
			return brama, nil
		}
	}
	return nil, nil
}

// DoNastepnej mowi, ile czekac, zanim ktorakolwiek brama bedzie gotowa.
func (m *Menedzer) DoNastepnej(teraz time.Time) time.Duration {
	var najblizsza time.Duration
	for _, brama := range m.bramy {
		czekanie := brama.NastepnaProba.Sub(teraz)
		if czekanie <= 0 {
			return 0
		}
		if najblizsza == 0 || czekanie < najblizsza {
			najblizsza = czekanie
		}
	}
	if najblizsza == 0 {
		return m.minBackoff
	}
	return najblizsza
}

// Sukces kasuje historie bledow bramy.
//
// Liczy sie sesja, ktora naprawde pracowala. Polaczenie zerwane po sekundzie
// nie jest sukcesem, choc technicznie sie nawiazalo - dlatego wolajacy
// decyduje, kiedy to wywolac.
func (m *Menedzer) Sukces(url string, teraz time.Time) {
	for _, brama := range m.bramy {
		if brama.URL == url {
			brama.Bledy = 0
			brama.Klasa = ""
			brama.OstatniSukces = teraz
			brama.NastepnaProba = time.Time{}
			return
		}
	}
}

// Blad odnotowuje nieudana probe i wyznacza okno nastepnej.
func (m *Menedzer) Blad(url string, klasa Klasa, teraz time.Time) {
	if klasa == KlasaTozsamosci {
		// Odwolany certyfikat nie jest problemem tej bramy. Dalsze proby
		// nie przywroca dostepu i tylko zasypia dziennik centrali.
		m.odrzucona = true
	}
	for _, brama := range m.bramy {
		if brama.URL != url {
			continue
		}
		brama.Bledy++
		brama.Klasa = klasa
		brama.NastepnaProba = teraz.Add(m.okno(brama))
		return
	}
}

// okno wylicza czas do nastepnej proby danej bramy.
func (m *Menedzer) okno(brama *Stan) time.Duration {
	gora := m.maxBackoff
	if brama.Klasa == KlasaKonfiguracji {
		gora = BackoffKonfiguracji
	}
	// Podwajanie ograniczone wykladnikiem: 1<<n przy kilkudziesieciu bledach
	// przekreca licznik i daje ujemny czas.
	wykladnik := brama.Bledy
	if wykladnik > 10 {
		wykladnik = 10
	}
	okno := m.minBackoff * time.Duration(1<<wykladnik)
	if okno > gora || okno <= 0 {
		okno = gora
	}
	return pelnyJitter(okno)
}

// pelnyJitter zwraca losowy czas z przedzialu [0, gora).
//
// Pelny jitter, a nie polowa: chodzi o rozproszenie floty, a nie o skrocenie
// czekania. Polowiczny zostawia szczyt w tym samym miejscu, tylko nizszy.
func pelnyJitter(gora time.Duration) time.Duration {
	if gora <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(gora)))
	if err != nil {
		return gora / 2
	}
	return time.Duration(n.Int64())
}

// Rozpoznaj klasyfikuje blad polaczenia.
//
// Rozpoznanie idzie po tresci bledu, bo biblioteki TLS nie daja tu typow,
// ktore przezylyby opakowanie w connect i http2. Nierozpoznany blad jest
// bledem sieci: to zalozenie, ktore najwyzej kaze sprobowac ponownie,
// a nie takie, ktore zatrzymuje agenta na zawsze.
func Rozpoznaj(err error) Klasa {
	if err == nil {
		return KlasaSieci
	}
	tresc := strings.ToLower(err.Error())
	switch {
	case strings.Contains(tresc, "certyfikat odwolany"),
		strings.Contains(tresc, "certyfikat nieznany"),
		strings.Contains(tresc, "identity_rejected"),
		strings.Contains(tresc, "tls: certificate required"),
		strings.Contains(tresc, "bad certificate"),
		strings.Contains(tresc, "certificate revoked"):
		return KlasaTozsamosci
	case strings.Contains(tresc, "unknown authority"),
		strings.Contains(tresc, "certificate signed by unknown"),
		strings.Contains(tresc, "not valid for any names"),
		strings.Contains(tresc, "certificate is valid for"),
		strings.Contains(tresc, "x509: "):
		return KlasaKonfiguracji
	}
	return KlasaSieci
}
