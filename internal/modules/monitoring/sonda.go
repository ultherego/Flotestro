// Package monitoring wykonuje sondy z hosta.
//
// Sonda odpowiada na pytanie, ktorego monitoring centralny nie umie zadac:
// "co widzi ten host". Alert moze mowic, ze usluga nie odpowiada, a z hosta
// odpowiadac - i wtedy problem jest w sieci miedzy nimi, a nie w usludze.
// Dlatego sonda jest zadaniem per host, a nie kolejnym zapytaniem do
// Prometheusa.
//
// Sonda niczego nie zmienia i nie potrzebuje roota, wiec nie idzie przez
// helpera: kazde przejscie przez roota trzeba uzasadnic.
package monitoring

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Rodzaje sond.
const (
	SondaHTTP = "http"
	SondaTCP  = "tcp"
)

// MaksymalnyLimit ogranicza czekanie na odpowiedz.
const MaksymalnyLimit = 60 * time.Second

// DomyslnyLimit obowiazuje sonde bez wskazanego limitu.
const DomyslnyLimit = 10 * time.Second

// maksymalnaTresc ogranicza ilosc czytanej odpowiedzi. Sonda sprawdza, czy
// usluga odpowiada - nie pobiera z niej danych.
const maksymalnaTresc = 64 << 10

// Zlecenie opisuje jedna sonde.
type Zlecenie struct {
	Kind string `json:"kind"`
	// Target jest adresem: URL dla sondy HTTP, host:port dla TCP.
	Target string `json:"target"`
	// ExpectStatus jest oczekiwanym kodem odpowiedzi. Zero oznacza dowolny
	// kod z zakresu 2xx i 3xx.
	ExpectStatus int `json:"expect_status,omitempty"`
	// ExpectBody jest fragmentem tresci, ktory ma sie w odpowiedzi znalezc.
	ExpectBody     string `json:"expect_body,omitempty"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
}

// Wynik opisuje to, co host zobaczyl.
type Wynik struct {
	Kind   string `json:"kind"`
	Target string `json:"target"`
	// Reachable mowi, czy polaczenie doszlo do skutku.
	Reachable bool `json:"reachable"`
	// Passed mowi, czy odpowiedz spelnila oczekiwania zlecenia. To dwie
	// rozne rzeczy: usluga moze odpowiadac i odpowiadac zle.
	Passed         bool  `json:"passed"`
	StatusCode     *int  `json:"status_code,omitempty"`
	DurationMillis int64 `json:"duration_millis"`
	BodyMatched    *bool `json:"body_matched,omitempty"`
	// TLSExpiry jest terminem certyfikatu, ktory usluga pokazala. Puste
	// oznacza polaczenie bez TLS albo brak certyfikatu.
	TLSExpiry  *time.Time `json:"tls_expiry,omitempty"`
	TLSIssuer  string     `json:"tls_issuer,omitempty"`
	Error      string     `json:"error,omitempty"`
	ObservedAt time.Time  `json:"observed_at"`
}

// Waliduj sprawdza zlecenie sondy.
func (z Zlecenie) Waliduj() error {
	if z.TimeoutSeconds < 0 || time.Duration(z.TimeoutSeconds)*time.Second > MaksymalnyLimit {
		return fmt.Errorf("limit czasu sondy jest poza zakresem 0-%s", MaksymalnyLimit)
	}
	if strings.ContainsAny(z.Target, " \t\n\r") || z.Target == "" {
		return fmt.Errorf("cel sondy jest pusty albo zawiera niedozwolony znak")
	}
	switch z.Kind {
	case SondaHTTP:
		adres, err := url.Parse(z.Target)
		if err != nil || adres.Host == "" {
			return fmt.Errorf("cel sondy %q nie jest poprawnym adresem", z.Target)
		}
		// Sonda mowi po HTTP, a nie dowolnym protokolem: "file://" albo
		// "gopher://" nie jest sprawdzeniem uslugi, tylko czytaniem hosta.
		if adres.Scheme != "http" && adres.Scheme != "https" {
			return fmt.Errorf("sonda HTTP obsluguje wylacznie http i https")
		}
		if z.ExpectStatus != 0 && (z.ExpectStatus < 100 || z.ExpectStatus > 599) {
			return fmt.Errorf("oczekiwany kod odpowiedzi %d jest poza zakresem", z.ExpectStatus)
		}
		if len(z.ExpectBody) > 512 {
			return fmt.Errorf("oczekiwany fragment tresci jest za dlugi")
		}
	case SondaTCP:
		gospodarz, port, err := net.SplitHostPort(z.Target)
		if err != nil || gospodarz == "" || port == "" {
			return fmt.Errorf("cel sondy %q nie ma postaci host:port", z.Target)
		}
	default:
		return fmt.Errorf("nieznany rodzaj sondy %q", z.Kind)
	}
	return nil
}

// Wykonaj przeprowadza sonde i opisuje, co host zobaczyl.
func Wykonaj(ctx context.Context, zlecenie Zlecenie) Wynik {
	wynik := Wynik{Kind: zlecenie.Kind, Target: zlecenie.Target, ObservedAt: time.Now().UTC()}
	if err := zlecenie.Waliduj(); err != nil {
		wynik.Error = err.Error()
		return wynik
	}
	limit := time.Duration(zlecenie.TimeoutSeconds) * time.Second
	if limit <= 0 {
		limit = DomyslnyLimit
	}
	sondaCtx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()

	start := time.Now()
	switch zlecenie.Kind {
	case SondaTCP:
		wynik = sondaTCP(sondaCtx, zlecenie, wynik)
	default:
		wynik = sondaHTTP(sondaCtx, zlecenie, wynik)
	}
	wynik.DurationMillis = time.Since(start).Milliseconds()
	return wynik
}

// sondaTCP sprawdza, czy da sie otworzyc polaczenie.
func sondaTCP(ctx context.Context, zlecenie Zlecenie, wynik Wynik) Wynik {
	dialer := &net.Dialer{}
	polaczenie, err := dialer.DialContext(ctx, "tcp", zlecenie.Target)
	if err != nil {
		wynik.Error = err.Error()
		return wynik
	}
	defer polaczenie.Close()
	wynik.Reachable = true
	wynik.Passed = true
	return wynik
}

// sondaHTTP sprawdza, co usluga odpowiada.
//
// Certyfikat sprawdzamy magazynem zaufania hosta, a nie panelu: pytanie
// brzmi "czy ten host moze korzystac z tej uslugi", a nie "czy ja jej ufam".
func sondaHTTP(ctx context.Context, zlecenie Zlecenie, wynik Wynik) Wynik {
	klient := &http.Client{
		// Przekierowania sledzimy, ale nie w nieskonczonosc: petla
		// przekierowan jest awaria uslugi, a nie odpowiedzia.
		CheckRedirect: func(_ *http.Request, poprzednie []*http.Request) error {
			if len(poprzednie) >= 5 {
				return fmt.Errorf("usluga przekierowuje w kolko")
			}
			return nil
		},
	}
	zadanie, err := http.NewRequestWithContext(ctx, http.MethodGet, zlecenie.Target, nil)
	if err != nil {
		wynik.Error = err.Error()
		return wynik
	}
	zadanie.Header.Set("User-Agent", "flotestro-probe/1")

	odpowiedz, err := klient.Do(zadanie)
	if err != nil {
		wynik.Error = err.Error()
		return wynik
	}
	defer odpowiedz.Body.Close()
	wynik.Reachable = true
	kod := odpowiedz.StatusCode
	wynik.StatusCode = &kod

	if odpowiedz.TLS != nil && len(odpowiedz.TLS.PeerCertificates) > 0 {
		lisc := odpowiedz.TLS.PeerCertificates[0]
		termin := lisc.NotAfter.UTC()
		wynik.TLSExpiry = &termin
		wynik.TLSIssuer = lisc.Issuer.String()
	}

	tresc, err := io.ReadAll(io.LimitReader(odpowiedz.Body, maksymalnaTresc))
	if err != nil {
		wynik.Error = err.Error()
		return wynik
	}
	if zlecenie.ExpectBody != "" {
		zawiera := strings.Contains(string(tresc), zlecenie.ExpectBody)
		wynik.BodyMatched = &zawiera
	}

	wynik.Passed = kodPasuje(kod, zlecenie.ExpectStatus) &&
		(wynik.BodyMatched == nil || *wynik.BodyMatched)
	if !wynik.Passed && wynik.Error == "" {
		wynik.Error = opisNiezgodnosci(kod, zlecenie, wynik)
	}
	return wynik
}

func kodPasuje(kod, oczekiwany int) bool {
	if oczekiwany != 0 {
		return kod == oczekiwany
	}
	return kod >= 200 && kod < 400
}

func opisNiezgodnosci(kod int, zlecenie Zlecenie, wynik Wynik) string {
	if !kodPasuje(kod, zlecenie.ExpectStatus) {
		if zlecenie.ExpectStatus != 0 {
			return fmt.Sprintf("usluga odpowiedziala %d, oczekiwano %d", kod, zlecenie.ExpectStatus)
		}
		return fmt.Sprintf("usluga odpowiedziala %d", kod)
	}
	if wynik.BodyMatched != nil && !*wynik.BodyMatched {
		return "odpowiedz nie zawiera oczekiwanego fragmentu"
	}
	return ""
}

// bezWeryfikacji jest tu tylko po to, zeby powiedziec, ze go nie ma:
// sonda nie wylacza sprawdzania certyfikatu. Usluga z certyfikatem, ktoremu
// host nie ufa, jest usluga, z ktorej ten host nie skorzysta - i to jest
// odpowiedz sondy, a nie szczegol do pominiecia.
var _ = tls.Config{}
