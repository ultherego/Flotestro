// Package nvd czyta opisy podatnosci z bazy NVD.
//
// To zrodlo niczego nie rozstrzyga. Zakresy wersji z NVD nie obejmuja
// poprawek backportowanych przez producenta dystrybucji, wiec uzyte do oceny
// hosta mowilyby o czym innym niz zainstalowany pakiet. Panel bierze stad
// wylacznie to, czego producent nie mowi: ocene CVSS i opis podatnosci.
package nvd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/vuln"
)

// Dostawca jest nazwa zrodla zapisywana przy kazdym opisie.
const Dostawca = "nvd"

// AdresDomyslny wskazuje API NVD w wersji 2.0.
const AdresDomyslny = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// RozmiarStrony jest najwiekszym, na ktory pozwala NVD.
const RozmiarStrony = 2000

// MaksymalneOkno jest najdluzszym okresem, o ktory NVD pozwala zapytac naraz.
const MaksymalneOkno = 120 * 24 * time.Hour

// MaksymalnaOdpowiedz ogranicza pojedyncza strone wynikow.
const MaksymalnaOdpowiedz = 128 << 20

// Odstepy miedzy zadaniami. NVD prosi o piec zadan na trzydziesci sekund bez
// klucza i piecdziesiat z kluczem; przekroczenie konczy sie odcieciem.
const (
	OdstepBezKlucza = 6 * time.Second
	OdstepZKluczem  = 700 * time.Millisecond
)

// Czytnik pobiera opisy podatnosci z NVD.
type Czytnik struct {
	URL    string
	Klucz  string
	Client *http.Client
	// Odstep miedzy zadaniami; zero oznacza odstep wlasciwy dla klucza.
	Odstep time.Duration
}

// Nowy tworzy czytnik.
func Nowy(adres, klucz string, limit time.Duration) *Czytnik {
	if adres == "" {
		adres = AdresDomyslny
	}
	if limit <= 0 {
		limit = 5 * time.Minute
	}
	return &Czytnik{URL: adres, Klucz: klucz, Client: &http.Client{Timeout: limit}}
}

func (c *Czytnik) Nazwa() string { return Dostawca }

// odstep zwraca przerwe miedzy zadaniami.
func (c *Czytnik) odstep() time.Duration {
	if c.Odstep > 0 {
		return c.Odstep
	}
	if c.Klucz != "" {
		return OdstepZKluczem
	}
	return OdstepBezKlucza
}

// Pobierz sciaga opisy zmienione od wskazanej chwili, strona po stronie.
//
// Zwraca chwile, do ktorej dane sa odczytane. Gdy poprzedni odczyt jest
// starszy niz okno, o ktore wolno zapytac, bierzemy caly zbior: to jest
// dluzsze, ale jedyne, co daje komplet.
func (c *Czytnik) Pobierz(ctx context.Context, od time.Time,
	przyjmij func([]vuln.SzczegolyCVE) error) (time.Time, error) {
	teraz := time.Now().UTC()
	pelne := od.IsZero() || teraz.Sub(od) > MaksymalneOkno

	indeks := 0
	najnowszy := od
	for {
		strona, wszystkich, err := c.strona(ctx, od, teraz, indeks, pelne)
		if err != nil {
			return time.Time{}, err
		}
		if len(strona) == 0 {
			break
		}
		for _, wpis := range strona {
			if wpis.ModifiedAt != nil && wpis.ModifiedAt.After(najnowszy) {
				najnowszy = *wpis.ModifiedAt
			}
		}
		if err := przyjmij(strona); err != nil {
			return time.Time{}, err
		}
		indeks += len(strona)
		if indeks >= wszystkich {
			break
		}
		select {
		case <-ctx.Done():
			return time.Time{}, ctx.Err()
		case <-time.After(c.odstep()):
		}
	}
	if najnowszy.IsZero() {
		najnowszy = teraz
	}
	return najnowszy, nil
}

// strona pobiera jedna strone wynikow.
func (c *Czytnik) strona(ctx context.Context, od, teraz time.Time, indeks int,
	pelne bool) ([]vuln.SzczegolyCVE, int, error) {
	parametry := url.Values{}
	parametry.Set("resultsPerPage", strconv.Itoa(RozmiarStrony))
	parametry.Set("startIndex", strconv.Itoa(indeks))
	if !pelne {
		parametry.Set("lastModStartDate", ZnacznikNVD(od))
		parametry.Set("lastModEndDate", ZnacznikNVD(teraz))
	}

	zadanie, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.URL+"?"+parametry.Encode(), nil)
	if err != nil {
		return nil, 0, err
	}
	zadanie.Header.Set("User-Agent", "flotestro-vuln/1")
	if c.Klucz != "" {
		zadanie.Header.Set("apiKey", c.Klucz)
	}

	odpowiedz, err := c.Client.Do(zadanie)
	if err != nil {
		return nil, 0, err
	}
	defer odpowiedz.Body.Close()
	if odpowiedz.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("NVD odpowiedzial %s", odpowiedz.Status)
	}

	tresc, err := io.ReadAll(io.LimitReader(odpowiedz.Body, MaksymalnaOdpowiedz))
	if err != nil {
		return nil, 0, err
	}
	return Parsuj(tresc)
}

// ZnacznikNVD zapisuje chwile w postaci, ktorej oczekuje NVD.
func ZnacznikNVD(chwila time.Time) string {
	return chwila.UTC().Format("2006-01-02T15:04:05.000") + "Z"
}

// odpowiedzNVD jest ta czescia odpowiedzi, ktora panel czyta.
type odpowiedzNVD struct {
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE wpisCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

type wpisCVE struct {
	ID           string `json:"id"`
	Published    string `json:"published"`
	LastModified string `json:"lastModified"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics map[string][]metryka `json:"metrics"`
}

// metryka jest jedna ocena CVSS podana przez NVD.
//
// Waga w wersji drugiej stoi obok danych, a nie w nich: tak wyglada
// odpowiedz NVD i bez tego oceny sprzed CVSS 3 zostawalyby bez slowa.
type metryka struct {
	Type         string `json:"type"`
	BaseSeverity string `json:"baseSeverity"`
	CVSSData     struct {
		Version      string  `json:"version"`
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
		VectorString string  `json:"vectorString"`
	} `json:"cvssData"`
}

// Parsuj czyta strone odpowiedzi NVD.
func Parsuj(tresc []byte) ([]vuln.SzczegolyCVE, int, error) {
	var odpowiedz odpowiedzNVD
	if err := json.Unmarshal(tresc, &odpowiedz); err != nil {
		return nil, 0, fmt.Errorf("odpowiedz NVD: %w", err)
	}
	wynik := make([]vuln.SzczegolyCVE, 0, len(odpowiedz.Vulnerabilities))
	for _, wpis := range odpowiedz.Vulnerabilities {
		szczegoly := szczegolyZWpisu(wpis.CVE)
		if szczegoly.CVE == "" {
			continue
		}
		wynik = append(wynik, szczegoly)
	}
	return wynik, odpowiedz.TotalResults, nil
}

// szczegolyZWpisu tlumaczy jeden wpis NVD na opis panelu.
func szczegolyZWpisu(wpis wpisCVE) vuln.SzczegolyCVE {
	szczegoly := vuln.SzczegolyCVE{
		CVE:    strings.ToValidUTF8(strings.TrimSpace(wpis.ID), ""),
		Source: Dostawca,
	}
	for _, opis := range wpis.Descriptions {
		if opis.Lang == "en" {
			szczegoly.Summary = skrocony(opis.Value)
			break
		}
	}
	if ocena, wersja, waga, wektor, ok := NajlepszaOcena(wpis.Metrics); ok {
		szczegoly.CVSSScore = &ocena
		szczegoly.CVSSVersion = wersja
		szczegoly.CVSSSeverity = strings.ToLower(waga)
		szczegoly.CVSSVector = wektor
	}
	szczegoly.PublishedAt = czas(wpis.Published)
	szczegoly.ModifiedAt = czas(wpis.LastModified)
	return szczegoly
}

// KolejnoscMetryk mowi, ktora ocena wygrywa, gdy jest ich kilka.
//
// Nowsza wersja CVSS opisuje te sama podatnosc dokladniej, wiec bierzemy
// najnowsza, ktora zrodlo podalo - a nie pierwsza z brzegu.
var KolejnoscMetryk = []string{"cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"}

// NajlepszaOcena wybiera ocene CVSS z metryk wpisu.
func NajlepszaOcena(metryki map[string][]metryka) (float64, string, string, string, bool) {
	for _, nazwa := range KolejnoscMetryk {
		wpisy := metryki[nazwa]
		if len(wpisy) == 0 {
			continue
		}
		wybrany := wpisy[0]
		// Ocena producenta danych ma pierwszenstwo przed wtorna.
		for _, wpis := range wpisy {
			if strings.EqualFold(wpis.Type, "Primary") {
				wybrany = wpis
				break
			}
		}
		dane := wybrany.CVSSData
		if dane.BaseScore == 0 && dane.VectorString == "" {
			continue
		}
		waga := dane.BaseSeverity
		if waga == "" {
			waga = wybrany.BaseSeverity
		}
		return dane.BaseScore, dane.Version, waga, dane.VectorString, true
	}
	return 0, "", "", "", false
}

// czas czyta znacznik NVD. Znaczniki przychodza bez strefy i sa w UTC.
func czas(znacznik string) *time.Time {
	znacznik = strings.TrimSpace(znacznik)
	if znacznik == "" {
		return nil
	}
	for _, wzorzec := range []string{"2006-01-02T15:04:05.000", "2006-01-02T15:04:05", time.RFC3339} {
		if chwila, err := time.Parse(wzorzec, znacznik); err == nil {
			chwilaUTC := chwila.UTC()
			return &chwilaUTC
		}
	}
	return nil
}

// skrocony przycina opis do 500 znakow, a nie bajtow.
func skrocony(opis string) string {
	opis = strings.ToValidUTF8(strings.TrimSpace(opis), "")
	znaki := []rune(opis)
	if len(znaki) > 500 {
		return string(znaki[:500])
	}
	return opis
}
