// Package metrics czyta metryki z systemu, ktory juz je zbiera.
//
// Panel nie ma wlasnej bazy szeregow czasowych i miec nie bedzie: pytanie
// "ile ten host mial procesora o trzeciej w nocy" ma odpowiedz w Prometheusie,
// a duplikowanie jej w panelu oznaczaloby druga baze, drugi retencyjny problem
// i dwie rozne prawdy. Panel pokazuje wiec cudzy wykres razem z nazwa zrodla
// i zakresem czasu - i mowi wprost, gdy zrodlo nie odpowiada.
package metrics

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

	"github.com/ultherego/flotestro/internal/integrations"
)

// Punkt jest jedna probka szeregu.
type Punkt struct {
	At    time.Time `json:"at"`
	Value float64   `json:"value"`
}

// Szereg to nazwany przebieg wartosci.
type Szereg struct {
	Name string `json:"name"`
	// Unit opisuje, w czym jest wartosc - panel nie zgaduje tego z nazwy.
	Unit   string  `json:"unit,omitempty"`
	Points []Punkt `json:"points,omitempty"`
	// Last jest ostatnia wartoscia. Pusty wskaznik oznacza brak danych,
	// a nie zero: host bez metryk i host z zerowym obciazeniem to co innego.
	Last *float64 `json:"last,omitempty"`
	// Query jest zapytaniem, ktore panel wyslal. Operator ma widziec, skad
	// wzial sie wykres, zeby moc go powtorzyc u zrodla.
	Query string `json:"query,omitempty"`
	// UnavailableReason mowi, dlaczego szeregu nie ma.
	UnavailableReason string `json:"unavailable_reason,omitempty"`
}

// Zapytanie opisuje jeden panel wykresu.
type Zapytanie struct {
	Name   string
	Unit   string
	PromQL string
}

// Provider jest zrodlem metryk.
type Provider interface {
	Nazwa() string
	Skonfigurowany() bool
	Zdrowie(ctx context.Context) integrations.Stan
	// Szeregi liczy wykresy dla jednego hosta.
	Szeregi(ctx context.Context, etykieta string, od, do time.Time) []Szereg
}

// Prometheus jest adapterem Prometheusa i wszystkiego, co mowi jego jezykiem.
type Prometheus struct {
	URL    string
	Client *http.Client
	Limit  time.Duration
	// Zapytania opisuja panele wykresu. Puste oznacza zestaw domyslny.
	Zapytania []Zapytanie
	obwod     *integrations.Obwod
}

// DomyslneZapytania sa napisane pod nazewnictwo node_exportera, bo to ono
// jest de facto standardem w instalacjach, do ktorych panel sie podlacza.
// Instalacja z innym zestawem metryk podmienia je w konfiguracji, zamiast
// dostawac puste wykresy bez wyjasnienia.
func DomyslneZapytania() []Zapytanie {
	return []Zapytanie{
		{
			Name: "cpu", Unit: "%",
			PromQL: `100 - (avg by (instance) (rate(node_cpu_seconds_total{mode="idle",instance="%s"}[5m])) * 100)`,
		},
		{
			Name: "memory", Unit: "%",
			PromQL: `100 * (1 - node_memory_MemAvailable_bytes{instance="%s"} / node_memory_MemTotal_bytes{instance="%s"})`,
		},
		{
			Name: "load1", Unit: "",
			PromQL: `node_load1{instance="%s"}`,
		},
		{
			Name: "disk_root", Unit: "%",
			PromQL: `100 - (node_filesystem_avail_bytes{instance="%s",mountpoint="/"} / node_filesystem_size_bytes{instance="%s",mountpoint="/"} * 100)`,
		},
	}
}

// NowyPrometheus tworzy adapter. Pusty adres oznacza instalacje bez metryk -
// i to jest stan poprawny, a nie awaria.
func NowyPrometheus(adres string, limit time.Duration, zapytania []Zapytanie) *Prometheus {
	if len(zapytania) == 0 {
		zapytania = DomyslneZapytania()
	}
	return &Prometheus{
		URL:       strings.TrimRight(adres, "/"),
		Client:    &http.Client{Timeout: limit + time.Second},
		Limit:     limit,
		Zapytania: zapytania,
		obwod:     integrations.NowyObwod(),
	}
}

func (p *Prometheus) Nazwa() string { return "prometheus" }

func (p *Prometheus) Skonfigurowany() bool { return p != nil && p.URL != "" }

// Zdrowie pyta zrodlo o gotowosc.
func (p *Prometheus) Zdrowie(ctx context.Context) integrations.Stan {
	stan := integrations.Stan{Name: p.Nazwa(), Configured: p.Skonfigurowany(), URL: p.URL}
	if !p.Skonfigurowany() {
		stan.Reason = "this installation has no metrics source configured"
		return stan
	}
	if p.obwod.Otwarty() {
		stan.Reason = integrations.ErrOtwartyObwod.Error()
		return stan
	}
	zapytanieCtx, cancel := integrations.ZLimitem(ctx, p.Limit)
	defer cancel()

	start := time.Now()
	err := p.obwod.Wykonaj(func() error {
		odpowiedz, err := p.get(zapytanieCtx, "/-/ready", nil)
		if err != nil {
			return err
		}
		odpowiedz.Body.Close()
		if odpowiedz.StatusCode != http.StatusOK {
			return fmt.Errorf("zrodlo metryk odpowiedzialo %s", odpowiedz.Status)
		}
		return nil
	})
	czas := time.Since(start).Milliseconds()
	sprawdzone := time.Now().UTC()
	stan.LatencyMillis = &czas
	stan.CheckedAt = &sprawdzone
	if err != nil {
		stan.Reason = err.Error()
		return stan
	}
	stan.Healthy = true
	return stan
}

// Szeregi liczy wykresy dla jednego hosta.
//
// Blad jednego panelu nie moze zabrac pozostalych: kazdy szereg niesie swoj
// powod niedostepnosci, a operator widzi te wykresy, ktore sie udalo policzyc.
func (p *Prometheus) Szeregi(ctx context.Context, etykieta string, od, do time.Time) []Szereg {
	wynik := make([]Szereg, 0, len(p.Zapytania))
	if !p.Skonfigurowany() {
		return wynik
	}
	krok := do.Sub(od) / 60
	if krok < 15*time.Second {
		krok = 15 * time.Second
	}
	for _, zapytanie := range p.Zapytania {
		szereg := Szereg{Name: zapytanie.Name, Unit: zapytanie.Unit}
		szereg.Query = podstawEtykiete(zapytanie.PromQL, etykieta)
		punkty, err := p.zakres(ctx, szereg.Query, od, do, krok)
		if err != nil {
			szereg.UnavailableReason = err.Error()
			wynik = append(wynik, szereg)
			continue
		}
		szereg.Points = punkty
		if len(punkty) > 0 {
			ostatni := punkty[len(punkty)-1].Value
			szereg.Last = &ostatni
		}
		wynik = append(wynik, szereg)
	}
	return wynik
}

// podstawEtykiete wstawia wartosc etykiety hosta w kazde miejsce zapytania.
func podstawEtykiete(zapytanie, etykieta string) string {
	ile := strings.Count(zapytanie, "%s")
	wartosci := make([]any, ile)
	for i := range wartosci {
		wartosci[i] = etykieta
	}
	return fmt.Sprintf(zapytanie, wartosci...)
}

// zakres pyta o szereg w oknie czasu.
func (p *Prometheus) zakres(ctx context.Context, zapytanie string,
	od, do time.Time, krok time.Duration) ([]Punkt, error) {
	zapytanieCtx, cancel := integrations.ZLimitem(ctx, p.Limit)
	defer cancel()

	parametry := url.Values{}
	parametry.Set("query", zapytanie)
	parametry.Set("start", strconv.FormatInt(od.Unix(), 10))
	parametry.Set("end", strconv.FormatInt(do.Unix(), 10))
	parametry.Set("step", strconv.Itoa(int(krok.Seconds()))+"s")

	var punkty []Punkt
	err := p.obwod.Wykonaj(func() error {
		odpowiedz, err := p.get(zapytanieCtx, "/api/v1/query_range", parametry)
		if err != nil {
			return err
		}
		defer odpowiedz.Body.Close()
		if odpowiedz.StatusCode != http.StatusOK {
			return fmt.Errorf("zrodlo metryk odpowiedzialo %s", odpowiedz.Status)
		}
		dane, err := io.ReadAll(io.LimitReader(odpowiedz.Body, 8<<20))
		if err != nil {
			return err
		}
		punkty, err = ParsujZakres(dane)
		return err
	})
	if err != nil {
		return nil, err
	}
	return punkty, nil
}

// ParsujZakres czyta odpowiedz query_range.
//
// Bierzemy pierwszy szereg: zapytanie panelu jest tak napisane, zeby dotyczylo
// jednego hosta. Kilka szeregow oznacza, ze etykieta nie identyfikuje hosta
// jednoznacznie - i wtedy lepiej pokazac jeden wykres niz sklejke kilku.
func ParsujZakres(dane []byte) ([]Punkt, error) {
	var odpowiedz struct {
		Status string `json:"status"`
		Error  string `json:"error"`
		Data   struct {
			Result []struct {
				Values [][2]json.RawMessage `json:"values"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(dane, &odpowiedz); err != nil {
		return nil, fmt.Errorf("nie rozpoznano odpowiedzi zrodla metryk: %w", err)
	}
	if odpowiedz.Status != "success" {
		if odpowiedz.Error != "" {
			return nil, fmt.Errorf("zrodlo metryk: %s", odpowiedz.Error)
		}
		return nil, fmt.Errorf("zrodlo metryk odrzucilo zapytanie")
	}
	if len(odpowiedz.Data.Result) == 0 {
		return nil, nil
	}
	var punkty []Punkt
	for _, para := range odpowiedz.Data.Result[0].Values {
		var znacznik float64
		if err := json.Unmarshal(para[0], &znacznik); err != nil {
			continue
		}
		var tekst string
		if err := json.Unmarshal(para[1], &tekst); err != nil {
			continue
		}
		wartosc, err := strconv.ParseFloat(tekst, 64)
		if err != nil {
			// NaN w szeregu jest normalny: oznacza przerwe w zbieraniu,
			// a nie wartosc zerowa. Pomijamy punkt, zamiast rysowac zero.
			continue
		}
		punkty = append(punkty, Punkt{
			At:    time.Unix(int64(znacznik), 0).UTC(),
			Value: wartosc,
		})
	}
	return punkty, nil
}

func (p *Prometheus) get(ctx context.Context, sciezka string, parametry url.Values) (*http.Response, error) {
	adres := p.URL + sciezka
	if len(parametry) > 0 {
		adres += "?" + parametry.Encode()
	}
	zadanie, err := http.NewRequestWithContext(ctx, http.MethodGet, adres, nil)
	if err != nil {
		return nil, err
	}
	return p.Client.Do(zadanie)
}
