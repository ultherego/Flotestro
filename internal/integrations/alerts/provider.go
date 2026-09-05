// Package alerts czyta alerty i zaklada wyciszenia w systemie, ktory nimi
// zarzadza.
//
// Panel nie ma wlasnej regulki alertowej i miec nie bedzie: druga definicja
// tego, co jest awaria, oznaczalaby dwa rozne zdania o tym samym hoscie.
// Wyciszenie zakladamy tam, gdzie alerty powstaja - i zawsze z terminem,
// wlascicielem i powodem, bo cisza bez terminu to alert wylaczony na zawsze
// przez kogos, kogo juz nie ma w firmie.
package alerts

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/integrations"
)

// MaksymalnaCisza ogranicza wyciszenie zakladane z panelu.
//
// Cisza dluzsza niz doba przestaje byc "wiem, pracuje nad tym", a staje sie
// wylaczeniem alertu. Takie wylaczenie ma inne miejsce i innego wlasciciela
// niz przycisk w panelu hosta.
const MaksymalnaCisza = 24 * time.Hour

// DomyslnaCisza obowiazuje, gdy operator nie poda innego czasu.
const DomyslnaCisza = 2 * time.Hour

// Alert jest jednym alertem widzianym u zrodla.
type Alert struct {
	Name        string            `json:"name"`
	Severity    string            `json:"severity,omitempty"`
	State       string            `json:"state,omitempty"`
	Summary     string            `json:"summary,omitempty"`
	Description string            `json:"description,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	StartsAt    *time.Time        `json:"starts_at,omitempty"`
	// SilencedBy wylicza wyciszenia, ktore ten alert obejmuja.
	SilencedBy []string `json:"silenced_by,omitempty"`
	// GeneratorURL prowadzi do reguly u zrodla; panel nie kopiuje jej tresci.
	GeneratorURL string `json:"generator_url,omitempty"`
}

// Cisza jest wyciszeniem alertow.
type Cisza struct {
	ID string `json:"id,omitempty"`
	// Matchers opisuja, czego cisza dotyczy.
	Matchers  []Dopasowanie `json:"matchers"`
	StartsAt  time.Time     `json:"starts_at"`
	EndsAt    time.Time     `json:"ends_at"`
	CreatedBy string        `json:"created_by"`
	Comment   string        `json:"comment"`
	Status    string        `json:"status,omitempty"`
}

// Dopasowanie jest jednym warunkiem ciszy.
type Dopasowanie struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	IsRegex bool   `json:"is_regex,omitempty"`
}

// Provider jest zrodlem alertow.
type Provider interface {
	Nazwa() string
	Skonfigurowany() bool
	Zdrowie(ctx context.Context) integrations.Stan
	Alerty(ctx context.Context, filtry []string) ([]Alert, error)
	Ciszy(ctx context.Context, filtry []string) ([]Cisza, error)
	Ucisz(ctx context.Context, cisza Cisza) (string, error)
	Odcisz(ctx context.Context, id string) error
}

// Alertmanager jest adapterem Alertmanagera.
type Alertmanager struct {
	URL    string
	Client *http.Client
	Limit  time.Duration
	obwod  *integrations.Obwod
}

// NowyAlertmanager tworzy adapter. Pusty adres oznacza instalacje bez alertow.
func NowyAlertmanager(adres string, limit time.Duration) *Alertmanager {
	return &Alertmanager{
		URL:    strings.TrimRight(adres, "/"),
		Client: &http.Client{Timeout: limit + time.Second},
		Limit:  limit,
		obwod:  integrations.NowyObwod(),
	}
}

func (a *Alertmanager) Nazwa() string { return "alertmanager" }

func (a *Alertmanager) Skonfigurowany() bool { return a != nil && a.URL != "" }

// Zdrowie pyta zrodlo o gotowosc.
func (a *Alertmanager) Zdrowie(ctx context.Context) integrations.Stan {
	stan := integrations.Stan{Name: a.Nazwa(), Configured: a.Skonfigurowany(), URL: a.URL}
	if !a.Skonfigurowany() {
		stan.Reason = "this installation has no alert source configured"
		return stan
	}
	if a.obwod.Otwarty() {
		stan.Reason = integrations.ErrOtwartyObwod.Error()
		return stan
	}
	zapytanieCtx, cancel := integrations.ZLimitem(ctx, a.Limit)
	defer cancel()

	start := time.Now()
	err := a.obwod.Wykonaj(func() error {
		odpowiedz, err := a.wyslij(zapytanieCtx, http.MethodGet, "/-/ready", nil, nil)
		if err != nil {
			return err
		}
		defer odpowiedz.Body.Close()
		if odpowiedz.StatusCode != http.StatusOK {
			return fmt.Errorf("zrodlo alertow odpowiedzialo %s", odpowiedz.Status)
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

// Alerty czyta aktywne alerty pasujace do filtrow.
func (a *Alertmanager) Alerty(ctx context.Context, filtry []string) ([]Alert, error) {
	if !a.Skonfigurowany() {
		return nil, nil
	}
	parametry := url.Values{}
	for _, filtr := range filtry {
		parametry.Add("filter", filtr)
	}
	parametry.Set("silenced", "true")
	parametry.Set("active", "true")
	parametry.Set("inhibited", "false")

	var alerty []Alert
	err := a.zapytaj(ctx, http.MethodGet, "/api/v2/alerts", parametry, nil, func(dane []byte) error {
		var wynik []struct {
			Labels       map[string]string `json:"labels"`
			Annotations  map[string]string `json:"annotations"`
			StartsAt     time.Time         `json:"startsAt"`
			GeneratorURL string            `json:"generatorURL"`
			Status       struct {
				State      string   `json:"state"`
				SilencedBy []string `json:"silencedBy"`
			} `json:"status"`
		}
		if err := json.Unmarshal(dane, &wynik); err != nil {
			return fmt.Errorf("nie rozpoznano odpowiedzi zrodla alertow: %w", err)
		}
		for _, wpis := range wynik {
			start := wpis.StartsAt.UTC()
			alerty = append(alerty, Alert{
				Name:         wpis.Labels["alertname"],
				Severity:     wpis.Labels["severity"],
				State:        wpis.Status.State,
				Summary:      wpis.Annotations["summary"],
				Description:  wpis.Annotations["description"],
				Labels:       wpis.Labels,
				StartsAt:     &start,
				SilencedBy:   wpis.Status.SilencedBy,
				GeneratorURL: wpis.GeneratorURL,
			})
		}
		return nil
	})
	return alerty, err
}

// Ciszy czyta wyciszenia pasujace do filtrow.
func (a *Alertmanager) Ciszy(ctx context.Context, filtry []string) ([]Cisza, error) {
	if !a.Skonfigurowany() {
		return nil, nil
	}
	parametry := url.Values{}
	for _, filtr := range filtry {
		parametry.Add("filter", filtr)
	}
	var ciszy []Cisza
	err := a.zapytaj(ctx, http.MethodGet, "/api/v2/silences", parametry, nil, func(dane []byte) error {
		var wynik []struct {
			ID        string    `json:"id"`
			StartsAt  time.Time `json:"startsAt"`
			EndsAt    time.Time `json:"endsAt"`
			CreatedBy string    `json:"createdBy"`
			Comment   string    `json:"comment"`
			Status    struct {
				State string `json:"state"`
			} `json:"status"`
			Matchers []struct {
				Name    string `json:"name"`
				Value   string `json:"value"`
				IsRegex bool   `json:"isRegex"`
			} `json:"matchers"`
		}
		if err := json.Unmarshal(dane, &wynik); err != nil {
			return fmt.Errorf("nie rozpoznano odpowiedzi zrodla alertow: %w", err)
		}
		for _, wpis := range wynik {
			// Cisza wygasla jest historia, a nie stanem: pokazujemy te,
			// ktore jeszcze obowiazuja albo dopiero zaczna obowiazywac.
			if wpis.Status.State == "expired" {
				continue
			}
			cisza := Cisza{
				ID: wpis.ID, StartsAt: wpis.StartsAt.UTC(), EndsAt: wpis.EndsAt.UTC(),
				CreatedBy: wpis.CreatedBy, Comment: wpis.Comment, Status: wpis.Status.State,
			}
			for _, dopasowanie := range wpis.Matchers {
				cisza.Matchers = append(cisza.Matchers, Dopasowanie{
					Name: dopasowanie.Name, Value: dopasowanie.Value, IsRegex: dopasowanie.IsRegex,
				})
			}
			ciszy = append(ciszy, cisza)
		}
		return nil
	})
	return ciszy, err
}

// Ucisz zaklada wyciszenie i zwraca jego identyfikator.
func (a *Alertmanager) Ucisz(ctx context.Context, cisza Cisza) (string, error) {
	if !a.Skonfigurowany() {
		return "", fmt.Errorf("ta instalacja nie ma zrodla alertow")
	}
	if err := WalidujCisze(cisza); err != nil {
		return "", err
	}
	tresc, err := json.Marshal(map[string]any{
		"matchers":  dopasowaniaJSON(cisza.Matchers),
		"startsAt":  cisza.StartsAt.UTC().Format(time.RFC3339),
		"endsAt":    cisza.EndsAt.UTC().Format(time.RFC3339),
		"createdBy": cisza.CreatedBy,
		"comment":   cisza.Comment,
	})
	if err != nil {
		return "", err
	}
	var identyfikator string
	err = a.zapytaj(ctx, http.MethodPost, "/api/v2/silences", nil, tresc, func(dane []byte) error {
		var wynik struct {
			SilenceID string `json:"silenceID"`
		}
		if err := json.Unmarshal(dane, &wynik); err != nil {
			return fmt.Errorf("nie rozpoznano odpowiedzi zrodla alertow: %w", err)
		}
		identyfikator = wynik.SilenceID
		return nil
	})
	return identyfikator, err
}

// Odcisz konczy wyciszenie przed czasem.
func (a *Alertmanager) Odcisz(ctx context.Context, id string) error {
	if !a.Skonfigurowany() {
		return fmt.Errorf("ta instalacja nie ma zrodla alertow")
	}
	if id == "" || strings.ContainsAny(id, "/?#") {
		return fmt.Errorf("nieprawidlowy identyfikator wyciszenia")
	}
	return a.zapytaj(ctx, http.MethodDelete, "/api/v2/silence/"+url.PathEscape(id), nil, nil, nil)
}

// WalidujCisze sprawdza wyciszenie przed wyslaniem.
//
// Cisza bez terminu jest alertem wylaczonym na zawsze; cisza bez powodu jest
// alertem wylaczonym bez wiadomo czemu. Ani jedno, ani drugie nie moze wyjsc
// z panelu.
func WalidujCisze(cisza Cisza) error {
	if len(cisza.Matchers) == 0 {
		return fmt.Errorf("wyciszenie musi wskazywac, czego dotyczy")
	}
	for _, dopasowanie := range cisza.Matchers {
		if dopasowanie.Name == "" || strings.ContainsAny(dopasowanie.Name, " \t\n=") {
			return fmt.Errorf("nieprawidlowa nazwa etykiety %q", dopasowanie.Name)
		}
		if strings.ContainsAny(dopasowanie.Value, "\n") {
			return fmt.Errorf("wartosc etykiety zawiera znak nowej linii")
		}
	}
	if cisza.EndsAt.IsZero() || !cisza.EndsAt.After(cisza.StartsAt) {
		return fmt.Errorf("wyciszenie wymaga terminu konca")
	}
	if cisza.EndsAt.Sub(cisza.StartsAt) > MaksymalnaCisza {
		return fmt.Errorf("wyciszenie z panelu trwa najwyzej %s", MaksymalnaCisza)
	}
	if len(strings.TrimSpace(cisza.Comment)) < 8 {
		return fmt.Errorf("wyciszenie wymaga powodu (co najmniej 8 znakow)")
	}
	if cisza.CreatedBy == "" {
		return fmt.Errorf("wyciszenie wymaga wlasciciela")
	}
	return nil
}

func dopasowaniaJSON(dopasowania []Dopasowanie) []map[string]any {
	wynik := make([]map[string]any, 0, len(dopasowania))
	for _, dopasowanie := range dopasowania {
		wynik = append(wynik, map[string]any{
			"name": dopasowanie.Name, "value": dopasowanie.Value,
			"isRegex": dopasowanie.IsRegex, "isEqual": true,
		})
	}
	return wynik
}

// zapytaj wysyla zadanie przez bezpiecznik i przekazuje tresc odpowiedzi.
func (a *Alertmanager) zapytaj(ctx context.Context, metoda, sciezka string,
	parametry url.Values, tresc []byte, odbierz func([]byte) error) error {
	zapytanieCtx, cancel := integrations.ZLimitem(ctx, a.Limit)
	defer cancel()

	return a.obwod.Wykonaj(func() error {
		odpowiedz, err := a.wyslij(zapytanieCtx, metoda, sciezka, parametry, tresc)
		if err != nil {
			return err
		}
		defer odpowiedz.Body.Close()
		dane, err := io.ReadAll(io.LimitReader(odpowiedz.Body, 8<<20))
		if err != nil {
			return err
		}
		if odpowiedz.StatusCode >= 300 {
			opis := strings.TrimSpace(string(dane))
			if len(opis) > 200 {
				opis = opis[:200]
			}
			return fmt.Errorf("zrodlo alertow odpowiedzialo %s: %s", odpowiedz.Status, opis)
		}
		if odbierz == nil {
			return nil
		}
		return odbierz(dane)
	})
}

func (a *Alertmanager) wyslij(ctx context.Context, metoda, sciezka string,
	parametry url.Values, tresc []byte) (*http.Response, error) {
	adres := a.URL + sciezka
	if len(parametry) > 0 {
		adres += "?" + parametry.Encode()
	}
	var body io.Reader
	if tresc != nil {
		body = bytes.NewReader(tresc)
	}
	zadanie, err := http.NewRequestWithContext(ctx, metoda, adres, body)
	if err != nil {
		return nil, err
	}
	if tresc != nil {
		zadanie.Header.Set("Content-Type", "application/json")
	}
	return a.Client.Do(zadanie)
}
