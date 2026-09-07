package docker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Event to jedno zdarzenie dziennika silnika kontenerow.
//
// Zdarzenie jest odpowiedzia na pytanie "co sie tu stalo", a nie stanem
// hosta: nie trafia do inwentarza i nie zastepuje odczytu stanu. Kontener,
// ktory zostal zabity przez OOM, wyglada w inwentarzu tak samo jak kontener
// zatrzymany recznie - roznica jest wylacznie tutaj.
type Event struct {
	Time time.Time `json:"time"`
	// Type jest rodzajem obiektu: container, image, network, volume.
	Type string `json:"type"`
	// Action jest tym, co sie z nim stalo: start, die, destroy, pull.
	Action    string `json:"action"`
	ActorID   string `json:"actor_id,omitempty"`
	ActorName string `json:"actor_name,omitempty"`
	// Attributes niesie wybrane atrybuty zdarzenia. Silnik wklada tam takze
	// wszystkie etykiety kontenera, wiec lista jest zawezona: dziennik
	// zdarzen nie jest miejscem na wyciek sekretu z etykiety.
	Attributes map[string]string `json:"attributes,omitempty"`
}

// EventsSnapshot jest wynikiem jednego odczytu dziennika.
type EventsSnapshot struct {
	Events []Event `json:"events"`
	// Since i Until opisuja okno, ktore naprawde zostalo przeczytane.
	// Bez nich pusta lista nie mowi nic: cisza w oknie i brak odczytu
	// wygladaja tak samo.
	Since time.Time `json:"since"`
	Until time.Time `json:"until"`
	Types []string  `json:"types,omitempty"`
	// Truncated oznacza odczyt urwany limitem. Urwana lista bez tego
	// znacznika wygladalaby na kompletna - i operator wyciagalby wnioski
	// z dziennika, ktorego nie widzial w calosci.
	Truncated bool   `json:"truncated"`
	Reason    string `json:"truncated_reason,omitempty"`
}

// EventsOptions opisuje zamkniete okno odczytu.
type EventsOptions struct {
	Since  time.Duration
	Follow time.Duration
	Types  []string
	Max    int
}

// Granice odczytu dziennika. Sa tu, a nie tylko w panelu, bo to host placi
// za odczyt: zadanie bez konca zostaloby na nim na zawsze.
const (
	// MaksymalneOknoZdarzen ogranicza siegniecie wstecz.
	MaksymalneOknoZdarzen = 24 * time.Hour
	// MaksymalneSledzenieZdarzen ogranicza czekanie na zdarzenia przyszle.
	MaksymalneSledzenieZdarzen = 60 * time.Second
	// MaksymalnieZdarzen ogranicza liczbe zwroconych zdarzen.
	MaksymalnieZdarzen = 1000
	// MaksymalnyRozmiarZdarzen ogranicza rozmiar odczytu. Host, na ktorym
	// cos wstaje w petli, potrafi wyprodukowac tysiace zdarzen na minute.
	MaksymalnyRozmiarZdarzen = 256 << 10
	domyslnieZdarzen         = 200
	domyslneOknoZdarzen      = time.Hour
)

// RodzajeZdarzen wylicza rodzaje obiektow, o ktore wolno pytac.
//
// Lista jest zamknieta, bo filtr jedzie do Engine API. Silnik zna takze
// zdarzenia demona i wtyczek - te nie sa odpowiedzia na zadne pytanie
// operatora tej zakladki.
var RodzajeZdarzen = []string{"container", "image", "network", "volume"}

// RodzajZdarzenia mowi, czy nazwa jest znanym rodzajem.
func RodzajZdarzenia(nazwa string) bool {
	for _, rodzaj := range RodzajeZdarzen {
		if rodzaj == nazwa {
			return true
		}
	}
	return false
}

// atrybutyZdarzenia wylicza atrybuty, ktore trafiaja do wyniku.
//
// Silnik wklada do zdarzenia wszystkie etykiety obiektu. Etykiety bywaja
// miejscem, w ktore ktos wpisal token - dziennik zdarzen nie jest miejscem
// na jego wyciek, wiec lista jest zamknieta.
var atrybutyZdarzenia = []string{
	"image", "exitCode", "signal", "container", "name",
	"com.docker.compose.project", "com.docker.compose.service",
}

// Events czyta dziennik zdarzen silnika w zamknietym oknie czasu.
//
// Okno jest domkniete z obu stron: until jest wyliczone przy starcie, a nie
// zostawione otwarte. Dzieki temu odczyt konczy sie sam, takze wtedy, gdy
// panel przestal go sluchac.
func Events(ctx context.Context, client *Client, opts EventsOptions) (EventsSnapshot, error) {
	if client == nil {
		return EventsSnapshot{}, fmt.Errorf("%w: brak adaptera silnika", ErrUnavailable)
	}
	opts = domknijOpcje(opts)

	teraz := time.Now()
	snapshot := EventsSnapshot{
		Since: teraz.Add(-opts.Since).UTC(),
		Until: teraz.Add(opts.Follow).UTC(),
		Types: opts.Types,
	}

	query := url.Values{}
	query.Set("since", strconv.FormatInt(snapshot.Since.Unix(), 10))
	query.Set("until", strconv.FormatInt(snapshot.Until.Unix(), 10))
	if len(opts.Types) > 0 {
		filtr := map[string][]string{"type": opts.Types}
		zakodowany, err := json.Marshal(filtr)
		if err != nil {
			return snapshot, err
		}
		query.Set("filters", string(zakodowany))
	}

	// Odczyt ma wlasny limit czasu, niezalezny od kontekstu zadania: silnik,
	// ktory nie domknie strumienia, nie moze zatrzymac agenta.
	limit := opts.Follow + 30*time.Second
	odczytCtx, anuluj := context.WithTimeout(ctx, limit)
	defer anuluj()

	err := client.strumien(odczytCtx, "/events", query, func(linia []byte) bool {
		zdarzenie, ok := zdarzenieZLinii(linia)
		if !ok {
			return true
		}
		snapshot.Events = append(snapshot.Events, zdarzenie)
		if len(snapshot.Events) >= opts.Max {
			snapshot.Truncated = true
			snapshot.Reason = fmt.Sprintf("osiagnieto limit %d zdarzen", opts.Max)
			return false
		}
		return true
	}, MaksymalnyRozmiarZdarzen)
	switch {
	case err == nil:
	case errors.Is(err, errLimitRozmiaru):
		// Urwanie limitem rozmiaru nie jest bledem odczytu: operator dostaje
		// to, co zmiescilo sie w limicie, i wie, ze reszta zostala.
		snapshot.Truncated = true
		snapshot.Reason = fmt.Sprintf("osiagnieto limit %d bajtow odczytu",
			MaksymalnyRozmiarZdarzen)
	case errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil:
		// Koniec okna jest normalnym koncem odczytu, a nie awaria: silnik
		// trzyma strumien otwarty do until i czasem nie domyka go sam.
	default:
		return snapshot, err
	}

	sort.SliceStable(snapshot.Events, func(i, j int) bool {
		return snapshot.Events[i].Time.Before(snapshot.Events[j].Time)
	})
	return snapshot, nil
}

// domknijOpcje sprowadza zamowienie do granic, ktore host uniesie.
func domknijOpcje(opts EventsOptions) EventsOptions {
	if opts.Since <= 0 {
		opts.Since = domyslneOknoZdarzen
	}
	if opts.Since > MaksymalneOknoZdarzen {
		opts.Since = MaksymalneOknoZdarzen
	}
	if opts.Follow < 0 {
		opts.Follow = 0
	}
	if opts.Follow > MaksymalneSledzenieZdarzen {
		opts.Follow = MaksymalneSledzenieZdarzen
	}
	if opts.Max <= 0 {
		opts.Max = domyslnieZdarzen
	}
	if opts.Max > MaksymalnieZdarzen {
		opts.Max = MaksymalnieZdarzen
	}
	wybrane := make([]string, 0, len(opts.Types))
	for _, rodzaj := range opts.Types {
		rodzaj = strings.ToLower(strings.TrimSpace(rodzaj))
		if RodzajZdarzenia(rodzaj) && !zawiera(wybrane, rodzaj) {
			wybrane = append(wybrane, rodzaj)
		}
	}
	if len(wybrane) == 0 {
		// Brak filtra znaczy cztery rodzaje, a nie "wszystko, co silnik ma":
		// zdarzenia demona i wtyczek nie sa odpowiedzia na pytanie operatora.
		wybrane = append(wybrane, RodzajeZdarzen...)
	}
	sort.Strings(wybrane)
	opts.Types = wybrane
	return opts
}

// zdarzenieZLinii tlumaczy jedna linie strumienia na zdarzenie.
func zdarzenieZLinii(linia []byte) (Event, bool) {
	var surowe struct {
		Type   string `json:"Type"`
		Action string `json:"Action"`
		Actor  struct {
			ID         string            `json:"ID"`
			Attributes map[string]string `json:"Attributes"`
		} `json:"Actor"`
		Time     int64 `json:"time"`
		TimeNano int64 `json:"timeNano"`
	}
	if err := json.Unmarshal(linia, &surowe); err != nil || surowe.Type == "" {
		return Event{}, false
	}
	zdarzenie := Event{
		Type: surowe.Type, Action: surowe.Action, ActorID: surowe.Actor.ID,
		ActorName: surowe.Actor.Attributes["name"],
	}
	switch {
	case surowe.TimeNano > 0:
		zdarzenie.Time = time.Unix(0, surowe.TimeNano).UTC()
	case surowe.Time > 0:
		zdarzenie.Time = time.Unix(surowe.Time, 0).UTC()
	}
	for _, nazwa := range atrybutyZdarzenia {
		if wartosc, ok := surowe.Actor.Attributes[nazwa]; ok && wartosc != "" {
			if zdarzenie.Attributes == nil {
				zdarzenie.Attributes = map[string]string{}
			}
			zdarzenie.Attributes[nazwa] = wartosc
		}
	}
	return zdarzenie, true
}
