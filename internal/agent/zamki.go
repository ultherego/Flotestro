package agent

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/opspec"
)

// RoszczenieHosta jest zajeciem calego hosta. Restart i wylaczenie koliduja
// z kazda inna mutacja: zmiana, ktora zaczela sie tuz przed restartem, nie ma
// jak sie skonczyc.
const RoszczenieHosta = "host"

// limitOczekiwaniaNaZasob konczy czekanie na zajety zasob.
//
// Czekanie bez konca zamienialoby kolejke hosta w cisze: panel widzialby
// zadanie przyjete i nic wiecej, az do limitu czasu operacji. Odmowa
// z nazwa blokujacego zadania jest odpowiedzia, z ktora operator moze cos
// zrobic.
const limitOczekiwaniaNaZasob = 2 * time.Minute

// zamki serializuja mutacje na zasobach hosta.
//
// Limit liczby zadan (budzet) i blokada zasobu odpowiadaja na dwa rozne
// pytania: czy host ma moc na kolejne zadanie i czy dwie operacje sie nie
// wykluczaja. Dwa restarty sieci moga zmiescic sie w limicie dwoch zadan
// ogolnych, a mimo to zostawic konfiguracje, ktorej zaden plan wycofania nie
// opisuje.
//
// Wszystkie roszczenia zadania sa brane naraz, pod jednym zamkiem. Dzieki
// temu nie ma czesciowego zajecia ani kolejnosci nabywania, a wiec i cyklu:
// zadanie albo dostaje caly zestaw, albo czeka.
type zamki struct {
	mu     sync.Mutex
	zajete map[string]zajecie
	// zmiana jest zamykana przy kazdym zwolnieniu. Czekajacy budzi sie
	// i sprawdza jeszcze raz, zamiast odpytywac w petli.
	zmiana chan struct{}
}

// zajecie mowi, kto trzyma zasob. Nazwa operacji jest czescia odpowiedzi dla
// operatora: "sieć zajęta" bez wskazania, przez co, nie jest odpowiedzia.
type zajecie struct {
	zadanie  string
	operacja string
}

func noweZamki() *zamki {
	return &zamki{zajete: map[string]zajecie{}, zmiana: make(chan struct{})}
}

// zajmij bierze wszystkie roszczenia zadania albo czeka, az bedzie to mozliwe.
//
// Zwraca funkcje zwalniajaca i pusty powod. Gdy czekanie sie konczy, zwraca
// nil i powod z nazwa zasobu oraz operacji, ktora go trzyma.
func (z *zamki) zajmij(ctx context.Context, zadanie, operacja string,
	roszczenia []string) (func(), string) {
	if len(roszczenia) == 0 {
		return func() {}, ""
	}
	for {
		z.mu.Lock()
		if zasob, kto, kolizja := z.kolizja(roszczenia); !kolizja {
			for _, roszczenie := range roszczenia {
				z.zajete[roszczenie] = zajecie{zadanie: zadanie, operacja: operacja}
			}
			z.mu.Unlock()
			return func() { z.zwolnij(roszczenia) }, ""
		} else {
			czekaj := z.zmiana
			z.mu.Unlock()
			select {
			case <-czekaj:
			case <-ctx.Done():
				return nil, opisKolizji(zasob, kto)
			}
		}
	}
}

// kolizja mowi, czy ktorekolwiek roszczenie jest zajete. Roszczenie hosta
// koliduje ze wszystkim - i wszystko koliduje z nim.
func (z *zamki) kolizja(roszczenia []string) (zasob string, kto zajecie, jest bool) {
	if kto, trwa := z.zajete[RoszczenieHosta]; trwa {
		return RoszczenieHosta, kto, true
	}
	for _, roszczenie := range roszczenia {
		if roszczenie == RoszczenieHosta && len(z.zajete) > 0 {
			for zasob, kto := range z.zajete {
				return zasob, kto, true
			}
		}
		if kto, trwa := z.zajete[roszczenie]; trwa {
			return roszczenie, kto, true
		}
	}
	return "", zajecie{}, false
}

func (z *zamki) zwolnij(roszczenia []string) {
	z.mu.Lock()
	for _, roszczenie := range roszczenia {
		delete(z.zajete, roszczenie)
	}
	// Kazde zwolnienie budzi wszystkich czekajacych: ktory z nich pojdzie
	// dalej, rozstrzyga ponowne sprawdzenie, a nie kolejnosc zasniecia.
	close(z.zmiana)
	z.zmiana = make(chan struct{})
	z.mu.Unlock()
}

func opisKolizji(zasob string, kto zajecie) string {
	opis := fmt.Sprintf("zasob %s jest zajety", zasob)
	if kto.operacja != "" {
		opis += fmt.Sprintf(" przez operacje %s", kto.operacja)
	}
	if kto.zadanie != "" {
		opis += fmt.Sprintf(" (zadanie %s)", kto.zadanie)
	}
	return opis
}

// roszczeniaZadania wylicza zasoby, ktore zadanie zajmuje na wylacznosc.
//
// Odczyty nie zajmuja niczego: dwa odczyty stanu moga isc obok siebie, a ich
// koszt ogranicza budzet zadan, nie blokada. Wylaczne sa mutacje - i to one
// maja klase zasobu w rejestrze operacji.
func roszczeniaZadania(task *agentv1.TaskEnvelope) []string {
	action, payload, err := decodeAction(task)
	if err != nil || !action.Mutating() {
		return nil
	}

	zbior := map[string]bool{}
	if klasa := action.LockClass(); klasa != opspec.LockNone {
		zbior[klasa] = true
	}
	switch action {
	// Restart i wylaczenie zabieraja caly host: kazda inna mutacja i tak nie
	// zdazylaby sie skonczyc.
	case opspec.ActionSystemReboot, opspec.ActionSystemShutdown:
		zbior[RoszczenieHosta] = true

	// Jadro jest zasobem osobnym, ale sysctl i moduly zmieniaja takze stos
	// sieciowy. Bez tego drugiego roszczenia zmiana sysctl mogla by isc
	// rownolegle ze zmiana adresu i zostawic stan, ktorego nikt nie planowal.
	case opspec.ActionSysctlEnsure, opspec.ActionKernelModuleLoad,
		opspec.ActionKernelModuleBlacklist:
		zbior["kernel"] = true
		zbior[opspec.LockNetwork] = true

	// Bezpieczenstwo hosta: tryb MAC i reguly audytu przestawiaja polityke,
	// z ktora liczy sie kazda nastepna zmiana.
	case opspec.ActionSELinuxModeSet, opspec.ActionAuditRulesReload:
		zbior["security"] = true
	}

	// Plik jest zasobem sam w sobie: dwie zmiany tego samego pliku musza isc
	// po kolei, a zmiany roznych plikow nie maja powodu na siebie czekac.
	if sciezka := sciezkaPliku(action, payload); sciezka != "" {
		zbior["file:"+sciezka] = true
	}

	roszczenia := make([]string, 0, len(zbior))
	for nazwa := range zbior {
		roszczenia = append(roszczenia, nazwa)
	}
	// Kolejnosc jest ustalona, zeby opis kolizji i testy byly powtarzalne.
	sort.Strings(roszczenia)
	return roszczenia
}

// sciezkaPliku zwraca sciezke, ktorej dotyczy operacja plikowa.
func sciezkaPliku(action opspec.ActionType, payload opspec.Payload) string {
	switch action {
	case opspec.ActionFileEnsure, opspec.ActionFileRemove, opspec.ActionFileRollback:
		if payload.File != nil {
			return strings.TrimSpace(payload.File.Path)
		}
	}
	return ""
}

// nazwaOperacji nazywa zadanie w opisie kolizji. Nieznana operacja nie ma
// nazwy, ale ma identyfikator - i to wystarczy, zeby wskazac blokujacego.
func nazwaOperacji(task *agentv1.TaskEnvelope) string {
	action, _, err := decodeAction(task)
	if err != nil {
		return ""
	}
	return string(action)
}

// zajmijZasoby czeka na zasoby zadania z wlasnym limitem czasu.
//
// Limit jest krotszy niz limit operacji: zadanie, ktore przez dwie minuty nie
// dostalo zasobu, ma wrocic z odpowiedzia, a nie milczec do konca swojego
// czasu. Pusty powod i nil oznaczaja koniec sesji.
func zajmijZasoby(ctx context.Context, zasoby *zamki, task *agentv1.TaskEnvelope,
	roszczenia []string) (func(), string) {
	if len(roszczenia) == 0 {
		return func() {}, ""
	}
	czekanie, anuluj := context.WithTimeout(ctx, limitOczekiwaniaNaZasob)
	defer anuluj()

	oddaj, powod := zasoby.zajmij(czekanie, task.GetTaskId(), nazwaOperacji(task), roszczenia)
	if oddaj != nil {
		return oddaj, ""
	}
	if ctx.Err() != nil {
		// Sesja sie skonczyla: wyniku nie ma komu odeslac.
		return nil, ""
	}
	return nil, powod
}
