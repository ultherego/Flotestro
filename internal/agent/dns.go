package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/dns"
	"github.com/ultherego/flotestro/internal/modules/network"
	"github.com/ultherego/flotestro/internal/opspec"
)

const (
	sciezkaResolvConf = "/etc/resolv.conf"
	sciezkaResolvectl = "/usr/bin/resolvectl"
	sciezkaGetent     = "/usr/bin/getent"
)

// ZbierzDNS czyta stan resolvera hosta.
//
// Odczyt nie wymaga roota: resolv.conf jest czytelny dla wszystkich, a
// resolvectl pyta uslugi przez magistrale systemowa.
func ZbierzDNS(ctx context.Context) dns.Snapshot {
	snapshot := dns.Snapshot{ObservedAt: time.Now().UTC(), ResolvConf: sciezkaResolvConf}

	cel, _ := os.Readlink(sciezkaResolvConf)
	snapshot.ResolvConfTarget = cel
	tresc, err := os.ReadFile(sciezkaResolvConf)
	if err != nil {
		snapshot.UnavailableReason = "resolv.conf: " + err.Error()
	}
	snapshot.Owner = dns.WlascicielResolvConf(cel, string(tresc))

	// resolvectl podaje wiecej niz plik: stan per link, DNSSEC i DNS-over-TLS.
	// Bez niego zostaje sam plik, ktory mowi tylko, dokad ida zapytania.
	if network.Istnieje(sciezkaResolvectl) {
		if wyjscie, err := wyjsciePolecenia(ctx, sciezkaResolvectl, "status", "--no-pager"); err == nil {
			zResolved := dns.ParsujResolvectl(wyjscie)
			zResolved.ObservedAt = snapshot.ObservedAt
			zResolved.ResolvConf = snapshot.ResolvConf
			zResolved.ResolvConfTarget = snapshot.ResolvConfTarget
			zResolved.Owner = snapshot.Owner
			snapshot = zResolved
		}
	}
	if len(snapshot.Servers) == 0 {
		serwery, domeny := dns.ParsujResolvConf(string(tresc))
		snapshot.Servers = serwery
		snapshot.SearchDomains = append(snapshot.SearchDomains, domeny...)
		if snapshot.Mode == "" {
			snapshot.Mode = dns.TrybPlikowy
		}
	}

	// Zapis idzie przez profil polaczenia. Bez NetworkManagera panel nie ma
	// czym zmienic resolvera tak, zeby zmiana przetrwala kolejne zdarzenie
	// sieci - i mowi to wprost, zamiast pisac po pliku, ktory i tak zniknie.
	if network.Istnieje(network.SciezkaNmcli) {
		snapshot.Writable = true
		snapshot.WriteAdapter = network.AdapterNetworkManager
	} else {
		snapshot.ReadOnlyReason = "resolver is owned by " + opisWlasciciela(snapshot.Owner) +
			" and this host has no NetworkManager to change it through"
	}
	return snapshot
}

func opisWlasciciela(wlasciciel string) string {
	if wlasciciel == "" {
		return "an unidentified writer"
	}
	return wlasciciel
}

// applyDNS wykonuje operacje modulu DNS.
func (e *TaskExecutor) applyDNS(ctx context.Context, task *agentv1.TaskEnvelope,
	action opspec.ActionType, payload *opspec.DNSPayload) *agentv1.TaskResult {
	if payload == nil {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectInvalidRequest, "brak payloadu DNS")
	}
	timeout := timeoutOf(task, action)

	if action == opspec.ActionDNSResolveTest {
		// Test nie wymaga roota i nie zmienia hosta, wiec nie idzie przez
		// helpera: kazde przejscie przez roota trzeba uzasadnic.
		callCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		wyniki := testujNazwy(callCtx, payload.Names)
		zakodowane, err := json.Marshal(struct {
			Queries []dns.WynikZapytania `json:"queries"`
		}{wyniki})
		if err != nil {
			return rejected(agentv1.TaskResult_STATUS_FAILED, RejectInternalError, err.Error())
		}
		return &agentv1.TaskResult{
			TaskId:    task.GetTaskId(),
			Status:    agentv1.TaskResult_STATUS_SUCCEEDED,
			Message:   podsumowanieTestu(wyniki),
			DnsResult: &agentv1.DnsResult{Queries: zakodowane},
		}
	}

	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	response, err := e.helper.Call(callCtx, &helperv1.HelperRequest{
		TaskId:         task.GetTaskId(),
		ExpiresAt:      task.GetExpiresAt(),
		TimeoutSeconds: uint32(timeout.Seconds()),
		Action: &helperv1.HelperRequest_Dns{
			Dns: &helperv1.DnsRequest{
				Operation:       helperv1.DnsRequest_OPERATION_APPLY,
				Interface:       payload.Interface,
				Servers:         payload.Servers,
				SearchDomains:   payload.SearchDomains,
				IgnoreAutoDns:   payload.IgnoreAutoDNS,
				RollbackSeconds: payload.RollbackSeconds,
			},
		},
	}, timeout)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectHelperFailed, err.Error())
	}

	wynik := response.GetDnsResult()
	szczegoly := &agentv1.DnsResult{
		Profiles:         wynik.GetProfiles(),
		Message:          wynik.GetMessage(),
		RollbackId:       wynik.GetRollbackId(),
		RollbackDeadline: wynik.GetRollbackDeadline(),
	}
	if !response.GetAccepted() {
		odrzucone := rejected(agentv1.TaskResult_STATUS_REJECTED,
			response.GetErrorCode(), response.GetMessage())
		odrzucone.TaskId = task.GetTaskId()
		odrzucone.DnsResult = szczegoly
		return odrzucone
	}

	// Zly resolver odcina host od katalogu i od Kerberosa, wiec zmiana jest
	// uzbrojona wycofaniem tak samo jak zmiana adresu.
	if wynik.GetRollbackId() != "" {
		termin := terminWycofania(wynik.GetRollbackDeadline())
		if !czekajNaPanel(ctx, adresPanelu, termin.Add(-marginesPotwierdzenia)) {
			return &agentv1.TaskResult{
				TaskId: task.GetTaskId(), Status: agentv1.TaskResult_STATUS_FAILED,
				ErrorCode: RejectNetworkUnreachable,
				Message:   "po zmianie resolvera host nie dosiega panelu; wycofanie o " + wynik.GetRollbackDeadline(),
				DnsResult: szczegoly,
			}
		}
		potwierdzenie, err := e.helper.Call(ctx, &helperv1.HelperRequest{
			TaskId: task.GetTaskId(), TimeoutSeconds: 60,
			Action: &helperv1.HelperRequest_Network{
				Network: &helperv1.NetworkRequest{
					Operation:  helperv1.NetworkRequest_OPERATION_CONFIRM,
					RollbackId: wynik.GetRollbackId(),
				},
			},
		}, time.Minute)
		if err != nil || !potwierdzenie.GetAccepted() {
			return &agentv1.TaskResult{
				TaskId: task.GetTaskId(), Status: agentv1.TaskResult_STATUS_FAILED,
				ErrorCode: RejectHelperFailed, Message: "nie rozbrojono wycofania",
				DnsResult: szczegoly,
			}
		}
		szczegoly.Confirmed = true
		szczegoly.Message = wynik.GetMessage() + "; lacznosc potwierdzona, wycofanie rozbrojone"
		return &agentv1.TaskResult{
			TaskId:    task.GetTaskId(),
			Status:    agentv1.TaskResult_STATUS_SUCCEEDED,
			Message:   szczegoly.Message,
			DnsResult: szczegoly,
		}
	}

	return &agentv1.TaskResult{
		TaskId:    task.GetTaskId(),
		Status:    agentv1.TaskResult_STATUS_SUCCEEDED,
		Message:   wynik.GetMessage(),
		DnsResult: szczegoly,
	}
}

// testujNazwy rozwiazuje nazwy z hosta.
func testujNazwy(ctx context.Context, nazwy []string) []dns.WynikZapytania {
	wyniki := make([]dns.WynikZapytania, 0, len(nazwy))
	for _, nazwa := range nazwy {
		wyniki = append(wyniki, testujNazwe(ctx, nazwa))
	}
	return wyniki
}

// testujNazwe zadaje jedno pytanie i opisuje odpowiedz.
//
// Wynik jest nazwany, bo czas trwania dopisujemy w defer: bez tego pomiar
// gubilby sie przy kazdym wczesniejszym powrocie i kazde zapytanie trwaloby
// pozornie zero milisekund.
func testujNazwe(ctx context.Context, nazwa string) (wynik dns.WynikZapytania) {
	wynik = dns.WynikZapytania{Name: nazwa}
	if !dns.PoprawnaNazwaDoTestu(nazwa) {
		wynik.Error = "nazwa odrzucona przez agenta"
		return wynik
	}
	poczatek := time.Now()
	defer func() { wynik.TookMillis = time.Since(poczatek).Milliseconds() }()

	if network.Istnieje(sciezkaResolvectl) {
		// Legenda niesie protokol i zrodlo odpowiedzi, wiec jej nie wylaczamy:
		// operator pyta nie tylko "jaki adres", ale i "kto mi to powiedzial".
		wyjscie, komunikatBledu, err := wyjscieZBledem(ctx, sciezkaResolvectl, "query", nazwa)
		if err == nil {
			wynik.Addresses, wynik.Server = adresyZResolvectl(wyjscie)
			if len(wynik.Addresses) == 0 {
				// Pusta odpowiedz bez powodu bylaby cisza: nazwa bez adresu
				// i nazwa nierozwiazana to dwie rozne rzeczy.
				wynik.Error = "resolver nie zwrocil adresu"
			}
			return wynik
		}
		// Komunikat resolvera mowi, co sie stalo ("Name ... not found",
		// "No appropriate name servers"). Kod wyjscia nie mowi nic.
		wynik.Error = pierwszySensownyWiersz(komunikatBledu + "\n" + wyjscie)
		if wynik.Error == "" {
			wynik.Error = "nazwa nierozwiazana"
		}
		return wynik
	}

	// Host bez resolvectl pytamy tak, jak zapyta kazdy inny program.
	wyjscie, _, err := wyjscieZBledem(ctx, sciezkaGetent, "ahosts", nazwa)
	if err != nil {
		wynik.Error = "nazwa nierozwiazana"
		return wynik
	}
	widziane := map[string]bool{}
	for _, linia := range strings.Split(wyjscie, "\n") {
		pola := strings.Fields(linia)
		if len(pola) > 0 && !widziane[pola[0]] {
			widziane[pola[0]] = true
			wynik.Addresses = append(wynik.Addresses, pola[0])
		}
	}
	return wynik
}

// adresyZResolvectl czyta odpowiedz "resolvectl query".
//
// Wiersz odpowiedzi ma postac "nazwa: adres -- link: enp0s8", a wiersze
// legendy zaczynaja sie od dwoch myslnikow i mowia, skad odpowiedz przyszla.
// Zrodlo bierzemy z legendy, bo to ono odpowiada na pytanie "kto mi to
// powiedzial" - a przy diagnozie DNS to jest cale pytanie.
func adresyZResolvectl(wyjscie string) (adresy []string, serwer string) {
	for _, linia := range strings.Split(wyjscie, "\n") {
		linia = strings.TrimSpace(linia)
		if linia == "" {
			continue
		}
		if strings.HasPrefix(linia, "--") {
			opis := strings.TrimSpace(strings.TrimPrefix(linia, "--"))
			switch {
			case strings.HasPrefix(opis, "Data from:"):
				serwer = strings.TrimSpace(strings.TrimPrefix(opis, "Data from:"))
			case serwer == "" && strings.HasPrefix(opis, "Information acquired via protocol "):
				opis = strings.TrimPrefix(opis, "Information acquired via protocol ")
				protokol, _, _ := strings.Cut(opis, " ")
				serwer = protokol
			}
			continue
		}
		_, wartosc, ok := strings.Cut(linia, ":")
		if !ok {
			continue
		}
		// Ogon wiersza po "--" opisuje link, a nie adres.
		wartosc, _, _ = strings.Cut(wartosc, "--")
		pola := strings.Fields(wartosc)
		if len(pola) > 0 {
			adresy = append(adresy, pola[0])
		}
	}
	return adresy, serwer
}

// pierwszySensownyWiersz zwraca pierwszy niepusty wiersz komunikatu.
func pierwszySensownyWiersz(tresc string) string {
	for _, linia := range strings.Split(tresc, "\n") {
		linia = strings.TrimSpace(linia)
		if linia != "" && !strings.HasPrefix(linia, "--") {
			return linia
		}
	}
	return ""
}

func podsumowanieTestu(wyniki []dns.WynikZapytania) string {
	udane := 0
	for _, wynik := range wyniki {
		if len(wynik.Addresses) > 0 {
			udane++
		}
	}
	return "rozwiazano " + strconv.Itoa(udane) + " z " + strconv.Itoa(len(wyniki)) + " nazw"
}

func wyjsciePolecenia(ctx context.Context, sciezka string, argumenty ...string) (string, error) {
	wyjscie, _, err := wyjscieZBledem(ctx, sciezka, argumenty...)
	return wyjscie, err
}

// wyjscieZBledem zwraca oba strumienie. Komunikat bledu jest tu trescia
// odpowiedzi, a nie szumem: to on mowi, dlaczego nazwa sie nie rozwiazala.
func wyjscieZBledem(ctx context.Context, sciezka string, argumenty ...string) (string, string, error) {
	callCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(callCtx, sciezka, argumenty...)
	cmd.Env = []string{"LC_ALL=C", "LANG=C"}
	var blad bytes.Buffer
	cmd.Stderr = &blad
	wyjscie, err := cmd.Output()
	return string(wyjscie), blad.String(), err
}
