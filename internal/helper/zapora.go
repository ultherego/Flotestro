package helper

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/firewall"
)

// PlikPlanuZapory trzyma rejestr regul sprzed zmiany.
const rozszerzeniePlanuZapory = ".zapora.json"

// applyFirewall obsluguje operacje na zaporze hosta.
//
// Panel zmienia wylacznie wlasna tablice nftables albo strefe firewalld.
// Cudze lancuchy - dockera, firewalld, iptables-nft - sa przepisywane bez
// jego udzialu, wiec regula w nich zniknelaby bez sladu przy pierwszym
// starcie kontenera albo przeladowaniu uslugi.
func (s *Server) applyFirewall(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.FirewallRequest) *helperv1.HelperResponse {
	if !s.unitMutex.TryLock() {
		return reject(ErrorLocked, "inna operacja na jednostkach jest w toku")
	}
	defer s.unitMutex.Unlock()

	timeout := time.Duration(request.GetTimeoutSeconds()) * time.Second
	if timeout <= 0 || timeout > 30*time.Minute {
		timeout = 5 * time.Minute
	}
	actionCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	switch action.GetOperation() {
	case helperv1.FirewallRequest_OPERATION_READ:
		return odpowiedzZapory(s.czytajZapore(actionCtx), "", nil)
	case helperv1.FirewallRequest_OPERATION_CONFIRM:
		return s.potwierdzZapore(actionCtx, action.GetRollbackId())
	case helperv1.FirewallRequest_OPERATION_RESTORE:
		return s.przywrocZapore(actionCtx, action.GetRollbackId())
	case helperv1.FirewallRequest_OPERATION_ZONE_PORT,
		helperv1.FirewallRequest_OPERATION_ZONE_SERVICE:
		return s.zmienStrefe(actionCtx, action)
	case helperv1.FirewallRequest_OPERATION_RULE_ENSURE,
		helperv1.FirewallRequest_OPERATION_RULE_REMOVE:
		return s.zmienReguly(actionCtx, action)
	}
	return reject(ErrorUnknownAction, "nieznana operacja na zaporze")
}

// zmienReguly zaklada albo usuwa regule panelu i przebudowuje tablice.
func (s *Server) zmienReguly(ctx context.Context, action *helperv1.FirewallRequest) *helperv1.HelperResponse {
	if !exists(firewall.SciezkaNft) {
		return reject(ErrorUnsupported, "ten host nie ma nftables")
	}

	stan := s.czytajZapore(ctx)
	// Zmiana zlecona wobec innego zestawu regul nie jest ta sama zmiana,
	// ktora operator ogladal w planie.
	if oczekiwany := action.GetExpectedHash(); oczekiwany != "" && oczekiwany != stan.Hash {
		return reject(ErrorPreconditionFailed, fmt.Sprintf(
			"zestaw regul zmienil sie od czasu planu (%s zamiast %s)", stan.Hash, oczekiwany))
	}

	rejestr, err := firewall.WczytajRejestr(firewall.KatalogRejestru)
	if err != nil {
		return reject(ErrorExecFailed, "odczyt rejestru regul: "+err.Error())
	}
	poprzedni := rejestr

	if action.GetOperation() == helperv1.FirewallRequest_OPERATION_RULE_ENSURE {
		regula := firewall.RuleSpec{
			ID: action.GetRuleId(), Chain: action.GetChain(), Action: action.GetAction(),
			Protocol: action.GetProtocol(), Ports: action.GetPorts(),
			Sources: action.GetSources(), Interface: action.GetInterface(),
			Comment: action.GetComment(),
		}
		if err := regula.Waliduj(); err != nil {
			return reject(ErrorMalformed, err.Error())
		}
		// Kanal zarzadzania jest jedyna rzecza, ktorej nie wolno stracic:
		// bez niego host przestaje odpowiadac i nie ma czym cofnac zmiany.
		if !action.GetBreakGlass() {
			if err := firewall.ChroniKanalZarzadzania(regula,
				action.GetManagementAddress(), int(action.GetManagementPort())); err != nil {
				return reject(ErrorUnsupported, err.Error()+
					"; swiadome przelamanie wymaga jawnej zgody operatora")
			}
		}
		rejestr = rejestr.Ustaw(regula)
	} else {
		nowy, znaleziona := rejestr.Usun(action.GetRuleId())
		if !znaleziona {
			return reject(ErrorUnsupported, "regula "+action.GetRuleId()+" nie nalezy do panelu")
		}
		rejestr = nowy
	}
	rejestr.UpdatedAt = time.Now().UTC()

	plan, odpowiedz := s.uzbrojWycofanieZapory(ctx, poprzedni, action.GetRollbackSeconds())
	if odpowiedz != nil {
		return odpowiedz
	}
	if err := s.przebudujTablice(ctx, rejestr); err != nil {
		// Wycofanie zostaje uzbrojone: doprowadzi tablice do stanu sprzed
		// zmiany takze wtedy, gdy przebudowa stanela w polowie.
		odpowiedz := reject(ErrorExecFailed, err.Error())
		odpowiedz.FirewallResult = &helperv1.FirewallResult{
			Message:          err.Error(),
			RollbackId:       plan.ID,
			RollbackDeadline: plan.Termin.Format(time.RFC3339),
		}
		return odpowiedz
	}
	if err := firewall.ZapiszRejestr(firewall.KatalogRejestru, rejestr); err != nil {
		return reject(ErrorExecFailed, "zapis rejestru regul: "+err.Error())
	}

	return odpowiedzZapory(s.czytajZapore(ctx),
		fmt.Sprintf("reguly przebudowane; wycofanie o %s, jesli agent nie potwierdzi lacznosci",
			plan.Termin.Format(time.RFC3339)), &plan)
}

// zmienStrefe otwiera albo zamyka port lub usluge w strefie firewalld.
func (s *Server) zmienStrefe(ctx context.Context, action *helperv1.FirewallRequest) *helperv1.HelperResponse {
	if !exists(firewall.SciezkaFirewallCmd) {
		return reject(ErrorUnsupported, "ten host nie ma firewalld")
	}

	var kroki [][]string
	var err error
	if action.GetOperation() == helperv1.FirewallRequest_OPERATION_ZONE_PORT {
		if len(action.GetPorts()) != 1 {
			return reject(ErrorMalformed, "operacja dotyczy dokladnie jednego portu")
		}
		// Zamkniecie portu, ktorym host rozmawia z panelem, odcina panel.
		if !action.GetEnable() && !action.GetBreakGlass() &&
			action.GetPorts()[0] == strconv.Itoa(int(action.GetManagementPort())) {
			return reject(ErrorUnsupported,
				"port "+action.GetPorts()[0]+" jest kanalem zarzadzania; "+
					"swiadome zamkniecie wymaga jawnej zgody operatora")
		}
		kroki, err = firewall.ArgumentyOtwarciaPortu(action.GetZone(), action.GetPorts()[0],
			action.GetProtocol(), action.GetEnable())
	} else {
		kroki, err = firewall.ArgumentyUslugi(action.GetZone(), action.GetService(), action.GetEnable())
	}
	if err != nil {
		return reject(ErrorMalformed, err.Error())
	}

	for _, krok := range kroki {
		if wyjscie, err := uruchomNarzedzie(ctx, krok); err != nil {
			return reject(ErrorExecFailed, err.Error()+": "+wyjscie)
		}
	}
	return odpowiedzZapory(s.czytajZapore(ctx), "strefa zmieniona", nil)
}

// przebudujTablice odtwarza tablice panelu z rejestru.
func (s *Server) przebudujTablice(ctx context.Context, rejestr firewall.Rejestr) error {
	if len(rejestr.Rules) == 0 {
		// Pusta tablica z zaczepionymi lancuchami niczego nie filtruje, ale
		// zostawia obiekt, ktorego nikt nie potrzebuje.
		_, _ = uruchomNarzedzie(ctx, firewall.ArgumentyUsunieciaTablicy())
		return nil
	}
	kroki, err := firewall.ArgumentyPrzebudowy(rejestr)
	if err != nil {
		return err
	}
	for _, krok := range kroki {
		if wyjscie, err := uruchomNarzedzie(ctx, krok); err != nil {
			return fmt.Errorf("%s: %w: %s", strings.Join(krok, " "), err, wyjscie)
		}
	}
	return nil
}

// uzbrojWycofanieZapory zapisuje rejestr sprzed zmiany i uruchamia zegar.
func (s *Server) uzbrojWycofanieZapory(ctx context.Context, poprzedni firewall.Rejestr,
	sekundy uint32) (planZapory, *helperv1.HelperResponse) {
	plan := planZapory{
		ID:        identyfikatorWycofania(),
		Rejestr:   poprzedni,
		Utworzony: time.Now().UTC(),
	}
	okno := oknoWycofania(sekundy)
	plan.Termin = plan.Utworzony.Add(okno)

	if err := zapiszPlanZapory(plan); err != nil {
		return plan, reject(ErrorExecFailed, "zapis planu wycofania: "+err.Error())
	}
	if err := s.uzbrojZegar(ctx, "flotestro-zapora-"+plan.ID, okno, "-rollback-firewall", plan.ID); err != nil {
		_ = usunPlanZapory(plan.ID)
		return plan, reject(ErrorExecFailed, "uzbrojenie wycofania: "+err.Error())
	}
	return plan, nil
}

// potwierdzZapore rozbraja zegar po potwierdzeniu lacznosci.
func (s *Server) potwierdzZapore(ctx context.Context, id string) *helperv1.HelperResponse {
	if _, err := wczytajPlanZapory(id); err != nil {
		return odpowiedzZapory(s.czytajZapore(ctx),
			"nie ma czego rozbrajac: wycofanie "+id+" juz nie istnieje", nil)
	}
	_ = s.rozbrojZegar(ctx, "flotestro-zapora-"+id)
	if err := usunPlanZapory(id); err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	odpowiedz := odpowiedzZapory(s.czytajZapore(ctx), "zmiana zapory potwierdzona", nil)
	odpowiedz.FirewallResult.Confirmed = true
	return odpowiedz
}

// przywrocZapore wraca do rejestru sprzed zmiany na zadanie operatora.
func (s *Server) przywrocZapore(ctx context.Context, id string) *helperv1.HelperResponse {
	plan, err := wczytajPlanZapory(id)
	if err != nil {
		return reject(ErrorUnsupported, "nie ma planu wycofania "+id)
	}
	if err := s.przebudujTablice(ctx, plan.Rejestr); err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	if err := firewall.ZapiszRejestr(firewall.KatalogRejestru, plan.Rejestr); err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	_ = s.rozbrojZegar(ctx, "flotestro-zapora-"+id)
	_ = usunPlanZapory(id)
	return odpowiedzZapory(s.czytajZapore(ctx), "reguly przywrocone na zadanie", nil)
}

// czytajZapore sklada obraz zapory hosta.
func (s *Server) czytajZapore(ctx context.Context) firewall.Snapshot {
	snapshot := firewall.Snapshot{ObservedAt: time.Now().UTC()}

	if !exists(firewall.SciezkaNft) {
		snapshot.UnavailableReason = "this host has no nftables (nft) binary"
		return snapshot
	}
	// Ostrzezenia o tablicach nalezacych do innych programow nft wypisuje na
	// strumien bledu, a nie na wyjscie. Bez nich panel uznalby tablice
	// dockera za zwykle tablice hosta - i pozwolilby ich dotykac.
	wyjscie, ostrzezenia, err := wyjscieZOstrzezeniami(ctx, firewall.SciezkaNft, "-a", "list", "ruleset")
	if err != nil {
		snapshot.UnavailableReason = "nft list ruleset: " + err.Error()
		return snapshot
	}
	snapshot = firewall.ParsujRuleset(ostrzezenia + wyjscie)
	snapshot.ObservedAt = time.Now().UTC()
	snapshot.Writable = true

	// Firewalld trzyma wlasne tablice i przepisuje je przy przeladowaniu,
	// wiec na takim hoscie mowimy o strefach, a nie o regulach panelu.
	if exists(firewall.SciezkaFirewallCmd) {
		domyslna, _ := wyjscieNarzedzia(ctx, firewall.SciezkaFirewallCmd, "--get-default-zone")
		if strefy, err := wyjscieNarzedzia(ctx, firewall.SciezkaFirewallCmd, "--list-all-zones"); err == nil {
			snapshot.Zones = firewall.ParsujStrefy(strefy, strings.TrimSpace(domyslna))
			snapshot.Adapter = firewall.AdapterFirewalld
		}
	}
	return snapshot
}

// planZapory to rejestr regul sprzed zmiany wraz z terminem powrotu.
type planZapory struct {
	ID        string           `json:"id"`
	Rejestr   firewall.Rejestr `json:"registry"`
	Utworzony time.Time        `json:"created_at"`
	Termin    time.Time        `json:"deadline"`
}

func sciezkaPlanuZapory(id string) (string, error) {
	if !poprawnyIdentyfikatorPlanu(id) {
		return "", fmt.Errorf("nieprawidlowy identyfikator planu %q", id)
	}
	return filepath.Join(firewall.KatalogRejestru, id+rozszerzeniePlanuZapory), nil
}

func zapiszPlanZapory(plan planZapory) error {
	if err := os.MkdirAll(firewall.KatalogRejestru, 0o700); err != nil {
		return err
	}
	sciezka, err := sciezkaPlanuZapory(plan.ID)
	if err != nil {
		return err
	}
	dane, err := json.Marshal(plan)
	if err != nil {
		return err
	}
	tymczasowy := sciezka + ".nowy"
	if err := os.WriteFile(tymczasowy, dane, 0o600); err != nil {
		return err
	}
	return os.Rename(tymczasowy, sciezka)
}

func wczytajPlanZapory(id string) (planZapory, error) {
	sciezka, err := sciezkaPlanuZapory(id)
	if err != nil {
		return planZapory{}, err
	}
	dane, err := os.ReadFile(sciezka)
	if err != nil {
		return planZapory{}, err
	}
	var plan planZapory
	if err := json.Unmarshal(dane, &plan); err != nil {
		return planZapory{}, err
	}
	return plan, nil
}

func usunPlanZapory(id string) error {
	sciezka, err := sciezkaPlanuZapory(id)
	if err != nil {
		return err
	}
	if err := os.Remove(sciezka); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// WycofajZapore przywraca reguly panelu sprzed zmiany.
//
// Wolane przez przejsciowa jednostke systemd, gdy nikt nie potwierdzil
// lacznosci po zmianie zapory. Dziala bez agenta i bez panelu.
func WycofajZapore(ctx context.Context, id string) error {
	plan, err := wczytajPlanZapory(id)
	if err != nil {
		return fmt.Errorf("plan wycofania %s: %w", id, err)
	}
	serwer := &Server{}
	if err := serwer.przebudujTablice(ctx, plan.Rejestr); err != nil {
		return err
	}
	if err := firewall.ZapiszRejestr(firewall.KatalogRejestru, plan.Rejestr); err != nil {
		return err
	}
	return usunPlanZapory(id)
}

func odpowiedzZapory(snapshot firewall.Snapshot, komunikat string, plan *planZapory) *helperv1.HelperResponse {
	zakodowane, err := json.Marshal(snapshot)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	wynik := &helperv1.FirewallResult{Snapshot: zakodowane, Message: komunikat}
	if plan != nil {
		wynik.RollbackId = plan.ID
		wynik.RollbackDeadline = plan.Termin.Format(time.RFC3339)
	}
	return &helperv1.HelperResponse{Accepted: true, FirewallResult: wynik}
}

func uruchomNarzedzie(ctx context.Context, argumenty []string) (string, error) {
	cmd := exec.CommandContext(ctx, argumenty[0], argumenty[1:]...)
	cmd.Env = srodowiskoNarzedzi()
	wyjscie, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(wyjscie)), err
}

// wyjscieNarzedzia uruchamia narzedzie i dolacza jego komunikat bledu.
//
// Sam kod wyjscia nie mowi nic: "exit status 3" z nft moze znaczyc brak
// gniazda netlink, brak tablicy albo blad skladni, a operator ma przeczytac,
// ktore z nich.
func wyjscieNarzedzia(ctx context.Context, sciezka string, argumenty ...string) (string, error) {
	wyjscie, _, err := wyjscieZOstrzezeniami(ctx, sciezka, argumenty...)
	return wyjscie, err
}

// wyjscieZOstrzezeniami zwraca oba strumienie osobno.
//
// Strumien bledu bywa trescia odpowiedzi, a nie szumem: nft pisze tam
// ostrzezenia o cudzych tablicach, a przy bledzie - powod. Sam kod wyjscia
// nie mowi nic: "exit status 3" moze znaczyc brak gniazda netlink, brak
// tablicy albo blad skladni.
func wyjscieZOstrzezeniami(ctx context.Context, sciezka string, argumenty ...string) (string, string, error) {
	cmd := exec.CommandContext(ctx, sciezka, argumenty...)
	cmd.Env = srodowiskoNarzedzi()
	var blad strings.Builder
	cmd.Stderr = &blad
	wyjscie, err := cmd.Output()
	komunikat := blad.String()
	if err != nil {
		if tresc := strings.TrimSpace(komunikat); tresc != "" {
			return "", komunikat, fmt.Errorf("%w: %s", err, tresc)
		}
		return "", komunikat, err
	}
	return string(wyjscie), komunikat, nil
}

func exists(sciezka string) bool {
	_, err := os.Stat(sciezka)
	return err == nil
}
