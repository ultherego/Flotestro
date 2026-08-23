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
	"github.com/ultherego/flotestro/internal/modules/network"
)

// Zakres zegara wycofania. Za krotki nie da agentowi szansy na potwierdzenie
// lacznosci, za dlugi zostawia host odciety na kwadranse.
const (
	wycofanieDomyslne = 120 * time.Second
	wycofanieMin      = 30 * time.Second
	wycofanieMax      = 15 * time.Minute
)

// applyNetwork obsluguje zmiany konfiguracji sieci.
//
// Kazda zmiana jest uzbrajana wycofaniem, zanim host jej dozna: helper zapisuje
// stan sprzed zmiany i uruchamia przejsciowy zegar systemd, ktory ten stan
// przywroci. Zegar rozbraja dopiero potwierdzenie od agenta, ze host nadal
// rozmawia z panelem. Odwrotna kolejnosc zostawialaby okno, w ktorym host jest
// juz odciety, a nic go nie ratuje.
func (s *Server) applyNetwork(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.NetworkRequest) *helperv1.HelperResponse {
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

	if !network.Istnieje(network.SciezkaNmcli) {
		return reject(ErrorUnsupported,
			"ten host nie ma NetworkManagera; konfiguracja sieci jest tu tylko do odczytu")
	}

	switch action.GetOperation() {
	case helperv1.NetworkRequest_OPERATION_READ:
		return odpowiedzSieci(s.czytajProfile(actionCtx), "", nil)

	case helperv1.NetworkRequest_OPERATION_CONFIRM:
		return s.potwierdzZmiane(actionCtx, action.GetRollbackId())

	case helperv1.NetworkRequest_OPERATION_ROLLBACK:
		return s.wycofajTeraz(actionCtx, action.GetRollbackId())

	case helperv1.NetworkRequest_OPERATION_SET_MTU,
		helperv1.NetworkRequest_OPERATION_ENSURE_ROUTES,
		helperv1.NetworkRequest_OPERATION_APPLY_PROFILE:
		return s.zmienSiec(actionCtx, action)
	}
	return reject(ErrorUnknownAction, "nieznana operacja na sieci")
}

// zmienSiec sklada zmiane, uzbraja wycofanie i dopiero potem dotyka hosta.
func (s *Server) zmienSiec(ctx context.Context, action *helperv1.NetworkRequest) *helperv1.HelperResponse {
	polaczenie, profil, err := s.profilInterfejsu(ctx, action.GetInterface())
	if err != nil {
		return reject(ErrorUnsupported, err.Error())
	}

	kroki, err := krokiZmiany(action, polaczenie, profil)
	if err != nil {
		// Konfiguracja, ktorej host nie przyjmie, jest wada zlecenia,
		// a nie awaria wykonania.
		return reject(ErrorMalformed, err.Error())
	}

	// Plan wycofania powstaje ze stanu odczytanego przed zmiana. Zapisujemy go
	// na dysk, bo helper konczy prace po okresie bezczynnosci - zegar w jego
	// pamieci zniknalby razem z procesem.
	plan := network.PlanWycofania{
		ID:           identyfikatorWycofania(),
		Profil:       profil,
		Interfejs:    action.GetInterface(),
		Zarzadzajacy: false,
		Utworzony:    time.Now().UTC(),
		Powod:        action.GetReason(),
	}
	okno := oknoWycofania(action.GetRollbackSeconds())
	plan.Termin = plan.Utworzony.Add(okno)

	if _, err := network.KrokiWycofania(plan); err != nil {
		// Bez sprawdzonej drogi powrotnej zmiany nie robimy w ogole.
		return reject(ErrorUnsupported, "nie da sie zlozyc wycofania: "+err.Error())
	}
	if err := network.ZapiszPlan(network.KatalogWycofan, plan); err != nil {
		return reject(ErrorExecFailed, "zapis planu wycofania: "+err.Error())
	}
	if err := s.uzbrojWycofanie(ctx, plan, okno); err != nil {
		_ = network.UsunPlan(network.KatalogWycofan, plan.ID)
		return reject(ErrorExecFailed, "uzbrojenie wycofania: "+err.Error())
	}

	for _, krok := range kroki {
		if wyjscie, err := uruchomNmcli(ctx, krok); err != nil {
			// Zmiana, ktora sie nie udala, zostawia host w stanie posrednim.
			// Wycofanie zostaje uzbrojone i doprowadzi go do konca.
			return odpowiedzBleduSieci(plan, fmt.Sprintf("%s: %s", err, wyjscie))
		}
	}

	return odpowiedzSieci(s.czytajProfile(ctx),
		fmt.Sprintf("zmiana zastosowana; wycofanie o %s, jesli agent nie potwierdzi lacznosci",
			plan.Termin.Format(time.RFC3339)), &plan)
}

// krokiZmiany sklada polecenia dla konkretnej operacji.
func krokiZmiany(action *helperv1.NetworkRequest, polaczenie string,
	obecny network.Profil) ([][]string, error) {
	switch action.GetOperation() {
	case helperv1.NetworkRequest_OPERATION_SET_MTU:
		return network.ArgumentyMTU(polaczenie, action.GetMtu())
	case helperv1.NetworkRequest_OPERATION_ENSURE_ROUTES:
		return network.ArgumentyTras(polaczenie, action.GetRoutes())
	case helperv1.NetworkRequest_OPERATION_APPLY_PROFILE:
		docelowy := network.Profil{
			Polaczenie: polaczenie,
			Metoda:     action.GetMethod(),
			Adresy:     action.GetAddresses(),
			Brama:      action.GetGateway(),
			DNS:        action.GetDns(),
			// Trasy i MTU zostaja takie, jakie byly: profil adresowy jest
			// osobna operacja i nie moze po cichu skasowac ustawien,
			// o ktorych operator nie byl pytany.
			Trasy: obecny.Trasy,
			MTU:   obecny.MTU,
		}
		return network.ArgumentyProfilu(docelowy)
	}
	return nil, fmt.Errorf("nieznana operacja na sieci")
}

// potwierdzZmiane rozbraja wycofanie po tym, jak agent potwierdzil lacznosc.
func (s *Server) potwierdzZmiane(ctx context.Context, id string) *helperv1.HelperResponse {
	plan, err := network.WczytajPlan(network.KatalogWycofan, id)
	if err != nil {
		// Brak planu oznacza wycofanie juz wykonane albo juz rozbrojone.
		// To nie jest blad zlecenia, ale operator ma to wiedziec.
		return odpowiedzSieci(s.czytajProfile(ctx),
			"nie ma czego rozbrajac: wycofanie "+id+" juz nie istnieje", nil)
	}
	if err := s.rozbrojWycofanie(ctx, plan.ID); err != nil {
		return reject(ErrorExecFailed, "rozbrojenie wycofania: "+err.Error())
	}
	if err := network.UsunPlan(network.KatalogWycofan, plan.ID); err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	odpowiedz := odpowiedzSieci(s.czytajProfile(ctx), "zmiana potwierdzona", nil)
	odpowiedz.NetworkResult.Confirmed = true
	return odpowiedz
}

// wycofajTeraz przywraca stan sprzed zmiany na zadanie operatora.
func (s *Server) wycofajTeraz(ctx context.Context, id string) *helperv1.HelperResponse {
	plan, err := network.WczytajPlan(network.KatalogWycofan, id)
	if err != nil {
		return reject(ErrorUnsupported, "nie ma planu wycofania "+id)
	}
	kroki, err := network.KrokiWycofania(plan)
	if err != nil {
		return reject(ErrorUnsupported, err.Error())
	}
	for _, krok := range kroki {
		if wyjscie, err := uruchomNmcli(ctx, krok); err != nil {
			return reject(ErrorExecFailed, fmt.Sprintf("%s: %s", err, wyjscie))
		}
	}
	_ = s.rozbrojWycofanie(ctx, plan.ID)
	_ = network.UsunPlan(network.KatalogWycofan, plan.ID)
	return odpowiedzSieci(s.czytajProfile(ctx), "zmiana wycofana na zadanie", nil)
}

// uzbrojWycofanie uruchamia przejsciowy zegar systemd.
//
// Zegar zyje poza helperem: helper konczy prace po okresie bezczynnosci,
// a wycofanie ma zadzialac takze wtedy, gdy nikt juz do niego nie mowi.
// Jednostka wola ten sam binarny helper w trybie wycofania - polecenie nie
// pochodzi z planu, wiec plan nie moze wyrazic niczego innego.
func (s *Server) uzbrojWycofanie(ctx context.Context, plan network.PlanWycofania, okno time.Duration) error {
	systemdRun, err := exec.LookPath("systemd-run")
	if err != nil {
		return fmt.Errorf("host bez systemd-run nie potrafi uzbroic wycofania")
	}
	binarny, err := sciezkaHelpera()
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, systemdRun,
		"--collect", "--quiet",
		"--unit="+network.NazwaJednostkiWycofania(plan.ID),
		"--description=Flotestro: wycofanie zmiany sieci",
		"--on-active="+strconv.Itoa(int(okno.Seconds())),
		"--timer-property=AccuracySec=1s",
		"--", binarny, "-rollback", plan.ID)
	cmd.Env = srodowiskoNarzedzi()
	if wyjscie, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(wyjscie)))
	}
	return nil
}

// rozbrojWycofanie zatrzymuje zegar wycofania.
func (s *Server) rozbrojWycofanie(ctx context.Context, id string) error {
	jednostka := network.NazwaJednostkiWycofania(id)
	for _, nazwa := range []string{jednostka + ".timer", jednostka + ".service"} {
		cmd := exec.CommandContext(ctx, "/usr/bin/systemctl", "stop", nazwa)
		cmd.Env = srodowiskoNarzedzi()
		_ = cmd.Run()
	}
	return nil
}

// czytajProfile zbiera profile NetworkManagera wraz z ustawieniami.
func (s *Server) czytajProfile(ctx context.Context) []network.Profil {
	wyjscie, err := wyjscieNmcli(ctx, "-t", "-f", "NAME,UUID,DEVICE,TYPE,STATE", "connection", "show")
	if err != nil {
		return nil
	}
	var profile []network.Profil
	for _, polaczenie := range network.ParsujPolaczenia(wyjscie) {
		ustawienia, err := wyjscieNmcli(ctx, "-t", "-f",
			strings.Join(network.PolaProfilu, ","), "connection", "show", polaczenie.Nazwa)
		if err != nil {
			continue
		}
		profil := network.ParsujProfil(ustawienia)
		if profil.Polaczenie == "" {
			profil.Polaczenie = polaczenie.Nazwa
		}
		if profil.Interfejs == "" {
			profil.Interfejs = polaczenie.Urzadzenie
		}
		profile = append(profile, profil)
	}
	return profile
}

// profilInterfejsu znajduje profil aktywny na interfejsie.
func (s *Server) profilInterfejsu(ctx context.Context, interfejs string) (string, network.Profil, error) {
	if interfejs == "" {
		return "", network.Profil{}, fmt.Errorf("operacja wymaga nazwy interfejsu")
	}
	wyjscie, err := wyjscieNmcli(ctx, "-t", "-f", "NAME,UUID,DEVICE,TYPE,STATE", "connection", "show")
	if err != nil {
		return "", network.Profil{}, fmt.Errorf("odczyt polaczen: %w", err)
	}
	polaczenie := network.PolaczenieUrzadzenia(network.ParsujPolaczenia(wyjscie), interfejs)
	if polaczenie == nil {
		return "", network.Profil{}, fmt.Errorf(
			"interfejs %s nie ma profilu NetworkManagera; panel nie tworzy tu nowych profili", interfejs)
	}
	ustawienia, err := wyjscieNmcli(ctx, "-t", "-f",
		strings.Join(network.PolaProfilu, ","), "connection", "show", polaczenie.Nazwa)
	if err != nil {
		return "", network.Profil{}, fmt.Errorf("odczyt profilu %s: %w", polaczenie.Nazwa, err)
	}
	profil := network.ParsujProfil(ustawienia)
	if profil.Polaczenie == "" {
		profil.Polaczenie = polaczenie.Nazwa
	}
	return polaczenie.Nazwa, profil, nil
}

func oknoWycofania(sekundy uint32) time.Duration {
	if sekundy == 0 {
		return wycofanieDomyslne
	}
	okno := time.Duration(sekundy) * time.Second
	if okno < wycofanieMin {
		return wycofanieMin
	}
	if okno > wycofanieMax {
		return wycofanieMax
	}
	return okno
}

// identyfikatorWycofania sklada nazwe planu z chwili jego powstania.
// Nazwa jest czescia nazwy pliku i jednostki systemd, wiec ma waski zbior
// znakow.
func identyfikatorWycofania() string {
	return "w" + strconv.FormatInt(time.Now().UTC().UnixNano(), 36)
}

func uruchomNmcli(ctx context.Context, argumenty []string) (string, error) {
	cmd := exec.CommandContext(ctx, argumenty[0], argumenty[1:]...)
	cmd.Env = srodowiskoNarzedzi()
	wyjscie, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(wyjscie)), err
}

func wyjscieNmcli(ctx context.Context, argumenty ...string) (string, error) {
	cmd := exec.CommandContext(ctx, network.SciezkaNmcli, argumenty...)
	cmd.Env = srodowiskoNarzedzi()
	wyjscie, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(wyjscie), nil
}

func srodowiskoNarzedzi() []string {
	return []string{"LC_ALL=C", "LANG=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
}

func odpowiedzSieci(profile []network.Profil, komunikat string,
	plan *network.PlanWycofania) *helperv1.HelperResponse {
	zakodowane, err := json.Marshal(struct {
		Profile []network.Profil `json:"profiles"`
	}{profile})
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	wynik := &helperv1.NetworkResult{Profiles: zakodowane, Message: komunikat}
	if plan != nil {
		wynik.RollbackId = plan.ID
		wynik.RollbackDeadline = plan.Termin.Format(time.RFC3339)
	}
	return &helperv1.HelperResponse{Accepted: true, NetworkResult: wynik}
}

// odpowiedzBleduSieci opisuje zmiane, ktora sie nie udala, ale zostawila
// uzbrojone wycofanie. Operator ma wiedziec, ze host wroci sam.
func odpowiedzBleduSieci(plan network.PlanWycofania, komunikat string) *helperv1.HelperResponse {
	odpowiedz := reject(ErrorExecFailed, komunikat)
	odpowiedz.NetworkResult = &helperv1.NetworkResult{
		Message:          komunikat,
		RollbackId:       plan.ID,
		RollbackDeadline: plan.Termin.Format(time.RFC3339),
	}
	return odpowiedz
}

// sciezkaHelpera zwraca sciezke wlasnego binarnego pliku.
//
// Jednostka wycofania musi wolac dokladnie ten sam program, ktory zmiane
// zaczal: sciezka szukana w PATH mogla by w miedzyczasie wskazac co innego.
func sciezkaHelpera() (string, error) {
	sciezka, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("nie ustalono sciezki helpera: %w", err)
	}
	return filepath.EvalSymlinks(sciezka)
}

// WycofajZPlanu przywraca stan sprzed zmiany sieci. Wolane przez przejsciowa
// jednostke systemd, gdy nikt nie potwierdzil lacznosci w zadanym oknie.
//
// Funkcja dziala bez agenta i bez panelu: to ostatnia rzecz, ktora dziala,
// gdy zmiana odetnie host od swiata.
func WycofajZPlanu(ctx context.Context, id string) error {
	plan, err := network.WczytajPlan(network.KatalogWycofan, id)
	if err != nil {
		return fmt.Errorf("plan wycofania %s: %w", id, err)
	}
	kroki, err := network.KrokiWycofania(plan)
	if err != nil {
		_ = network.OdlozNieudanyPlan(network.KatalogWycofan, id)
		return err
	}
	for _, krok := range kroki {
		if wyjscie, err := uruchomNmcli(ctx, krok); err != nil {
			// Plan, ktorego zegar juz wybil, jest martwy takze wtedy, gdy
			// wycofanie sie nie udalo. Zostawiony w katalogu wygladalby jak
			// wycofanie wciaz czekajace na swoja chwile.
			_ = network.OdlozNieudanyPlan(network.KatalogWycofan, id)
			return fmt.Errorf("%s: %w: %s", strings.Join(krok, " "), err, wyjscie)
		}
	}
	return network.UsunPlan(network.KatalogWycofan, id)
}
