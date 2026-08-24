package helper

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	czas "github.com/ultherego/flotestro/internal/modules/time"
)

// oknoSynchronizacji ogranicza czekanie na demona po zmianie zrodel.
//
// Zapis i skutek to dwie rozne rzeczy: plik z serwerami nie jest jeszcze
// zsynchronizowanym zegarem. Z iburst pierwsza wymiana zajmuje kilka sekund,
// wiec czekamy tyle, zeby odpowiedziec na pytanie "czy zadzialalo", i nie
// dluzej, zeby nie trzymac zadania w nieskonczonosc.
const (
	oknoSynchronizacji = 45 * time.Second
	krokSynchronizacji = 5 * time.Second

	sciezkaSystemctl = "/usr/bin/systemctl"
)

// applyTime obsluguje operacje na czasie hosta.
func (s *Server) applyTime(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.TimeRequest) *helperv1.HelperResponse {
	timeout := time.Duration(request.GetTimeoutSeconds()) * time.Second
	if timeout <= 0 || timeout > 30*time.Minute {
		timeout = 5 * time.Minute
	}
	actionCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	switch action.GetOperation() {
	case helperv1.TimeRequest_OPERATION_CONFIG_APPLY:
		return s.zapiszSerweryCzasu(actionCtx, action)
	case helperv1.TimeRequest_OPERATION_TIMEZONE_SET:
		return s.ustawStrefe(actionCtx, action)
	}
	return reject(ErrorUnknownAction, "nieznana operacja na czasie")
}

// zapiszSerweryCzasu zapisuje zrodla czasu i przeladowuje demona.
func (s *Server) zapiszSerweryCzasu(ctx context.Context, action *helperv1.TimeRequest) *helperv1.HelperResponse {
	serwery := action.GetServers()
	// Postac wpisow sprawdzamy tu jeszcze raz, mimo ze panel juz to zrobil:
	// helper jest ostatnia bramka przed zapisem jako root i nie bierze na
	// wiare tego, co przyszlo z gory.
	if err := czas.WalidujSerwery(serwery); err != nil {
		return reject(ErrorMalformed, err.Error())
	}

	snapshot := czas.Zbierz(ctx, wyjscieNarzedzia)
	switch snapshot.Service {
	case czas.DemonChrony:
		return s.zapiszChrony(ctx, serwery, snapshot, action.GetEnableDropin())
	case czas.DemonTimesyncd:
		return s.zapiszTimesyncd(ctx, serwery)
	}
	return reject(ErrorUnsupported,
		"ten host nie ma demona czasu, ktoremu panel moglby wskazac serwery")
}

// zapiszChrony dopisuje serwery do katalogu, ktory chrony sam wlacza.
func (s *Server) zapiszChrony(ctx context.Context, serwery []string,
	snapshot czas.Snapshot, zgodaNaKatalog bool) *helperv1.HelperResponse {
	// Host, ktory nie wlacza zadnego katalogu, da sie doprowadzic do stanu
	// zapisywalnego jednym dopisanym wierszem - ale tylko za jawna zgoda:
	// to jedyne miejsce, w ktorym panel dotyka cudzej konfiguracji.
	wymaganyRestart := false
	if snapshot.ManagedPath == "" {
		if !zgodaNaKatalog {
			powod := snapshot.WriteReason
			if powod == "" {
				powod = "chrony na tym hoscie nie wlacza zadnego katalogu konfiguracji"
			}
			return reject(ErrorUnsupported, powod)
		}
		if odmowa := wlaczKatalogZrodel(snapshot); odmowa != nil {
			return odmowa
		}
		snapshot.ManagedPath = filepath.Join(czas.KatalogZrodelPanelu,
			czas.NazwaPlikuChrony(czas.RodzajZrodel))
		// Zmiana glownego pliku obowiazuje dopiero po starcie demona;
		// przeladowanie samych zrodel go nie przeczyta.
		wymaganyRestart = true
	}
	rodzaj := czas.RodzajKonfiguracji
	if filepath.Ext(snapshot.ManagedPath) == ".sources" {
		rodzaj = czas.RodzajZrodel
	}
	tresc, err := czas.SkladajChrony(serwery, rodzaj)
	if err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	if err := os.MkdirAll(filepath.Dir(snapshot.ManagedPath), 0o755); err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	poprzednia, _ := os.ReadFile(snapshot.ManagedPath)
	if err := zapiszPlikJadra(snapshot.ManagedPath, tresc, 0o644); err != nil {
		return reject(ErrorExecFailed, "zapis "+snapshot.ManagedPath+": "+err.Error())
	}

	// Katalog zrodel demon przeladowuje bez restartu, wiec host nie traci
	// synchronizacji na czas zmiany. Katalog konfiguracji wymaga restartu.
	komunikat := "serwery zapisane"
	if rodzaj == czas.RodzajZrodel && !wymaganyRestart {
		if wyjscie, err := wyjscieNarzedzia(ctx, czas.SciezkaChronyc, "reload", "sources"); err != nil {
			przywroc(snapshot.ManagedPath, poprzednia)
			return reject(ErrorExecFailed, "chronyc reload sources: "+err.Error()+" "+wyjscie)
		}
		komunikat = "serwery zapisane i przeladowane bez restartu demona"
	} else {
		jednostka := snapshot.Unit
		if jednostka == "" {
			jednostka = "chronyd.service"
		}
		if wyjscie, err := wyjscieNarzedzia(ctx, sciezkaSystemctl, "restart", jednostka); err != nil {
			// Demon, ktory nie wstaje z nowa konfiguracja, zostawilby host
			// bez zegara. Wracamy do poprzedniej tresci i podnosimy go
			// z powrotem, zanim zglosimy blad.
			przywroc(snapshot.ManagedPath, poprzednia)
			_, _ = wyjscieNarzedzia(ctx, sciezkaSystemctl, "restart", jednostka)
			return reject(ErrorExecFailed, "restart "+jednostka+": "+err.Error()+" "+wyjscie)
		}
		komunikat = "serwery zapisane, demon zrestartowany"
	}

	po, zsynchronizowany := poczekajNaSynchronizacje(ctx)
	return odpowiedzCzasu(po, komunikat+"; "+opisSynchronizacji(po, zsynchronizowany))
}

// wlaczKatalogZrodel zaklada katalog panelu i wskazuje go demonowi.
//
// Wiersz dopisujemy w miejscu, a nie przez podmiane pliku: plik nalezy do
// dystrybucji, a dopisanie zachowuje jego wlasciciela, prawa i etykiete
// SELinuksa. Panel niczego tam nie zmienia ani nie usuwa.
func wlaczKatalogZrodel(snapshot czas.Snapshot) *helperv1.HelperResponse {
	if snapshot.ConfigPath == "" {
		return reject(ErrorUnsupported, "nie znaleziono glownego pliku chronyego")
	}
	if err := os.MkdirAll(czas.KatalogZrodelPanelu, 0o755); err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	tresc, err := os.ReadFile(snapshot.ConfigPath)
	if err != nil {
		return reject(ErrorExecFailed, "odczyt "+snapshot.ConfigPath+": "+err.Error())
	}
	// Powtorzone zlecenie nie moze dopisac wiersza drugi raz.
	if czas.MaWpisWlaczenia(string(tresc)) {
		return nil
	}
	plik, err := os.OpenFile(snapshot.ConfigPath, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return reject(ErrorExecFailed, "zapis "+snapshot.ConfigPath+": "+err.Error())
	}
	defer func() { _ = plik.Close() }()
	if _, err := plik.WriteString(czas.WpisWlaczenia()); err != nil {
		return reject(ErrorExecFailed, "zapis "+snapshot.ConfigPath+": "+err.Error())
	}
	return nil
}

// zapiszTimesyncd zapisuje serwery dla systemd-timesyncd.
func (s *Server) zapiszTimesyncd(ctx context.Context, serwery []string) *helperv1.HelperResponse {
	tresc, err := czas.SkladajTimesyncd(serwery)
	if err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	if err := os.MkdirAll(czas.KatalogTimesyncd, 0o755); err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	poprzednia, _ := os.ReadFile(czas.PlikTimesyncd)
	if err := zapiszPlikJadra(czas.PlikTimesyncd, tresc, 0o644); err != nil {
		return reject(ErrorExecFailed, "zapis "+czas.PlikTimesyncd+": "+err.Error())
	}
	// Host z wylaczona synchronizacja ma ja wylaczona takze po zapisie pliku:
	// timesyncd nie chodzi, dopoki timedated go nie wlaczy. Zapis serwerow bez
	// tego kroku wygladalby na udany i nie zrobil nic.
	if exists(czas.SciezkaTimedatectl) {
		if wyjscie, err := wyjscieNarzedzia(ctx, czas.SciezkaTimedatectl, "set-ntp", "true"); err != nil {
			przywroc(czas.PlikTimesyncd, poprzednia)
			return reject(ErrorExecFailed, "timedatectl set-ntp: "+err.Error()+" "+wyjscie)
		}
	}
	if wyjscie, err := wyjscieNarzedzia(ctx, sciezkaSystemctl, "restart", "systemd-timesyncd.service"); err != nil {
		// Jak wyzej: host bez demona czasu jest gorszy niz host ze starymi
		// serwerami, wiec przy bledzie wracamy do poprzedniej tresci.
		przywroc(czas.PlikTimesyncd, poprzednia)
		_, _ = wyjscieNarzedzia(ctx, sciezkaSystemctl, "restart", "systemd-timesyncd.service")
		return reject(ErrorExecFailed, "restart systemd-timesyncd: "+err.Error()+" "+wyjscie)
	}

	po, zsynchronizowany := poczekajNaSynchronizacje(ctx)
	return odpowiedzCzasu(po, "serwery zapisane, demon zrestartowany; "+
		opisSynchronizacji(po, zsynchronizowany))
}

// ustawStrefe zmienia strefe czasowa hosta.
func (s *Server) ustawStrefe(ctx context.Context, action *helperv1.TimeRequest) *helperv1.HelperResponse {
	strefa := action.GetTimezone()
	if err := czas.WalidujStrefe(strefa); err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	// Strefa, ktorej host nie zna, konczy sie bledem narzedzia bez powodu.
	// Sprawdzamy plik strefy, zeby powiedziec wprost, czego brakuje.
	if !exists(czas.SciezkaStrefy(strefa)) {
		return reject(ErrorPreconditionFailed, "ten host nie zna strefy "+strefa)
	}
	if !exists(czas.SciezkaTimedatectl) {
		return reject(ErrorUnsupported, "ten host nie ma timedatectl")
	}
	if wyjscie, err := wyjscieNarzedzia(ctx, czas.SciezkaTimedatectl, "set-timezone", strefa); err != nil {
		return reject(ErrorExecFailed, "timedatectl set-timezone: "+err.Error()+" "+wyjscie)
	}

	// Zapis nie znaczy skutek: pytamy host, jaka strefe ma teraz.
	snapshot := czas.Zbierz(ctx, wyjscieNarzedzia)
	if snapshot.Timezone != strefa {
		return odpowiedzCzasu(snapshot, "polecenie wykonane, ale host zglasza strefe "+
			snapshot.Timezone+" zamiast "+strefa)
	}
	komunikat := "strefa ustawiona na " + strefa
	// Zegar sprzetowy w czasie lokalnym po zmianie strefy pokaze inna
	// godzine przy nastepnym starcie. To fakt o hoscie, nie o operacji.
	if snapshot.RTCInLocalTime != nil && *snapshot.RTCInLocalTime {
		komunikat += "; zegar sprzetowy chodzi w czasie lokalnym, wiec po restarcie host wstanie z przesunieta godzina"
	}
	return odpowiedzCzasu(snapshot, komunikat)
}

// poczekajNaSynchronizacje czeka, az demon wybierze zrodlo.
func poczekajNaSynchronizacje(ctx context.Context) (czas.Snapshot, bool) {
	koniec := time.Now().Add(oknoSynchronizacji)
	snapshot := czas.Zbierz(ctx, wyjscieNarzedzia)
	for time.Now().Before(koniec) {
		if snapshot.Zsynchronizowany() {
			return snapshot, true
		}
		select {
		case <-ctx.Done():
			return snapshot, snapshot.Zsynchronizowany()
		case <-time.After(krokSynchronizacji):
		}
		snapshot = czas.Zbierz(ctx, wyjscieNarzedzia)
	}
	return snapshot, snapshot.Zsynchronizowany()
}

// opisSynchronizacji nazywa stan zegara po zmianie.
func opisSynchronizacji(snapshot czas.Snapshot, zsynchronizowany bool) string {
	if !zsynchronizowany {
		return "host nie zsynchronizowal sie w " + oknoSynchronizacji.String() +
			"; zrodla moga byc nieosiagalne"
	}
	opis := "zegar zsynchronizowany"
	if snapshot.ReferenceName != "" {
		opis += " wzgledem " + snapshot.ReferenceName
	}
	return opis
}

// przywroc oddaje plikowi poprzednia tresc albo usuwa go, gdy go nie bylo.
func przywroc(sciezka string, poprzednia []byte) {
	if len(poprzednia) == 0 {
		_ = os.Remove(sciezka)
		return
	}
	_ = zapiszPlikJadra(sciezka, string(poprzednia), 0o644)
}

func odpowiedzCzasu(snapshot czas.Snapshot, komunikat string) *helperv1.HelperResponse {
	zakodowany, err := json.Marshal(snapshot)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	return &helperv1.HelperResponse{
		Accepted:   true,
		TimeResult: &helperv1.TimeResult{Snapshot: zakodowany, Message: komunikat},
	}
}
