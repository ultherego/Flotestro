package helper

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/kernel"
)

// applyKernel obsluguje operacje na ustawieniach jadra.
func (s *Server) applyKernel(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.KernelRequest) *helperv1.HelperResponse {
	timeout := time.Duration(request.GetTimeoutSeconds()) * time.Second
	if timeout <= 0 || timeout > 30*time.Minute {
		timeout = 5 * time.Minute
	}
	actionCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	switch action.GetOperation() {
	case helperv1.KernelRequest_OPERATION_READ:
		return odpowiedzJadra(s.czytajJadro(actionCtx, action.GetKeys()), "", nil, nil)
	case helperv1.KernelRequest_OPERATION_SYSCTL_ENSURE:
		return s.zapiszSysctl(actionCtx, action)
	case helperv1.KernelRequest_OPERATION_MODULE_LOAD:
		return s.zaladujModul(actionCtx, action)
	case helperv1.KernelRequest_OPERATION_MODULE_BLACKLIST:
		return s.zablokujModul(actionCtx, action)
	}
	return reject(ErrorUnknownAction, "nieznana operacja na jadrze")
}

// zapiszSysctl zapisuje ustawienia trwale i stosuje je od reki.
//
// Zapis i skutek to dwie rozne rzeczy: czesc ustawien jadro przyjmuje
// natychmiast, a czesc dopiero przy starcie. Panel rozdziela je w wyniku,
// zamiast zglaszac sukces i zostawiac operatora z wartoscia, ktora nie
// obowiazuje.
func (s *Server) zapiszSysctl(ctx context.Context, action *helperv1.KernelRequest) *helperv1.HelperResponse {
	ustawienia := action.GetSettings()
	if len(ustawienia) == 0 {
		return reject(ErrorMalformed, "zmiana nie zawiera zadnego ustawienia")
	}
	if !exists(kernel.SciezkaSysctl) {
		return reject(ErrorUnsupported, "ten host nie ma narzedzia sysctl")
	}

	// Klucz, ktorego host nie zna, zostalby w pliku na zawsze i nie zrobil
	// nic. Sprawdzamy istnienie, zanim cokolwiek zapiszemy.
	for klucz := range ustawienia {
		if err := kernel.WalidujKlucz(klucz); err != nil {
			return reject(ErrorMalformed, err.Error())
		}
		if _, err := wyjscieNarzedzia(ctx, kernel.SciezkaSysctl, "-n", klucz); err != nil {
			return reject(ErrorPreconditionFailed,
				"to jadro nie zna ustawienia "+klucz)
		}
	}

	// Do pliku trafia zbior dotychczasowy powiekszony o zmiane: panel
	// zarzadza calym swoim plikiem, wiec zapis jednego klucza nie moze
	// skasowac pozostalych.
	obecne := map[string]string{}
	if tresc, err := os.ReadFile(kernel.PlikSysctl); err == nil {
		obecne = kernel.ParsujPlikSysctl(string(tresc))
	}
	for klucz, wartosc := range ustawienia {
		obecne[klucz] = wartosc
	}
	tresc, err := kernel.SkladajPlikSysctl(obecne)
	if err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	if err := zapiszPlikJadra(kernel.PlikSysctl, tresc, 0o644); err != nil {
		return reject(ErrorExecFailed, "zapis "+kernel.PlikSysctl+": "+err.Error())
	}

	// Stosujemy wylacznie klucze z tej zmiany: przeladowanie calego pliku
	// dotknelo by takze ustawien, o ktore nikt teraz nie prosil.
	var zastosowane, oczekujace []string
	for klucz, wartosc := range ustawienia {
		if _, err := uruchomNarzedzie(ctx,
			[]string{kernel.SciezkaSysctl, "-w", klucz + "=" + wartosc}); err != nil {
			oczekujace = append(oczekujace, klucz+" = "+wartosc)
			continue
		}
		biezaca, err := wyjscieNarzedzia(ctx, kernel.SciezkaSysctl, "-n", klucz)
		if err != nil || strings.Join(strings.Fields(biezaca), " ") != strings.Join(strings.Fields(wartosc), " ") {
			oczekujace = append(oczekujace, klucz+" = "+wartosc)
			continue
		}
		zastosowane = append(zastosowane, klucz+" = "+wartosc)
	}

	komunikat := "ustawienia zapisane i zastosowane"
	if len(oczekujace) > 0 {
		komunikat = "ustawienia zapisane; czesc zadziala dopiero po restarcie"
	}
	return odpowiedzJadra(s.czytajJadro(ctx, nil), komunikat, oczekujace, zastosowane)
}

// zaladujModul laduje modul jadra.
func (s *Server) zaladujModul(ctx context.Context, action *helperv1.KernelRequest) *helperv1.HelperResponse {
	if err := kernel.WalidujModul(action.GetModule()); err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	if !exists(kernel.SciezkaModprobe) {
		return reject(ErrorUnsupported, "ten host nie ma modprobe")
	}
	wyjscie, err := uruchomNarzedzie(ctx, []string{kernel.SciezkaModprobe, action.GetModule()})
	if err != nil {
		return reject(ErrorExecFailed, "modprobe: "+err.Error()+": "+wyjscie)
	}
	return odpowiedzJadra(s.czytajJadro(ctx, nil), "modul "+action.GetModule()+" zaladowany", nil, nil)
}

// zablokujModul dopisuje albo usuwa modul z blokady.
func (s *Server) zablokujModul(ctx context.Context, action *helperv1.KernelRequest) *helperv1.HelperResponse {
	if err := kernel.WalidujModul(action.GetModule()); err != nil {
		return reject(ErrorMalformed, err.Error())
	}

	obecne := []string{}
	if tresc, err := os.ReadFile(kernel.PlikBlacklisty); err == nil {
		obecne = kernel.ParsujBlacklist(string(tresc))
	}
	nowe := make([]string, 0, len(obecne)+1)
	for _, nazwa := range obecne {
		if nazwa != action.GetModule() {
			nowe = append(nowe, nazwa)
		}
	}
	if action.GetBlacklist() {
		nowe = append(nowe, action.GetModule())
	}

	tresc, err := kernel.SkladajBlacklist(nowe)
	if err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	if err := zapiszPlikJadra(kernel.PlikBlacklisty, tresc, 0o644); err != nil {
		return reject(ErrorExecFailed, "zapis "+kernel.PlikBlacklisty+": "+err.Error())
	}

	komunikat := "modul " + action.GetModule() + " odblokowany"
	if action.GetBlacklist() {
		komunikat = "modul " + action.GetModule() + " zablokowany"
		// Blokada nie wyladowuje modulu, ktory juz dziala, a dla modulow
		// wciaganych przez initramfs nie zadziala nawet po restarcie, dopoki
		// initramfs nie zostanie odbudowany. Panel mowi to wprost.
		if powod := kernel.InitramfsWymagany(action.GetModule(), s.modulZaladowany(action.GetModule())); powod != "" {
			komunikat += "; " + powod
		}
	}
	return odpowiedzJadra(s.czytajJadro(ctx, nil), komunikat, nil, nil)
}

// czytajJadro sklada obraz ustawien jadra.
func (s *Server) czytajJadro(ctx context.Context, dodatkowe []string) kernel.Snapshot {
	snapshot := kernel.Snapshot{ObservedAt: time.Now().UTC(), ManagedPath: kernel.PlikSysctl}

	if dane, err := os.ReadFile("/proc/cmdline"); err == nil {
		snapshot.CommandLine = strings.TrimSpace(string(dane))
	}
	if dane, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		snapshot.Release = strings.TrimSpace(string(dane))
	}
	if dane, err := os.ReadFile("/proc/modules"); err == nil {
		snapshot.Modules = kernel.ParsujModuly(string(dane))
	}

	zapisane := map[string]string{}
	if tresc, err := os.ReadFile(kernel.PlikSysctl); err == nil {
		snapshot.Managed = string(tresc)
		zapisane = kernel.ParsujPlikSysctl(string(tresc))
	}
	if tresc, err := os.ReadFile(kernel.PlikBlacklisty); err == nil {
		snapshot.Blacklist = kernel.ParsujBlacklist(string(tresc))
	}
	for i := range snapshot.Modules {
		for _, zablokowany := range snapshot.Blacklist {
			if snapshot.Modules[i].Name == zablokowany {
				snapshot.Modules[i].Blacklisted = true
			}
		}
	}

	// Profil plus to, co panel juz zapisal, plus to, o co poproszono teraz.
	// Enumerowanie calego /proc/sys byloby kosztem bez odpowiedzi.
	klucze := append([]string{}, kernel.ProfilDomyslny...)
	for klucz := range zapisane {
		klucze = append(klucze, klucz)
	}
	klucze = append(klucze, dodatkowe...)
	snapshot.Settings = s.odczytajUstawienia(ctx, klucze, zapisane)
	return snapshot
}

// odczytajUstawienia czyta biezace wartosci wskazanych kluczy.
func (s *Server) odczytajUstawienia(ctx context.Context, klucze []string,
	zapisane map[string]string) []kernel.Ustawienie {
	widziane := map[string]bool{}
	var wynik []kernel.Ustawienie
	for _, klucz := range klucze {
		if widziane[klucz] || kernel.WalidujKlucz(klucz) != nil {
			continue
		}
		widziane[klucz] = true
		ustawienie := kernel.Ustawienie{Key: klucz}
		if wartosc, ok := zapisane[klucz]; ok {
			ustawienie.Desired = wartosc
			ustawienie.Managed = true
			ustawienie.Source = kernel.PlikSysctl
		}
		if wyjscie, err := wyjscieNarzedzia(ctx, kernel.SciezkaSysctl, "-n", klucz); err == nil {
			ustawienie.Current = strings.Join(strings.Fields(wyjscie), " ")
		}
		// Klucza, ktorego jadro nie zna, nie pokazujemy z pusta wartoscia:
		// wygladalby jak ustawienie o wartosci zerowej.
		if ustawienie.Current == "" && ustawienie.Desired == "" {
			continue
		}
		wynik = append(wynik, ustawienie)
	}
	return wynik
}

func (s *Server) modulZaladowany(nazwa string) bool {
	dane, err := os.ReadFile("/proc/modules")
	if err != nil {
		return false
	}
	for _, modul := range kernel.ParsujModuly(string(dane)) {
		if modul.Name == nazwa {
			return true
		}
	}
	return false
}

func zapiszPlikJadra(sciezka, tresc string, tryb os.FileMode) error {
	tymczasowy := sciezka + ".nowy"
	if err := os.WriteFile(tymczasowy, []byte(tresc), tryb); err != nil {
		return err
	}
	return os.Rename(tymczasowy, sciezka)
}

func odpowiedzJadra(snapshot kernel.Snapshot, komunikat string,
	oczekujace, zastosowane []string) *helperv1.HelperResponse {
	zakodowane, err := json.Marshal(snapshot)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	return &helperv1.HelperResponse{
		Accepted: true,
		KernelResult: &helperv1.KernelResult{
			Snapshot: zakodowane, Message: komunikat,
			PendingReboot: oczekujace, AppliedRuntime: zastosowane,
		},
	}
}
