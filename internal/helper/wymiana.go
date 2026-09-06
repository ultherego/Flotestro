package helper

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/packages"
)

// JednostkaWymianyAgenta jest nazwa przejsciowej jednostki, w ktorej dzieje
// sie wymiana agenta. Nazwa jest stala: dwie wymiany naraz na jednym hoscie
// nie maja sensu, a systemd odmowi drugiej zamiast wpuscic je obie na te sama
// baze pakietow.
const JednostkaWymianyAgenta = "flotestro-wymiana-agenta"

// ErrorSamowymiana oznacza, ze hosta nie da sie bezpiecznie wymienic.
const ErrorSamowymiana = "self_replacement_unavailable"

// wymianaAgenta rozpoznaje zlecenie, w ktorym agent wymienia sam siebie.
//
// Rozpoznanie idzie po nazwie pakietu, a nie po polu w zadaniu: to fakt
// o hoscie, a nie zyczenie panelu. Pakiet agenta w towarzystwie innych nie
// jest wymiana tylko instalacja zbioru - i tego nie wykonujemy, bo skrypty
// pakietu agenta przerwa transakcje w polowie, zostawiajac reszte zbioru
// w stanie, ktorego nikt nie zlecil.
func wymianaAgenta(pakiety []string) (string, bool) {
	if len(pakiety) != 1 {
		return "", false
	}
	spec := strings.TrimSpace(pakiety[0])
	if spec == packages.PakietAgenta {
		return spec, true
	}
	reszta, ok := strings.CutPrefix(spec, packages.PakietAgenta)
	if !ok || len(reszta) < 2 {
		return "", false
	}
	// apt oddziela wersje znakiem "=", dnf myslnikiem. Sam prefiks nie
	// wystarczy: "flotestro-agent-tools" tez sie nim zaczyna, a nie jest tym
	// pakietem. Rozstrzyga cyfra - wersja zaczyna sie od niej, nazwa nie.
	if reszta[0] != '=' && reszta[0] != '-' {
		return "", false
	}
	if reszta[1] < '0' || reszta[1] > '9' {
		return "", false
	}
	return spec, true
}

// zlecWymianeAgenta uruchamia instalacje pakietu agenta poza helperem.
//
// Skrypty pakietu agenta zatrzymuja helpera - a wraz z nim cala jego grupe
// kontrolna, czyli takze menedzera pakietow w polowie transakcji. Instalacja
// prowadzona przez helpera konczylaby sie wiec pakietem w stanie polowicznym
// i hostem, ktory nie wrocil. Dlatego ta jedna transakcja startuje jako
// osobna jednostka systemd: przezyje smierc tego, kto ja zlecil.
//
// Odpowiedz nie niesie wyniku transakcji i nie ma niesc: o powodzeniu
// rozstrzyga powrot agenta w oczekiwanej wersji, co widzi panel.
func (s *Server) zlecWymianeAgenta(ctx context.Context, manager packages.Manager,
	spec string) *helperv1.HelperResponse {
	if _, ok := manager.(packages.CyklZycia); !ok {
		return reject(ErrorUnsupported,
			"menedzer "+manager.Name()+" nie obsluguje instalacji pakietow")
	}
	if err := UruchomWymianeAgenta(ctx, spec); err != nil {
		return reject(ErrorSamowymiana, err.Error())
	}
	s.log.Info("wymiana agenta uruchomiona poza helperem",
		"pakiet", spec, "jednostka", JednostkaWymianyAgenta, "manager", manager.Name())
	return &helperv1.HelperResponse{
		Accepted: true,
		Message: "instalacja " + spec + " trwa w jednostce " +
			JednostkaWymianyAgenta + "; wynik rozstrzygnie powrot agenta",
		PackageResult: &helperv1.PackageActionResult{Manager: manager.Name()},
	}
}

// UruchomWymianeAgenta startuje przejsciowa jednostke, ktora wola ten sam
// binarny helper w trybie wymiany.
//
// Jednostka dostaje wylacznie nazwe pakietu z wersja - nie polecenie. Tresc
// transakcji sklada adapter menedzera po drugiej stronie, tak samo jak przy
// kazdej innej operacji pakietowej.
func UruchomWymianeAgenta(ctx context.Context, spec string) error {
	if _, ok := wymianaAgenta([]string{spec}); !ok {
		return fmt.Errorf("%q nie jest pakietem agenta", spec)
	}
	systemdRun, err := exec.LookPath("systemd-run")
	if err != nil {
		return fmt.Errorf("host bez systemd-run nie potrafi wymienic agenta")
	}
	binarny, err := sciezkaHelpera()
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, systemdRun,
		"--collect", "--quiet",
		"--unit="+JednostkaWymianyAgenta,
		"--description=Flotestro: wymiana agenta",
		"--property=Type=oneshot",
		// Transakcja pakietowa ma wlasny limit czasu; ten jest ostatnia
		// siatka, zeby zawieszona instalacja nie zostala na hoscie na zawsze.
		"--property=TimeoutStartSec=3600",
		"--", binarny, "-wymiana-agenta", spec)
	cmd.Env = srodowiskoNarzedzi()
	if wyjscie, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(wyjscie)))
	}
	return nil
}

// WykonajWymianeAgenta instaluje wskazana wersje pakietu agenta.
//
// Funkcja dziala bez agenta, bez gniazda i bez panelu: w chwili, gdy skrypty
// pakietu zatrzymaja helpera i zrestartuja agenta, jest jedynym procesem,
// ktory jeszcze wie, co mialo sie stac.
func WykonajWymianeAgenta(ctx context.Context, spec string, log *slog.Logger) error {
	if _, ok := wymianaAgenta([]string{spec}); !ok {
		return fmt.Errorf("%q nie jest pakietem agenta", spec)
	}
	if err := packages.SetRuntimeDir("/var/lib/flotestro-helper"); err != nil {
		return fmt.Errorf("katalog roboczy helpera: %w", err)
	}
	manager, err := packages.Detect()
	if err != nil {
		return err
	}
	cykl, ok := manager.(packages.CyklZycia)
	if !ok {
		return fmt.Errorf("menedzer %s nie obsluguje instalacji pakietow", manager.Name())
	}
	// Wersja jest wskazana wprost, wiec cofniecie tez jest decyzja operatora:
	// tak dziala powrot po nieudanym wydaniu agenta.
	apply, err := cykl.Install(ctx, packages.Options{
		Mode:           packages.ModeInstall,
		Packages:       []string{spec},
		AllowDowngrade: true,
	})
	if err != nil {
		// Wynik nie ma komu wrocic - agent tej transakcji juz nie slucha.
		// Dziennik hosta jest jedynym miejscem, w ktorym zostanie powod;
		// panel zobaczy tylko to, ze host nie wrocil w zadanej wersji.
		log.Error("wymiana agenta nie powiodla sie",
			"pakiet", spec, "manager", manager.Name(),
			"zmienionych", len(apply.Applied), "err", err)
		return err
	}
	log.Info("wymiana agenta wykonana",
		"pakiet", spec, "manager", manager.Name(), "zmienionych", len(apply.Applied))
	return nil
}
