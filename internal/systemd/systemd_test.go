package systemd

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateUnitOdrzucaWstrzykniecia(t *testing.T) {
	// Nazwa jednostki nigdy nie jest interpretowana przez powloke, ale walidacja
	// jest druga linia obrony i musi odrzucac takie ksztalty wprost.
	invalid := []string{
		"",
		"nginx",                         // brak sufiksu typu
		"../../etc/passwd",              // sciezka
		"nginx.service; rm -rf /",       // separator polecen
		"nginx.service && reboot",       // laczenie polecen
		"$(reboot).service",             // podstawienie polecenia
		"`reboot`.service",              // podstawienie polecenia
		"nginx.service\nrestart",        // nowa linia
		"nginx.conf",                    // nieznany typ jednostki
		"/etc/systemd/system/x.service", // sciezka bezwzgledna
	}
	for _, unit := range invalid {
		if err := ValidateUnit(unit); err == nil {
			t.Errorf("przyjeto nieprawidlowa nazwe %q", unit)
		}
	}
}

func TestValidateUnitPrzyjmujePoprawneNazwy(t *testing.T) {
	valid := []string{
		"nginx.service",
		"getty@tty1.service",
		"my-app.service",
		"backup.timer",
		"app.socket",
		"multi-user.target",
	}
	for _, unit := range valid {
		if err := ValidateUnit(unit); err != nil {
			t.Errorf("odrzucono poprawna nazwe %q: %v", unit, err)
		}
	}
}

func TestValidateUnitChroniKrytyczneJednostki(t *testing.T) {
	// Zatrzymanie tych jednostek odcieloby droge naprawy hosta.
	protected := []string{
		"flotestro-agent.service",
		"sshd.service",
		"ssh.service",
		"NetworkManager.service",
		"systemd-networkd.service",
		"systemd-journald.service",
	}
	for _, unit := range protected {
		err := ValidateUnit(unit)
		if err == nil {
			t.Errorf("jednostka chroniona %q zostala dopuszczona", unit)
			continue
		}
		if !errors.Is(err, ErrProtectedUnit) {
			t.Errorf("dla %q oczekiwano ErrProtectedUnit, otrzymano %v", unit, err)
		}
		if !IsProtected(unit) {
			t.Errorf("IsProtected(%q) = false", unit)
		}
	}
}

func TestValidateUnitBlokujeMontowaniaIWymiane(t *testing.T) {
	// Odmontowanie systemu plikow pod dzialajacym hostem nalezy do modulu
	// storage, ktory wymaga preflightu i drogi awaryjnej.
	for _, unit := range []string{"srv-data.mount", "swapfile.swap"} {
		err := ValidateUnit(unit)
		if err == nil || !errors.Is(err, ErrProtectedUnit) {
			t.Errorf("dopuszczono %q: %v", unit, err)
		}
	}
}

func TestOperationKnown(t *testing.T) {
	for _, op := range []Operation{
		OperationStart, OperationStop, OperationRestart, OperationReload,
		OperationEnable, OperationDisable, OperationMask, OperationUnmask,
		OperationResetFail,
	} {
		if !op.Known() {
			t.Errorf("%s powinna byc znana", op)
		}
	}
	// Lista operacji jest zamknieta: nie istnieje operacja "dowolne polecenie
	// systemctl". Isolate zmienia cel calego systemu, kill wysyla dowolny
	// sygnal, daemon-reexec restartuje pid 1 - zadna z nich nie jest operacja
	// na jednostce.
	for _, op := range []Operation{"", "daemon-reexec", "isolate", "kill", "set-property"} {
		if Operation(op).Known() {
			t.Errorf("nieobslugiwana operacja %q zostala przyjeta", op)
		}
	}
}

func TestUnitStateHealthyOdroznniaPetleRestartow(t *testing.T) {
	// "active" nie moze ukrywac jednostki, ktora wlasnie sie restartuje w kolko.
	looping := UnitState{ActiveState: "active", SubState: "auto-restart"}
	if looping.Healthy() {
		t.Error("jednostka w petli auto-restartu uznana za zdrowa")
	}
	running := UnitState{ActiveState: "active", SubState: "running"}
	if !running.Healthy() {
		t.Error("dzialajaca jednostka uznana za niezdrowa")
	}
	failed := UnitState{ActiveState: "failed", SubState: "failed"}
	if failed.Healthy() {
		t.Error("jednostka w bledzie uznana za zdrowa")
	}
}

func TestShownPropertiesSaKompletne(t *testing.T) {
	// Brak wlasciwosci w zapytaniu oznaczalby ciche zero w wyniku zadania.
	required := []string{"ActiveState", "SubState", "UnitFileState", "Result", "NRestarts"}
	joined := strings.Join(shownProperties, ",")
	for _, property := range required {
		if !strings.Contains(joined, property) {
			t.Errorf("brak wlasciwosci %s w zapytaniu do systemd", property)
		}
	}
}

func TestApplyArgsNiePrzekazujeArgumentuDoNoBlock(t *testing.T) {
	// Regresja: "--no-block=false" jest odrzucane przez systemctl, bo ta opcja
	// nie przyjmuje wartosci. Cale wywolanie konczylo sie wtedy kodem 1, choc
	// jednostka byla sprawna.
	args := applyArgs("nginx.service", OperationRestart)
	for _, arg := range args {
		if strings.HasPrefix(arg, "--no-block=") {
			t.Fatalf("opcja --no-block dostala argument: %q", arg)
		}
	}
	if args[0] != "restart" || args[1] != "nginx.service" {
		t.Fatalf("nieoczekiwane argumenty: %v", args)
	}
	// Brak --no-block jest celowy: musimy poznac wynik operacji.
	for _, arg := range args {
		if arg == "--no-block" {
			t.Fatal("--no-block sprawia, ze stan po operacji jest odczytany za wczesnie")
		}
	}
}
