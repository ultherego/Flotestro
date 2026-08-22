// Package systemd jest adapterem do jednostek systemd. Uzywa go helper roota,
// wiec kod jest celowo maly i nie przyjmuje danych, ktorych nie zwalidowal.
package systemd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const systemctlPath = "/usr/bin/systemctl"

// Operation jest typowana operacja na jednostce. Nie istnieje operacja
// "dowolne polecenie systemctl".
type Operation string

const (
	OperationStart   Operation = "start"
	OperationStop    Operation = "stop"
	OperationRestart Operation = "restart"
	OperationReload  Operation = "reload"
)

// Known sprawdza, czy operacja jest obslugiwana.
func (o Operation) Known() bool {
	switch o {
	case OperationStart, OperationStop, OperationRestart, OperationReload:
		return true
	default:
		return false
	}
}

var (
	// ErrProtectedUnit oznacza jednostke, ktorej ruszenie moze odciac hosta
	// od control plane albo zatrzymac samego agenta.
	ErrProtectedUnit = errors.New("jednostka chroniona")
	// ErrInvalidUnit oznacza nazwe, ktora nie jest poprawna nazwa jednostki.
	ErrInvalidUnit = errors.New("nieprawidlowa nazwa jednostki")

	// Nazwa jednostki wg systemd.unit(5): litery, cyfry i : _ . \ - @ oraz
	// wymagany sufiks typu. Wzorzec odrzuca sciezki i znaki powloki.
	unitPattern = regexp.MustCompile(
		`^[A-Za-z0-9:_.\\@-]+\.(service|socket|timer|target|path|mount|automount|swap|slice|scope)$`)

	// protectedUnits to jednostki, ktorych nie wolno ruszac operacja typowana.
	// Zatrzymanie agenta odcielo by zdalne naprawianie skutkow, a zatrzymanie
	// sshd lub sieci odcielo by droge awaryjna.
	protectedUnits = map[string]struct{}{
		"flotestro-agent.service":         {},
		"flotestro-helper.service":        {},
		"flotestro-helper.socket":         {},
		"flotestro-control-plane.service": {},
		"sshd.service":                    {},
		"ssh.service":                     {},
		"sshd.socket":                     {},
		"systemd-networkd.service":        {},
		"NetworkManager.service":          {},
		"networking.service":              {},
		"systemd-journald.service":        {},
		"systemd-journald.socket":         {},
		"dbus.service":                    {},
		"dbus-broker.service":             {},
		"systemd-logind.service":          {},
		"local-fs.target":                 {},
		"remote-fs.target":                {},
	}
)

// ValidateUnit sprawdza nazwe jednostki i polityke ochrony.
func ValidateUnit(unit string) error {
	if !unitPattern.MatchString(unit) {
		return fmt.Errorf("%w: %q", ErrInvalidUnit, unit)
	}
	if _, protected := protectedUnits[unit]; protected {
		return fmt.Errorf("%w: %q", ErrProtectedUnit, unit)
	}
	// Jednostki montowania i wymiany moga odciac system plików pod dzialajacym
	// hostem, wiec nie sa dostepne przez ten adapter.
	if strings.HasSuffix(unit, ".mount") || strings.HasSuffix(unit, ".swap") {
		return fmt.Errorf("%w: %q wymaga osobnego modulu storage", ErrProtectedUnit, unit)
	}
	return nil
}

// IsProtected mowi, czy jednostka jest na liscie chronionych.
func IsProtected(unit string) bool {
	_, protected := protectedUnits[unit]
	return protected
}

// UnitState rozdziela stany, ktore systemd rozroznia. Dzieki temu "active"
// nie ukrywa jednostki w petli auto-restartu.
type UnitState struct {
	Name          string `json:"name"`
	LoadState     string `json:"load_state"`
	ActiveState   string `json:"active_state"`
	SubState      string `json:"sub_state"`
	UnitFileState string `json:"unit_file_state"`
	Result        string `json:"result"`
	MainPID       uint32 `json:"main_pid"`
	NRestarts     uint32 `json:"n_restarts"`
}

// Healthy mowi, czy jednostka dziala i nie jest w petli restartow.
func (u UnitState) Healthy() bool {
	return u.ActiveState == "active" && u.SubState != "auto-restart"
}

var shownProperties = []string{
	"Names", "LoadState", "ActiveState", "SubState", "UnitFileState",
	"Result", "MainPID", "NRestarts",
}

// Show odczytuje stan jednostki. Uzywamy formatu klucz=wartosc, ktory nie jest
// tlumaczony, zamiast czytelnego dla czlowieka wyjscia "systemctl status".
func Show(ctx context.Context, unit string) (UnitState, error) {
	if !unitPattern.MatchString(unit) {
		return UnitState{}, fmt.Errorf("%w: %q", ErrInvalidUnit, unit)
	}
	args := append([]string{"show", unit, "--no-pager"}, "--property="+strings.Join(shownProperties, ","))
	stdout, _, err := run(ctx, 15*time.Second, args...)
	if err != nil {
		return UnitState{}, err
	}

	state := UnitState{Name: unit}
	for _, line := range strings.Split(stdout, "\n") {
		key, value, found := strings.Cut(strings.TrimSpace(line), "=")
		if !found {
			continue
		}
		switch key {
		case "Names":
			if value != "" {
				state.Name = strings.Fields(value)[0]
			}
		case "LoadState":
			state.LoadState = value
		case "ActiveState":
			state.ActiveState = value
		case "SubState":
			state.SubState = value
		case "UnitFileState":
			state.UnitFileState = value
		case "Result":
			state.Result = value
		case "MainPID":
			state.MainPID = parseUint32(value)
		case "NRestarts":
			state.NRestarts = parseUint32(value)
		}
	}
	return state, nil
}

// Apply wykonuje operacje na jednostce. Nazwa jest walidowana ponownie tuz
// przed wykonaniem, niezaleznie od tego, kto ja przyslal.
func Apply(ctx context.Context, unit string, operation Operation, timeout time.Duration) (stdout, stderr string, exitCode int, err error) {
	if !operation.Known() {
		return "", "", -1, fmt.Errorf("nieznana operacja %q", operation)
	}
	if err := ValidateUnit(unit); err != nil {
		return "", "", -1, err
	}
	out, errOut, err := run(ctx, timeout, applyArgs(unit, operation)...)
	code := 0
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		code = exitErr.ExitCode()
		err = nil
	} else if err != nil {
		code = -1
	}
	return out, errOut, code, err
}

// applyArgs buduje argumenty wywolania. Celowo nie przekazujemy --no-block:
// operacja ma sie zakonczyc, zanim odczytamy stan jednostki, bo inaczej wynik
// opisywalby stan sprzed zmiany.
func applyArgs(unit string, operation Operation) []string {
	return []string{string(operation), unit, "--no-pager"}
}

// Stabilne kody bledow operacji na jednostkach. Pochodza z kodu wyjscia
// systemctl, ktory jest interfejsem stabilnym, a nie z tlumaczonego komunikatu.
const (
	ErrorUnitNotFound   = "unit_not_found"
	ErrorUnitNotActive  = "unit_not_active"
	ErrorUnitActionFail = "unit_action_failed"
)

// ErrorCodeForExit tlumaczy kod wyjscia systemctl na stabilny kod bledu.
// systemctl zwraca 4 i 5 dla jednostki, ktorej nie ma, oraz 3 dla jednostki
// nieaktywnej; reszta to blad ogolny operacji.
func ErrorCodeForExit(exitCode int) string {
	switch exitCode {
	case 0:
		return ""
	case 3:
		return ErrorUnitNotActive
	case 4, 5:
		return ErrorUnitNotFound
	default:
		return ErrorUnitActionFail
	}
}

// ScheduleReboot planuje restart hosta po zadanym opoznieniu.
// Uzywamy transient timera systemd, bo shutdown przyjmuje pelne minuty, a
// kampania potrzebuje kilkunastu sekund na odeslanie wyniku przed zniknieciem
// hosta z sieci.
func ScheduleReboot(ctx context.Context, delay time.Duration, reason string) (stdout, stderr string, exitCode int, err error) {
	if delay < time.Second {
		delay = time.Second
	}
	args := []string{
		"--collect",
		"--on-active=" + strconv.Itoa(int(delay.Seconds())) + "s",
		"--unit=flotestro-reboot",
		"--description=" + reason,
		systemctlPath, "reboot",
	}
	out, errOut, err := runTool(ctx, 30*time.Second, systemdRunPath, args...)
	code := 0
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		code = exitErr.ExitCode()
		err = nil
	} else if err != nil {
		code = -1
	}
	return out, errOut, code, err
}

const systemdRunPath = "/usr/bin/systemd-run"

// run uruchamia systemctl ze stala sciezka i tablica argumentow. Nigdy nie
// uzywamy sh -c, wiec nazwa jednostki nie moze stac sie poleceniem.
func run(ctx context.Context, timeout time.Duration, args ...string) (string, string, error) {
	return runTool(ctx, timeout, systemctlPath, args...)
}

func runTool(ctx context.Context, timeout time.Duration, path string, args ...string) (string, string, error) {
	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(cmdCtx, path, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// LC_ALL=C stabilizuje komunikaty, ktore trafiaja do wyniku zadania.
	cmd.Env = []string{"LC_ALL=C", "LANG=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	err := cmd.Run()
	if cmdCtx.Err() != nil {
		return stdout.String(), stderr.String(), cmdCtx.Err()
	}
	return stdout.String(), stderr.String(), err
}

func parseUint32(value string) uint32 {
	parsed, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
	if err != nil {
		return 0
	}
	return uint32(parsed)
}
