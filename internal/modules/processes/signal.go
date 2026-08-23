package processes

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// Sygnaly dozwolone przez modul. Lista jest zamknieta: nie istnieje operacja
// "wyslij dowolny sygnal". Sygnaly zatrzymujace proces albo zmieniajace jego
// zachowanie w sposob trudny do cofniecia nie naleza do diagnostyki.
const (
	SignalTERM = "TERM"
	SignalKILL = "KILL"
	SignalHUP  = "HUP"
)

var numerySygnalow = map[string]syscall.Signal{
	SignalTERM: syscall.SIGTERM,
	SignalKILL: syscall.SIGKILL,
	SignalHUP:  syscall.SIGHUP,
}

var (
	// ErrNieznanySygnal oznacza sygnal spoza zamknietej listy.
	ErrNieznanySygnal = errors.New("nieobslugiwany sygnal")
	// ErrProcesChroniony oznacza proces, ktorego ubicie odcieloby host od
	// zarzadzania albo zatrzymalo caly system.
	ErrProcesChroniony = errors.New("proces chroniony")
	// ErrProcesZmieniony oznacza PID uzyty ponownie przez jadro.
	ErrProcesZmieniony = errors.New("pod tym PID dziala juz inny proces")
)

// ZnanySygnal sprawdza, czy sygnal jest obslugiwany.
func ZnanySygnal(nazwa string) bool {
	_, ok := numerySygnalow[nazwa]
	return ok
}

// Chronione opisuje procesy, ktorych nie wolno ruszac.
type Chronione struct {
	// PIDy wlasnych procesow: agenta i helpera. Ubicie ktoregokolwiek
	// odcieloby host od panelu, a wiec takze od naprawy tego, co wlasnie
	// zostalo zepsute.
	Wlasne []int32
}

// Wyslij wysyla sygnal do procesu zwiazanego z czasem startu.
//
// Sam PID nie identyfikuje procesu: jadro uzywa numerow ponownie, wiec sygnal
// wyslany chwile po obejrzeniu listy moze trafic w cos zupelnie innego niz
// operator zamierzal. Dlatego czas startu jest sprawdzany tuz przed wyslaniem.
func Wyslij(root string, pid int32, oczekiwanyStart uint64, sygnal string, chronione Chronione) error {
	numer, ok := numerySygnalow[sygnal]
	if !ok {
		return fmt.Errorf("%w: %s", ErrNieznanySygnal, sygnal)
	}
	if pid <= 1 {
		// PID 1 jest systemem inicjujacym: jego zatrzymanie konczy prace
		// calego hosta.
		return fmt.Errorf("%w: PID %d", ErrProcesChroniony, pid)
	}
	for _, wlasny := range chronione.Wlasne {
		if pid == wlasny {
			return fmt.Errorf("%w: PID %d nalezy do agenta zarzadzajacego", ErrProcesChroniony, pid)
		}
	}

	obecny, err := startProcesu(root, pid)
	if err != nil {
		return err
	}
	if oczekiwanyStart != 0 && obecny != oczekiwanyStart {
		return fmt.Errorf("%w: PID %d", ErrProcesZmieniony, pid)
	}
	return syscall.Kill(int(pid), numer)
}

// startProcesu odczytuje czas startu procesu.
func startProcesu(root string, pid int32) (uint64, error) {
	if root == "" {
		root = "/proc"
	}
	dane, err := os.ReadFile(filepath.Join(root, strconv.FormatInt(int64(pid), 10), "stat"))
	if err != nil {
		return 0, fmt.Errorf("proces %d nie istnieje", pid)
	}
	proces, ok := parsujStat(string(dane))
	if !ok {
		return 0, fmt.Errorf("nieczytelny stan procesu %d", pid)
	}
	return proces.StartTimeTicks, nil
}

// WlasnePID zwraca PIDy procesow, ktorych modul nie moze ubic: samego siebie
// i swojego rodzica. Helper jest uruchamiany przez systemd, wiec jego rodzicem
// jest pid 1 - chroniony osobno.
func WlasnePID() []int32 {
	return []int32{int32(os.Getpid()), int32(os.Getppid())}
}

// OpisSygnalu tlumaczy sygnal na zdanie dla operatora.
func OpisSygnalu(sygnal string) string {
	switch strings.ToUpper(sygnal) {
	case SignalTERM:
		return "prosba o zakonczenie pracy"
	case SignalKILL:
		return "wymuszone zabicie bez mozliwosci sprzatniecia"
	case SignalHUP:
		return "przeladowanie konfiguracji"
	}
	return sygnal
}
