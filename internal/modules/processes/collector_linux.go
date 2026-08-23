// Package processes czyta procesy hosta z /proc.
//
// Modul jest diagnostyka, a nie systemem obserwacji. Snapshot powstaje
// wylacznie na zadanie operatora i ma gorna granice rozmiaru: ciagly strumien
// metryk procesow nalezy do Prometheusa, nie do panelu zarzadzania.
package processes

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Process opisuje jeden proces hosta.
type Process struct {
	PID  int32  `json:"pid"`
	PPID int32  `json:"ppid"`
	User string `json:"user,omitempty"`
	UID  uint32 `json:"uid"`
	// Command jest pelnym wierszem polecenia; puste dla procesow jadra,
	// ktore go nie maja.
	Command string `json:"command,omitempty"`
	// Name pochodzi z /proc/<pid>/stat i istnieje takze dla procesow jadra.
	Name  string `json:"name"`
	State string `json:"state"`
	// RSSBytes to pamiec rezydentna. Zero dla procesu jadra jest prawda,
	// a nie brakiem danych.
	RSSBytes int64 `json:"rss_bytes"`
	Threads  int32 `json:"threads"`
	// StartTimeTicks wiaze proces z jego identyfikatorem. Sam PID jest
	// ponownie uzywany przez jadro, wiec sygnal wyslany po chwili moglby
	// trafic w zupelnie inny proces.
	StartTimeTicks uint64 `json:"start_time_ticks"`
	// CPUTicks to sumaryczny czas procesora. Panel nie liczy z niego
	// procentow: do tego trzeba dwoch pomiarow, a snapshot jest jeden.
	CPUTicks uint64 `json:"cpu_ticks"`
	// Unit i Container wskazuja, co zarzadza procesem. Bez tego operator
	// widzi PID i musi sam zgadywac, czyj on jest.
	Unit      string `json:"unit,omitempty"`
	Container string `json:"container,omitempty"`
}

// Snapshot to wynik jednego odczytu.
type Snapshot struct {
	Processes []Process `json:"processes"`
	// Total mowi, ile procesow bylo na hoscie. Lista bywa krotsza od tej
	// liczby: urwana lista bez niej wygladalaby na pelna.
	Total     int   `json:"total"`
	Truncated bool  `json:"truncated"`
	ClockHz   int64 `json:"clock_hz"`
}

// MaksymalnieProcesow ogranicza jeden snapshot.
const MaksymalnieProcesow = 500

// Sortowanie decyduje, ktore procesy trafia do wyniku, gdy jest ich wiecej
// niz limit. Wybor nalezy do operatora: szuka albo zargu pamieci, albo
// zargu procesora, albo konkretnego polecenia.
const (
	SortByRSS     = "rss"
	SortByCPU     = "cpu"
	SortByPID     = "pid"
	SortByStarted = "started"
)

// Collect czyta procesy hosta.
//
// Odczyt idzie z /proc i nie wymaga roota: panel pokazuje to, co widzi kazdy
// uzytkownik hosta. Wyslanie sygnalu wymaga juz uprawnien i idzie przez
// helpera.
func Collect(root string, sortBy string, limit int) Snapshot {
	if root == "" {
		root = "/proc"
	}
	if limit <= 0 || limit > MaksymalnieProcesow {
		limit = MaksymalnieProcesow
	}

	wpisy, err := os.ReadDir(root)
	if err != nil {
		return Snapshot{ClockHz: clockHz}
	}

	uzytkownicy := czytajUzytkownikow("/etc/passwd")
	var procesy []Process
	for _, wpis := range wpisy {
		pid, err := strconv.ParseInt(wpis.Name(), 10, 32)
		if err != nil {
			continue
		}
		proces, ok := czytajProces(root, int32(pid), uzytkownicy)
		if !ok {
			// Proces, ktory zniknal w trakcie odczytu, nie jest bledem:
			// snapshot opisuje chwile, a chwila juz minela.
			continue
		}
		procesy = append(procesy, proces)
	}

	snapshot := Snapshot{Total: len(procesy), ClockHz: clockHz}
	posortuj(procesy, sortBy)
	if len(procesy) > limit {
		procesy = procesy[:limit]
		snapshot.Truncated = true
	}
	snapshot.Processes = procesy
	return snapshot
}

func posortuj(procesy []Process, sortBy string) {
	switch sortBy {
	case SortByCPU:
		sort.Slice(procesy, func(i, j int) bool { return procesy[i].CPUTicks > procesy[j].CPUTicks })
	case SortByPID:
		sort.Slice(procesy, func(i, j int) bool { return procesy[i].PID < procesy[j].PID })
	case SortByStarted:
		sort.Slice(procesy, func(i, j int) bool {
			return procesy[i].StartTimeTicks > procesy[j].StartTimeTicks
		})
	default:
		// Domyslnie po pamieci: to ona najczesciej konczy sie na hoscie
		// i to jej brak widac jako pierwszy.
		sort.Slice(procesy, func(i, j int) bool { return procesy[i].RSSBytes > procesy[j].RSSBytes })
	}
}

// czytajProces sklada opis jednego procesu.
func czytajProces(root string, pid int32, uzytkownicy map[uint32]string) (Process, bool) {
	katalog := filepath.Join(root, strconv.FormatInt(int64(pid), 10))
	stat, err := os.ReadFile(filepath.Join(katalog, "stat"))
	if err != nil {
		return Process{}, false
	}
	proces, ok := parsujStat(string(stat))
	if !ok {
		return Process{}, false
	}
	proces.PID = pid

	if dane, err := os.ReadFile(filepath.Join(katalog, "cmdline")); err == nil {
		// Argumenty sa rozdzielone bajtem zerowym; pusty cmdline oznacza
		// proces jadra, a nie brak polecenia.
		proces.Command = strings.TrimSpace(strings.ReplaceAll(string(dane), "\x00", " "))
	}
	if dane, err := os.ReadFile(filepath.Join(katalog, "status")); err == nil {
		proces.UID = uidZeStatusu(string(dane))
		proces.User = uzytkownicy[proces.UID]
	}
	if dane, err := os.ReadFile(filepath.Join(katalog, "cgroup")); err == nil {
		proces.Unit, proces.Container = wlascicielZCgroup(string(dane))
	}
	return proces, true
}

// parsujStat czyta /proc/<pid>/stat.
//
// Nazwa procesu jest w nawiasach i moze zawierac spacje oraz same nawiasy,
// wiec pola liczbowe czytamy dopiero za ostatnim nawiasem zamykajacym -
// podzial calej linii po spacjach dawalby zle wyniki dla takich nazw.
func parsujStat(linia string) (Process, bool) {
	otwarcie := strings.IndexByte(linia, '(')
	zamkniecie := strings.LastIndexByte(linia, ')')
	if otwarcie < 0 || zamkniecie < otwarcie {
		return Process{}, false
	}
	proces := Process{Name: linia[otwarcie+1 : zamkniecie]}

	pola := strings.Fields(linia[zamkniecie+1:])
	// Pola liczone od trzeciego pola stat: state, ppid, ...
	if len(pola) < 20 {
		return Process{}, false
	}
	proces.State = pola[0]
	proces.PPID = int32(liczba(pola[1]))
	proces.CPUTicks = uint64(liczba(pola[11])) + uint64(liczba(pola[12]))
	proces.Threads = int32(liczba(pola[17]))
	proces.StartTimeTicks = uint64(liczba(pola[19]))
	// RSS jest w stronach pamieci.
	if len(pola) > 21 {
		proces.RSSBytes = liczba(pola[21]) * int64(os.Getpagesize())
	}
	return proces, true
}

func liczba(tekst string) int64 {
	wartosc, _ := strconv.ParseInt(tekst, 10, 64)
	return wartosc
}

func uidZeStatusu(status string) uint32 {
	for _, linia := range strings.Split(status, "\n") {
		if !strings.HasPrefix(linia, "Uid:") {
			continue
		}
		pola := strings.Fields(linia)
		if len(pola) > 1 {
			return uint32(liczba(pola[1]))
		}
	}
	return 0
}

// wlascicielZCgroup rozpoznaje jednostke systemd i kontener Dockera.
// Operator widzacy sam PID musialby zgadywac, czyj on jest.
func wlascicielZCgroup(cgroup string) (unit, container string) {
	for _, linia := range strings.Split(cgroup, "\n") {
		czesci := strings.SplitN(linia, ":", 3)
		if len(czesci) < 3 {
			continue
		}
		sciezka := czesci[2]
		if index := strings.Index(sciezka, "docker-"); index >= 0 {
			reszta := sciezka[index+len("docker-"):]
			if koniec := strings.Index(reszta, ".scope"); koniec > 0 {
				container = reszta[:koniec]
			}
		}
		for _, segment := range strings.Split(sciezka, "/") {
			if strings.HasSuffix(segment, ".service") || strings.HasSuffix(segment, ".scope") {
				if !strings.HasPrefix(segment, "docker-") {
					unit = segment
				}
			}
		}
	}
	return unit, container
}

// czytajUzytkownikow mapuje UID na nazwe. Nieznany UID zostaje nieznany:
// pusta nazwa jest uczciwsza niz zmyslona.
func czytajUzytkownikow(sciezka string) map[uint32]string {
	dane, err := os.ReadFile(sciezka)
	if err != nil {
		return map[uint32]string{}
	}
	uzytkownicy := map[uint32]string{}
	for _, linia := range strings.Split(string(dane), "\n") {
		pola := strings.Split(linia, ":")
		if len(pola) < 3 {
			continue
		}
		uzytkownicy[uint32(liczba(pola[2]))] = pola[0]
	}
	return uzytkownicy
}

// clockHz jest czestotliwoscia tykow jadra. Sluzy do przeliczenia czasu
// startu procesu na czas rzeczywisty po stronie interfejsu.
const clockHz = 100
