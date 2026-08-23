package packages

import (
	"bufio"
	"context"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Progress opisuje postep transakcji pakietowej.
//
// Krok i procent sa rozdzielone, bo narzedzia podaja co innego: apt zna
// procent calej operacji, dnf numeruje kroki. Nieustalonej wartosci nie
// zamieniamy na zero - zero krokow wygladaloby jak brak pracy.
type Progress struct {
	Step    uint32
	Total   uint32
	Percent *uint32
	Message string
}

// ProgressFunc odbiera postep. Wywolania sa juz ograniczone czestotliwoscia,
// wiec odbiorca nie musi ich dlawic.
type ProgressFunc func(Progress)

// minimalnyOdstepPostepu ogranicza strumien do tempa czytelnego dla czlowieka.
// Apt potrafi wypisac kilkaset zmian procentu na sekunde; kazda z nich
// kosztowalaby powiadomienie przez cala droge do przegladarki.
const minimalnyOdstepPostepu = 400 * time.Millisecond

// dnfKrok rozpoznaje linie postepu dnf. Kolumna opisu jest dopelniana do
// stalej szerokosci, wiec miedzy opisem a procentem bywa jedna spacja albo
// kilkanascie - wzorzec zaczepia sie o kolumne procentu, a nie o odstep:
//
//	[1/6] Verify package files              100% | 166.0   B/s | ...
//	[3/6] Upgrading tcpdump-14:4.99.6-2.fc4 100% |  36.0 MiB/s | ...
var dnfKrok = regexp.MustCompile(`^\[\s*(\d+)/(\d+)\]\s+(.+?)\s+\d{1,3}%`)

// dnfKrokBezProcentu obsluguje kroki wypisane bez kolumny postepu.
var dnfKrokBezProcentu = regexp.MustCompile(`^\[\s*(\d+)/(\d+)\]\s+(.+?)\s*$`)

// dławik przepuszcza postep nie czesciej niz co minimalnyOdstepPostepu,
// ale ostatniego stanu nie gubi.
type dlawik struct {
	mu       sync.Mutex
	odbiorca ProgressFunc
	ostatnie time.Time
}

func (d *dlawik) wyslij(p Progress, teraz time.Time) {
	if d == nil || d.odbiorca == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if teraz.Sub(d.ostatnie) < minimalnyOdstepPostepu {
		return
	}
	d.ostatnie = teraz
	d.odbiorca(p)
}

// runWithProgress uruchamia narzedzie i melduje postep w trakcie.
//
// Apt dostaje osobny deskryptor stanu (APT::Status-Fd). To jego wlasny,
// maszynowy kanal postepu - parsowanie paskow z terminala dawaloby wynik
// zalezny od szerokosci okna i locale.
func runWithProgress(ctx context.Context, timeout time.Duration, postep ProgressFunc,
	statusFd bool, path string, args ...string) commandResult {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() || info.Mode()&0o111 == 0 {
		return commandResult{ExitCode: -1, Err: errorf("%s: brak narzedzia", path)}
	}
	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, path, args...)
	cmd.Env = srodowisko()

	throttle := &dlawik{odbiorca: postep}
	var czekaj sync.WaitGroup

	stdout := &limitowanyBufor{limit: maksymalneWyjscie}
	stderr := &limitowanyBufor{limit: maksymalneWyjscie}

	// Wyjscia sa czytane linia po linii, zeby postep dochodzil w trakcie,
	// a nie dopiero po zakonczeniu narzedzia.
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return commandResult{ExitCode: -1, Err: err}
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return commandResult{ExitCode: -1, Err: err}
	}

	if statusFd {
		czytnik, zapis, err := os.Pipe()
		if err != nil {
			return commandResult{ExitCode: -1, Err: err}
		}
		// ExtraFiles zaczyna sie od deskryptora 3.
		cmd.ExtraFiles = []*os.File{zapis}
		czekaj.Add(1)
		go func() {
			defer czekaj.Done()
			defer czytnik.Close()
			czytajStatusApta(czytnik, throttle)
		}()
		defer zapis.Close()
	}

	if err := cmd.Start(); err != nil {
		return commandResult{ExitCode: -1, Err: err}
	}
	if statusFd {
		// Rodzic musi zamknac swoj koniec, inaczej czytnik nigdy nie zobaczy
		// konca strumienia.
		_ = cmd.ExtraFiles[0].Close()
	}

	czekaj.Add(2)
	go func() { defer czekaj.Done(); czytajWyjscie(stdoutPipe, stdout, throttle) }()
	go func() { defer czekaj.Done(); czytajWyjscie(stderrPipe, stderr, throttle) }()

	// Czytniki musza skonczyc przed Wait: Wait zamyka potoki, wiec wywolany
	// wczesniej uciąłby wyjscie, ktore jeszcze nie zostalo odczytane.
	czekaj.Wait()
	runErr := cmd.Wait()

	result := commandResult{Stdout: stdout.String(), Stderr: stderr.String(), ExitCode: -1, Err: runErr}
	switch {
	case runErr == nil:
		result.Ran, result.ExitCode = true, 0
	default:
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			result.Ran, result.ExitCode = true, exitErr.ExitCode()
		}
	}
	if cmdCtx.Err() != nil {
		result.Ran = false
	}
	return result
}

// czytajWyjscie zbiera wyjscie i po drodze rozpoznaje kroki dnf.
func czytajWyjscie(r io.Reader, bufor *limitowanyBufor, throttle *dlawik) {
	skaner := bufio.NewScanner(r)
	skaner.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for skaner.Scan() {
		linia := skaner.Text()
		bufor.WriteLine(linia)
		if postep, ok := krokDnf(linia); ok {
			throttle.wyslij(postep, time.Now())
		}
	}
}

// krokDnf czyta numer kroku z linii postepu dnf.
func krokDnf(linia string) (Progress, bool) {
	dopasowanie := dnfKrok.FindStringSubmatch(linia)
	if dopasowanie == nil {
		dopasowanie = dnfKrokBezProcentu.FindStringSubmatch(linia)
	}
	if dopasowanie == nil {
		return Progress{}, false
	}
	krok, err := strconv.ParseUint(dopasowanie[1], 10, 32)
	if err != nil {
		return Progress{}, false
	}
	total, err := strconv.ParseUint(dopasowanie[2], 10, 32)
	if err != nil || total == 0 {
		return Progress{}, false
	}
	return Progress{
		Step:    uint32(krok),
		Total:   uint32(total),
		Message: strings.TrimSpace(dopasowanie[3]),
	}, true
}

// czytajStatusApta czyta maszynowy kanal postepu apta.
//
// Format to "rodzaj:pakiet:procent:opis". Rodzaj dlstatus dotyczy pobierania,
// pmstatus samej instalacji; operatora interesuje jedno i drugie, bo obie
// fazy potrafia trwac.
func czytajStatusApta(r io.Reader, throttle *dlawik) {
	skaner := bufio.NewScanner(r)
	skaner.Buffer(make([]byte, 0, 8<<10), 256<<10)
	for skaner.Scan() {
		if postep, ok := statusApta(skaner.Text()); ok {
			throttle.wyslij(postep, time.Now())
		}
	}
}

// statusApta czyta jedna linie kanalu statusu apta.
func statusApta(linia string) (Progress, bool) {
	czesci := strings.SplitN(linia, ":", 4)
	if len(czesci) < 4 {
		return Progress{}, false
	}
	rodzaj := czesci[0]
	if rodzaj != "pmstatus" && rodzaj != "dlstatus" {
		return Progress{}, false
	}
	wartosc, err := strconv.ParseFloat(strings.TrimSpace(czesci[2]), 64)
	if err != nil {
		return Progress{}, false
	}
	procent := uint32(wartosc)
	opis := strings.TrimSpace(czesci[3])
	if rodzaj == "dlstatus" {
		opis = "Downloading: " + opis
	}
	return Progress{Percent: &procent, Message: opis}, true
}

// czytajStatusAptaTest wystawia parser statusu apta testom bez dlawienia
// czestotliwosci: test ma sprawdzac czytanie formatu, a nie tempo meldunkow.
func czytajStatusAptaTest(r io.Reader, throttle *dlawik) {
	throttle.mu.Lock()
	throttle.ostatnie = time.Time{}
	throttle.mu.Unlock()
	skaner := bufio.NewScanner(r)
	for skaner.Scan() {
		if p, ok := statusApta(skaner.Text()); ok {
			throttle.odbiorca(p)
		}
	}
}
