package backup

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
)

// ErrPrzerwane oznacza operacje przerwana przed koncem.
//
// Przerwany backup nie jest backupem nieudanym ani udanym: jest stanem,
// o ktorym trzeba powiedziec wprost. Repozytorium moze miec zaczete zapisy,
// a katalog odtwarzania - polowe plikow.
var ErrPrzerwane = errors.New("operacja zostala przerwana przed zakonczeniem")

// srodowiskoNarzedzia sklada zmienne dla procesu narzedzia.
//
// Poswiadczenia ida wlasnie tedy, a nie w argumentach: wiersz polecen jest
// w /proc czytelny dla kazdego uzytkownika hosta, a srodowisko - wylacznie
// dla wlasciciela procesu.
func srodowiskoNarzedzia(zlecenie Zlecenie, zmiennaHasla string) []string {
	srodowisko := []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"LC_ALL=C",
		"HOME=" + katalogRoboczy(),
		"TMPDIR=" + katalogRoboczy(),
	}
	if len(zlecenie.Haslo) > 0 && zmiennaHasla != "" {
		srodowisko = append(srodowisko, zmiennaHasla+"="+string(zlecenie.Haslo))
	}
	for nazwa, wartosc := range zlecenie.Srodowisko {
		srodowisko = append(srodowisko, nazwa+"="+string(wartosc))
	}
	return srodowisko
}

// katalogRoboczy wskazuje katalog zapisywalny dla procesu narzedzia.
var katalogRoboczy = func() string { return os.TempDir() }

// SetKatalogRoboczy wskazuje katalog roboczy narzedzi backupu.
func SetKatalogRoboczy(katalog string) {
	if katalog == "" {
		return
	}
	katalogRoboczy = func() string { return katalog }
}

// wynikPolecenia oddziela fakt uruchomienia procesu od jego wyniku.
type wynikPolecenia struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Ran      bool
	Err      error
}

// Powod opisuje niepowodzenie w sposob czytelny w wyniku zadania.
//
// Poswiadczenia sa juz zasloniete przez tego, kto uruchamia polecenie: powod
// idzie do wyniku zadania, a stamtad do bazy panelu.
func (w wynikPolecenia) Powod() string {
	if w.Err != nil && !w.Ran {
		return w.Err.Error()
	}
	opis := strings.TrimSpace(w.Stderr)
	if opis == "" {
		opis = strings.TrimSpace(w.Stdout)
	}
	if opis == "" {
		return fmt.Sprintf("kod %d", w.ExitCode)
	}
	// Ostatnie linie mowia, co sie stalo; poczatek bywa banerem narzedzia.
	linie := strings.Split(opis, "\n")
	if len(linie) > 6 {
		linie = linie[len(linie)-6:]
	}
	return fmt.Sprintf("kod %d: %s", w.ExitCode, strings.Join(linie, " / "))
}

// uruchom wykonuje narzedzie i zwraca jego wyjscie.
//
// Nigdy przez powloke i zawsze tablica argumentow: nazwa sciezki w definicji
// backupu nie moze stac sie poleceniem. Linie stdout ida na biezaco do
// odbiorcy postepu, bo backup trwa dlugo, a operator ma widziec, ze cos sie
// dzieje - nie sam koniec.
func uruchom(ctx context.Context, sciezka string, argumenty []string,
	srodowisko []string, tajne [][]byte, liniaFunc func(string)) wynikPolecenia {
	return uruchomWKatalogu(ctx, "", sciezka, argumenty, srodowisko, tajne, liniaFunc)
}

// uruchomWKatalogu uruchamia narzedzie w podanym katalogu roboczym.
//
// Borg rozpakowuje archiwum do katalogu biezacego procesu, a nie do katalogu
// podanego argumentem - wiec katalog docelowy odtworzenia jest tu czescia
// wywolania, a nie tresci polecenia.
func uruchomWKatalogu(ctx context.Context, katalog, sciezka string, argumenty []string,
	srodowisko []string, tajne [][]byte, liniaFunc func(string)) wynikPolecenia {
	cmd := exec.CommandContext(ctx, sciezka, argumenty...)
	cmd.Env = srodowisko
	cmd.Dir = katalog

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return wynikPolecenia{Err: err}
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return wynikPolecenia{Err: err}
	}

	var zebrane strings.Builder
	var mu sync.Mutex
	czytanie := make(chan struct{})
	go func() {
		defer close(czytanie)
		skaner := bufio.NewScanner(stdout)
		// Linia postepu resticu z lista plikow bywa dluga; domyslny bufor
		// skanera by ja uciolby i zepsul parsowanie JSON.
		skaner.Buffer(make([]byte, 0, 64<<10), 1<<20)
		for skaner.Scan() {
			linia := skaner.Text()
			mu.Lock()
			if zebrane.Len() < MaksymalneWyjscie*2 {
				zebrane.WriteString(linia)
				zebrane.WriteString("\n")
			}
			mu.Unlock()
			if liniaFunc != nil {
				liniaFunc(linia)
			}
		}
		_, _ = io.Copy(io.Discard, stdout)
	}()

	<-czytanie
	err = cmd.Wait()

	wynik := wynikPolecenia{Ran: true}
	mu.Lock()
	wynik.Stdout = Ogranicz(Zaslon(zebrane.String(), tajne))
	mu.Unlock()
	wynik.Stderr = Ogranicz(Zaslon(stderr.String(), tajne))
	if err != nil {
		var bladWyjscia *exec.ExitError
		if errors.As(err, &bladWyjscia) {
			wynik.ExitCode = bladWyjscia.ExitCode()
		} else {
			wynik.Ran = false
			wynik.Err = err
		}
	}
	// Przerwanie ma wlasny powod: proces zabity przez limit czasu albo przez
	// anulowanie zadania zostawia stan, ktorego nikt nie zna, a milczenie
	// w tym miejscu wygladaloby jak zwykla awaria narzedzia.
	if ctx.Err() != nil {
		wynik.Err = fmt.Errorf("%w: %v", ErrPrzerwane, ctx.Err())
	}
	return wynik
}

// tajneZlecenia zbiera wartosci, ktorych nie moze byc w wyjsciu.
func tajneZlecenia(zlecenie Zlecenie) [][]byte {
	tajne := make([][]byte, 0, len(zlecenie.Srodowisko)+1)
	if len(zlecenie.Haslo) > 0 {
		tajne = append(tajne, zlecenie.Haslo)
	}
	for _, wartosc := range zlecenie.Srodowisko {
		tajne = append(tajne, wartosc)
	}
	return tajne
}

// istnieje mowi, czy plik jest na hoscie.
func istnieje(sciezka string) bool {
	info, err := os.Stat(sciezka)
	return err == nil && !info.IsDir()
}
