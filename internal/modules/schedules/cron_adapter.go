package schedules

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Katalog wpisow crona i prefiks plikow nalezacych do panelu.
//
// Jeden plik na wpis, a nie wspolny plik z wieloma liniami: dzieki temu zmiana
// jednego harmonogramu nie przepisuje pozostalych, a usuniecie jest
// skasowaniem pliku, a nie edycja wiersza w srodku cudzej tresci.
const (
	KatalogCronD    = "/etc/cron.d"
	PrefiksPlikow   = "flotestro-"
	NaglowekPliku   = "# Zarzadzane przez Flotestro. Recznych zmian nie zachowa kolejna operacja."
	SciezkaCrontabu = "/etc/crontab"
)

// identyfikatorWpisu dopuszcza nazwy, ktore moga byc czescia nazwy pliku
// w /etc/cron.d. Cron pomija pliki z kropka i innymi znakami specjalnymi,
// wiec wpis o zlej nazwie po cichu nigdy by sie nie uruchomil.
//
// Zbior znakow jest ten sam, ktory dopuszcza cron: litery, cyfry, podkreslnik
// i myslnik. Wezszy zbior uniemozliwialby przejecie wpisu zastanego o nazwie
// takiej jak "e2scrub_all" - a takie wlasnie stoja na hostach.
var identyfikatorWpisu = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$`)

// PoprawnyIdentyfikator sprawdza nazwe wpisu zarzadzanego.
func PoprawnyIdentyfikator(id string) bool {
	return identyfikatorWpisu.MatchString(id)
}

// SciezkaWpisu zwraca plik wpisu zarzadzanego.
func SciezkaWpisu(katalog, id string) string {
	return filepath.Join(katalog, PrefiksPlikow+id)
}

// CzytajCron zbiera wpisy crona z /etc/crontab i /etc/cron.d.
//
// Wpisy uzytkownikow nie sa czytane w tym module: leza w katalogu spool,
// naleza do konkretnych kont i ich odczyt jest osobna decyzja o prywatnosci.
func CzytajCron(crontab, katalog string, teraz time.Time) []Schedule {
	var wpisy []Schedule
	wpisy = append(wpisy, czytajPlikCrona(crontab, true, teraz)...)

	pliki, err := os.ReadDir(katalog)
	if err != nil {
		return wpisy
	}
	nazwy := make([]string, 0, len(pliki))
	for _, plik := range pliki {
		if plik.IsDir() {
			continue
		}
		nazwy = append(nazwy, plik.Name())
	}
	sort.Strings(nazwy)
	for _, nazwa := range nazwy {
		wpisy = append(wpisy, czytajPlikCrona(filepath.Join(katalog, nazwa), true, teraz)...)
	}
	return wpisy
}

// czytajPlikCrona parsuje jeden plik. zUzytkownikiem odroznia format
// /etc/crontab i /etc/cron.d - tam po piatym polu jest nazwa uzytkownika -
// od crontaba uzytkownika, gdzie jej nie ma.
func czytajPlikCrona(sciezka string, zUzytkownikiem bool, teraz time.Time) []Schedule {
	plik, err := os.Open(sciezka)
	if err != nil {
		return nil
	}
	defer plik.Close()

	zarzadzany := strings.HasPrefix(filepath.Base(sciezka), PrefiksPlikow)
	identyfikator := strings.TrimPrefix(filepath.Base(sciezka), PrefiksPlikow)

	var wpisy []Schedule
	skaner := bufio.NewScanner(plik)
	numer := 0
	var komentarz string
	for skaner.Scan() {
		numer++
		linia := strings.TrimSpace(skaner.Text())
		if linia == "" {
			continue
		}
		// Wpis wylaczony jest zakomentowany, a nie skasowany: wylaczenie nie
		// jest usunieciem i tresc ma przetrwac.
		wylaczony := strings.HasPrefix(linia, "#@")
		if wylaczony {
			linia = strings.TrimSpace(strings.TrimPrefix(linia, "#@"))
		} else if strings.HasPrefix(linia, "#") {
			// Komentarz przypisujemy wylacznie wpisom wlasnym: w cudzym pliku
			// nad wpisem stoi zwykle naglowek formatu albo notatka o czyms
			// innym, a pokazana przy wpisie wygladalaby na jego opis.
			if zarzadzany && linia != NaglowekPliku {
				komentarz = strings.TrimSpace(strings.TrimPrefix(linia, "#"))
			}
			continue
		}
		// Przypisania zmiennych srodowiskowych nie sa harmonogramem.
		if !strings.HasPrefix(linia, "@") && strings.Contains(strings.Fields(linia)[0], "=") {
			continue
		}

		wpis, ok := parsujLinieCrona(linia, zUzytkownikiem)
		if !ok {
			continue
		}
		wpis.Path = sciezka
		wpis.Line = numer
		wpis.Enabled = !wylaczony
		wpis.Comment = komentarz
		komentarz = ""
		if zarzadzany {
			wpis.Source = SourceManaged
			wpis.ID = identyfikator
			// Wpis wlasny panel zapisal sam, wiec wie, ze wiersz jest lista
			// argumentow i moze go tak pokazac.
			wpis.Command = strings.Fields(wpis.CommandLine)
		} else {
			wpis.Source = SourceManual
			wpis.ID = fmt.Sprintf("%s:%d", sciezka, numer)
		}
		// Termin liczymy tylko dla wpisow aktywnych: wylaczony wpis nie ma
		// nastepnego uruchomienia i podanie go byloby falszem.
		if wpis.Enabled {
			if wyrazenie, err := ParsujWyrazenie(wpis.Expression); err == nil {
				if terminy := wyrazenie.NastepneUruchomienia(teraz, 1); len(terminy) > 0 {
					termin := terminy[0]
					wpis.NextRun = &termin
				}
			}
		}
		wpisy = append(wpisy, wpis)
	}
	return wpisy
}

// parsujLinieCrona rozdziela wyrazenie, uzytkownika i polecenie.
func parsujLinieCrona(linia string, zUzytkownikiem bool) (Schedule, bool) {
	pola := strings.Fields(linia)
	polWyrazenia := polCrona
	if strings.HasPrefix(linia, "@") {
		polWyrazenia = 1
	}
	minimum := polWyrazenia + 1
	if zUzytkownikiem {
		minimum++
	}
	if len(pola) < minimum {
		return Schedule{}, false
	}

	wpis := Schedule{
		Kind:       KindCron,
		Expression: strings.Join(pola[:polWyrazenia], " "),
	}
	reszta := pola[polWyrazenia:]
	if zUzytkownikiem {
		wpis.User = reszta[0]
		reszta = reszta[1:]
	}
	wpis.CommandLine = strings.Join(reszta, " ")
	return wpis, true
}

// ZapiszWpis zapisuje wpis zarzadzany.
//
// Zapis jest atomowy: plik powstaje obok i dopiero gotowy zastepuje poprzedni.
// Cron czyta katalog w dowolnej chwili, wiec plik pisany w miejscu moglby
// zostac odczytany w polowie - z wpisem, ktorego nikt nie zlecil.
func ZapiszWpis(katalog string, wpis Schedule) error {
	if !PoprawnyIdentyfikator(wpis.ID) {
		return fmt.Errorf("nieprawidlowy identyfikator wpisu %q", wpis.ID)
	}
	if _, err := ParsujWyrazenie(wpis.Expression); err != nil {
		return err
	}
	polecenie, err := ZlozPolecenie(wpis.Command)
	if err != nil {
		return err
	}
	uzytkownik := wpis.User
	if uzytkownik == "" {
		uzytkownik = "root"
	}

	prefiks := ""
	if !wpis.Enabled {
		prefiks = "#@"
	}
	tresc := NaglowekPliku + "\n"
	if wpis.Comment != "" {
		tresc += "# " + strings.ReplaceAll(wpis.Comment, "\n", " ") + "\n"
	}
	tresc += fmt.Sprintf("%s%s %s %s\n", prefiks, wpis.Expression, uzytkownik, polecenie)

	docelowy := SciezkaWpisu(katalog, wpis.ID)
	tymczasowy := docelowy + ".nowy"
	if err := os.WriteFile(tymczasowy, []byte(tresc), 0o644); err != nil {
		return err
	}
	return os.Rename(tymczasowy, docelowy)
}

// UsunWpis kasuje plik wpisu zarzadzanego.
func UsunWpis(katalog, id string) error {
	if !PoprawnyIdentyfikator(id) {
		return fmt.Errorf("nieprawidlowy identyfikator wpisu %q", id)
	}
	err := os.Remove(SciezkaWpisu(katalog, id))
	if os.IsNotExist(err) {
		// Wpis, ktorego nie ma, jest stanem docelowym operacji usuwajacej.
		return nil
	}
	return err
}

// znakiPowloki sa niedozwolone w argumentach polecenia.
//
// Cron uruchamia polecenie przez powloke, wiec argument z metaznakiem
// przestaje byc argumentem, a staje sie druga komenda. Modul podstawowy nie
// przyjmuje dowolnego wiersza powloki - polecenie jest tablica argumentow.
const znakiPowloki = "|&;<>()$`\\\"'\n\r\t*?[]{}~!#"

// ZlozPolecenie sklada argumenty w wiersz dla crona.
func ZlozPolecenie(argumenty []string) (string, error) {
	if len(argumenty) == 0 {
		return "", fmt.Errorf("polecenie jest puste")
	}
	if !strings.HasPrefix(argumenty[0], "/") {
		// Sciezka wzgledna zalezy od PATH crona, ktory bywa inny niz PATH
		// operatora. Wpis dzialajacy recznie i niedzialajacy z crona jest
		// najtrudniejsza do zdiagnozowania awaria w tym module.
		return "", fmt.Errorf("polecenie musi byc sciezka bezwzgledna, jest %q", argumenty[0])
	}
	for _, argument := range argumenty {
		if argument == "" {
			return "", fmt.Errorf("pusty argument polecenia")
		}
		if strings.ContainsAny(argument, znakiPowloki) {
			return "", fmt.Errorf("argument %q zawiera znak powloki", argument)
		}
		// Procent ma w cronie wlasne znaczenie: konczy polecenie i zaczyna
		// wejscie standardowe.
		if strings.Contains(argument, "%") {
			return "", fmt.Errorf("argument %q zawiera znak procentu", argument)
		}
	}
	return strings.Join(argumenty, " "), nil
}

// StrefaHosta zwraca strefe czasowa hosta.
//
// Nazwa strefy pochodzi z konfiguracji systemu, a nie z time.Local: ta
// ostatnia zawsze nazywa sie "Local" i nie odpowiada na pytanie, o ktorej
// naprawde uruchomi sie wpis. Nieustalona strefa zostaje pusta - "UTC"
// wpisane na wszelki wypadek byloby zgadywaniem.
func StrefaHosta() string {
	if dane, err := os.ReadFile("/etc/timezone"); err == nil {
		if nazwa := strings.TrimSpace(string(dane)); nazwa != "" {
			return nazwa
		}
	}
	cel, err := filepath.EvalSymlinks("/etc/localtime")
	if err != nil {
		return ""
	}
	const katalogStref = "/usr/share/zoneinfo/"
	if indeks := strings.Index(cel, katalogStref); indeks >= 0 {
		return cel[indeks+len(katalogStref):]
	}
	return ""
}
