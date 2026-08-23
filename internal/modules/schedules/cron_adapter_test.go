package schedules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Cron uruchamia polecenie przez powloke, wiec argument z metaznakiem
// przestaje byc argumentem, a staje sie druga komenda. Modul podstawowy nie
// przyjmuje dowolnego wiersza powloki.
func TestPolecenieOdrzucaZnakiPowloki(t *testing.T) {
	zle := [][]string{
		{"/usr/bin/backup; reboot"},
		{"/usr/bin/backup", "&&", "reboot"},
		{"/usr/bin/backup", "$(reboot)"},
		{"/usr/bin/backup", "`reboot`"},
		{"/usr/bin/backup", "plik*"},
		{"/usr/bin/backup", "a\nb"},
		// Procent ma w cronie wlasne znaczenie: konczy polecenie.
		{"/usr/bin/date", "+%Y"},
		{},
		{""},
	}
	for _, polecenie := range zle {
		if _, err := ZlozPolecenie(polecenie); err == nil {
			t.Errorf("przyjeto polecenie %v", polecenie)
		}
	}
}

// Sciezka wzgledna zalezy od PATH crona, ktory bywa inny niz PATH operatora.
// Wpis dzialajacy recznie i niedzialajacy z crona jest najtrudniejsza do
// zdiagnozowania awaria w tym module.
func TestPolecenieWymagaSciezkiBezwzglednej(t *testing.T) {
	if _, err := ZlozPolecenie([]string{"backup.sh"}); err == nil {
		t.Error("przyjeto sciezke wzgledna")
	}
	wynik, err := ZlozPolecenie([]string{"/usr/local/bin/backup.sh", "--full"})
	if err != nil {
		t.Fatalf("odrzucono poprawne polecenie: %v", err)
	}
	if wynik != "/usr/local/bin/backup.sh --full" {
		t.Errorf("polecenie = %q", wynik)
	}
}

// Cron pomija pliki o nazwach z kropka i innymi znakami specjalnymi, wiec
// wpis o zlej nazwie po cichu nigdy by sie nie uruchomil.
func TestIdentyfikatorMusiBycPoprawnaNazwaPliku(t *testing.T) {
	for _, id := range []string{"", "backup.nocny", "backup nocny", "../etc/passwd", "-backup", "_backup"} {
		if PoprawnyIdentyfikator(id) {
			t.Errorf("przyjeto identyfikator %q", id)
		}
	}
	// Podkreslnik i wielkie litery dopuszcza sam cron, wiec dopuszcza je tez
	// panel: bez tego nie dalo by sie przejac wpisu "e2scrub_all".
	for _, id := range []string{"backup", "backup-nocny", "b", "kopia-2", "e2scrub_all", "Backup"} {
		if !PoprawnyIdentyfikator(id) {
			t.Errorf("odrzucono identyfikator %q", id)
		}
	}
}

// Wpis zalozony przez panel jest rozpoznawany jako zarzadzany i ma stabilny
// identyfikator; wpis zastany nalezy do administratora hosta.
func TestWpisyZarzadzaneSaOdrozniane(t *testing.T) {
	katalog := t.TempDir()
	wpis := Schedule{
		ID: "kopia-nocna", Expression: "0 3 * * *", Enabled: true,
		Command: []string{"/usr/local/bin/backup.sh"}, Comment: "kopia bazy",
	}
	if err := ZapiszWpis(katalog, wpis); err != nil {
		t.Fatalf("zapis: %v", err)
	}
	// Wpis administratora hosta obok naszego.
	reczny := filepath.Join(katalog, "porzadki")
	if err := os.WriteFile(reczny, []byte("0 4 * * * root /usr/bin/find /tmp -delete\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	teraz := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	wpisy := CzytajCron(filepath.Join(katalog, "brak-crontaba"), katalog, teraz)
	if len(wpisy) != 2 {
		t.Fatalf("wpisow = %d: %+v", len(wpisy), wpisy)
	}

	var zarzadzany, manualny *Schedule
	for i := range wpisy {
		if wpisy[i].Source == SourceManaged {
			zarzadzany = &wpisy[i]
		} else {
			manualny = &wpisy[i]
		}
	}
	if zarzadzany == nil || manualny == nil {
		t.Fatalf("nie rozpoznano obu rodzajow: %+v", wpisy)
	}
	if zarzadzany.ID != "kopia-nocna" {
		t.Errorf("identyfikator zarzadzanego = %q", zarzadzany.ID)
	}
	if zarzadzany.NextRun == nil || zarzadzany.NextRun.Hour() != 3 {
		t.Errorf("nastepne uruchomienie = %v", zarzadzany.NextRun)
	}
	if zarzadzany.Comment != "kopia bazy" {
		t.Errorf("komentarz = %q", zarzadzany.Comment)
	}
	// Wpis zastany bywa wierszem powloki, wiec zostaje wierszem: rozbity na
	// argumenty pokazywalby cos, czego cron tak nie uruchomi.
	if manualny.User != "root" || manualny.CommandLine == "" || len(manualny.Command) != 0 {
		t.Errorf("wpis reczny = %+v", manualny)
	}
}

// Wylaczenie nie jest usunieciem: tresc ma przetrwac, a wpis nie moze miec
// nastepnego terminu, bo sie nie uruchomi.
func TestWpisWylaczonyZachowujeTrescBezTerminu(t *testing.T) {
	katalog := t.TempDir()
	wpis := Schedule{
		ID: "kopia-nocna", Expression: "0 3 * * *", Enabled: false,
		Command: []string{"/usr/local/bin/backup.sh"},
	}
	if err := ZapiszWpis(katalog, wpis); err != nil {
		t.Fatal(err)
	}

	tresc, _ := os.ReadFile(SciezkaWpisu(katalog, "kopia-nocna"))
	if !strings.Contains(string(tresc), "/usr/local/bin/backup.sh") {
		t.Error("tresc wpisu przepadla przy wylaczeniu")
	}

	wpisy := CzytajCron("", katalog, time.Now())
	if len(wpisy) != 1 {
		t.Fatalf("wpisow = %d", len(wpisy))
	}
	if wpisy[0].Enabled {
		t.Error("wpis wylaczony zostal odczytany jako aktywny")
	}
	if wpisy[0].NextRun != nil {
		t.Error("wpis wylaczony ma nastepne uruchomienie")
	}
}

// Usuniecie wpisu, ktorego nie ma, jest stanem docelowym operacji, a nie
// bledem.
func TestUsuniecieNieistniejacegoWpisuJestSukcesem(t *testing.T) {
	if err := UsunWpis(t.TempDir(), "nie-ma-takiego"); err != nil {
		t.Errorf("usuniecie nieistniejacego wpisu = %v", err)
	}
	if err := UsunWpis(t.TempDir(), "../etc/passwd"); err == nil {
		t.Error("przyjeto identyfikator ze sciezka")
	}
}

// Przypisania zmiennych srodowiskowych nie sa harmonogramem.
func TestPrzypisaniaSrodowiskaNieSaWpisami(t *testing.T) {
	katalog := t.TempDir()
	plik := filepath.Join(katalog, "porzadki")
	tresc := "SHELL=/bin/sh\nPATH=/usr/bin:/bin\nMAILTO=root\n0 4 * * * root /usr/bin/true\n"
	if err := os.WriteFile(plik, []byte(tresc), 0o644); err != nil {
		t.Fatal(err)
	}
	wpisy := CzytajCron("", katalog, time.Now())
	if len(wpisy) != 1 {
		t.Fatalf("wpisow = %d: %+v", len(wpisy), wpisy)
	}
}

// Timery i cron sa dwoma mechanizmami tego samego: operator chce zobaczyc
// jedna tabele zadan, a nie dwie listy do polaczenia w glowie.
func TestTimeryTrafiajaDoTejSamejTabeli(t *testing.T) {
	lista := strings.Join([]string{
		"NEXT                        LEFT       LAST                        PASSED   UNIT                         ACTIVATES",
		"Sun 2026-08-23 06:00:00 UTC 5h left    Sat 2026-08-22 06:00:00 UTC 18h ago  logrotate.timer              logrotate.service",
		"-                           -          -                           -        systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.service",
	}, "\n")
	jednostki := strings.Join([]string{
		"logrotate.timer                loaded active waiting Daily rotation",
		"systemd-tmpfiles-clean.timer   loaded inactive dead  Cleanup",
	}, "\n")

	// Kolejnosc jak na hoscie: rekordy rozdziela pusta linia, a systemd
	// wypisuje TimersCalendar przed Id. Timer bez kalendarza (monotoniczny)
	// ma w rekordzie samo Id.
	kalendarze := strings.Join([]string{
		"Id=systemd-tmpfiles-clean.timer",
		"",
		"TimersCalendar={ OnCalendar=*-*-* 06:00:00 ; next_elapse=Sun 2026-08-23 06:00:00 UTC }",
		"Id=logrotate.timer",
	}, "\n")

	wpisy := CzytajTimery(lista, jednostki, kalendarze)
	if len(wpisy) != 2 {
		t.Fatalf("timerow = %d: %+v", len(wpisy), wpisy)
	}

	po := map[string]Schedule{}
	for _, wpis := range wpisy {
		po[wpis.ID] = wpis
	}
	logrotate := po["logrotate.timer"]
	if logrotate.Kind != KindTimer || !logrotate.Enabled {
		t.Errorf("logrotate = %+v", logrotate)
	}
	if logrotate.NextRun == nil || logrotate.NextRun.Hour() != 6 {
		t.Errorf("termin logrotate = %v", logrotate.NextRun)
	}
	// Timer pokazuje swoje OnCalendar, a nie staly napis "systemd timer":
	// bez wyrazenia wiersz nie tlumaczy, skad wzial sie nastepny termin.
	if logrotate.Expression != "*-*-* 06:00:00" {
		t.Errorf("wyrazenie logrotate = %q", logrotate.Expression)
	}
	// Timer monotoniczny nie ma wyrazenia kalendarzowego i nie moze dostac
	// cudzego: przy czytaniu linia po linii dostalby wlasnie takie.
	if po["systemd-tmpfiles-clean.timer"].Expression != "" {
		t.Errorf("timer monotoniczny dostal wyrazenie %q",
			po["systemd-tmpfiles-clean.timer"].Expression)
	}
	// Timer bez zaplanowanego terminu nie moze dostac daty zerowej udajacej
	// konkretna chwile.
	if po["systemd-tmpfiles-clean.timer"].NextRun != nil {
		t.Error("timer bez terminu dostal date")
	}
	if po["systemd-tmpfiles-clean.timer"].Enabled {
		t.Error("timer nieaktywny zostal odczytany jako aktywny")
	}
}
