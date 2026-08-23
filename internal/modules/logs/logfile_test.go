package logs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Panel, ktory potrafi przeczytac dowolny plik roota, potrafi przeczytac
// klucze prywatne i /etc/shadow. Zakres jest wyliczony, a nie podany
// w zadaniu.
func TestAllowlistaOgraniczaZakres(t *testing.T) {
	allowlist := Allowlist{Wzorce: []string{"/var/log/*.log", "/var/log/syslog"}}

	for _, sciezka := range []string{"/var/log/nginx.log", "/var/log/syslog"} {
		if !allowlist.Dozwolona(sciezka) {
			t.Errorf("odrzucono dozwolona sciezke %q", sciezka)
		}
	}
	for _, sciezka := range []string{
		"/etc/shadow",
		"/root/.ssh/id_ed25519",
		"var/log/nginx.log",
		"/var/log/nginx/access.log",
	} {
		if allowlist.Dozwolona(sciezka) {
			t.Errorf("przyjeto sciezke spoza zakresu %q", sciezka)
		}
	}
}

// Wzorzec opisuje sciezke, a nie to, gdzie ona prowadzi. Sciezka z ".."
// dopasowuje sie tekstowo do wzorca, a wychodzi poza katalog, ktory ten
// wzorzec opisuje.
func TestSciezkaZWyjsciemWGoreJestOdrzucana(t *testing.T) {
	allowlist := Allowlist{Wzorce: []string{"/var/log/*.log", "/var/log/*"}}
	for _, sciezka := range []string{
		"/var/log/../../etc/shadow",
		"/var/log/./syslog",
		"/var/log//syslog",
	} {
		if allowlist.Dozwolona(sciezka) {
			t.Errorf("przyjeto sciezke %q", sciezka)
		}
	}
}

// Dowiazanie w katalogu logow pozwoliloby przeczytac dowolny plik roota mimo
// poprawnej allowlisty.
func TestOdczytNiePodazaZaDowiazaniem(t *testing.T) {
	katalog := t.TempDir()
	tajne := filepath.Join(katalog, "tajne.txt")
	if err := os.WriteFile(tajne, []byte("haslo\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dowiazanie := filepath.Join(katalog, "podszywacz.log")
	if err := os.Symlink(tajne, dowiazanie); err != nil {
		t.Skipf("system nie pozwala tworzyc dowiazan: %v", err)
	}

	allowlist := Allowlist{Wzorce: []string{filepath.Join(katalog, "*.log")}}
	_, err := Czytaj(allowlist, dowiazanie, 10)
	if err == nil {
		t.Fatal("odczyt podazyl za dowiazaniem")
	}
	if !strings.Contains(err.Error(), "dowiazanie") {
		t.Errorf("blad = %v, oczekiwano odmowy z powodu dowiazania", err)
	}
}

// Przyczyna awarii jest zwykle przy koncu logu, wiec zwracamy koncowke
// i mowimy wprost, ze reszta zostala pominieta.
func TestOdczytZwracaKoncowkeIZaznaczaObciecie(t *testing.T) {
	katalog := t.TempDir()
	sciezka := filepath.Join(katalog, "duzy.log")
	var tresc strings.Builder
	for i := 0; i < 50; i++ {
		tresc.WriteString("linia ")
		tresc.WriteString(strings.Repeat("x", 10))
		tresc.WriteString("\n")
	}
	if err := os.WriteFile(sciezka, []byte(tresc.String()), 0o600); err != nil {
		t.Fatal(err)
	}

	allowlist := Allowlist{Wzorce: []string{filepath.Join(katalog, "*.log")}}
	fragment, err := Czytaj(allowlist, sciezka, 10)
	if err != nil {
		t.Fatalf("odczyt: %v", err)
	}
	if len(fragment.Lines) != 10 {
		t.Errorf("linii = %d, oczekiwano 10", len(fragment.Lines))
	}
	if !fragment.Truncated {
		t.Error("obciecie nie zostalo zaznaczone")
	}
	if fragment.SizeBytes == 0 {
		t.Error("rozmiar pliku nie zostal podany")
	}
}

// Katalog i gniazdo nie sa logiem; odczyt z potoku zawisnalby na zawsze.
func TestOdczytOdmawiaNiepliku(t *testing.T) {
	katalog := t.TempDir()
	podkatalog := filepath.Join(katalog, "logi.log")
	if err := os.Mkdir(podkatalog, 0o755); err != nil {
		t.Fatal(err)
	}
	allowlist := Allowlist{Wzorce: []string{filepath.Join(katalog, "*.log")}}
	if _, err := Czytaj(allowlist, podkatalog, 10); err == nil {
		t.Error("odczytano katalog jak plik")
	}
}

// Brak pliku administratora nie moze znaczyc "wszystko wolno".
func TestBrakPlikuDajeListeDomyslna(t *testing.T) {
	allowlist := WczytajAllowliste(filepath.Join(t.TempDir(), "nie-ma.allow"))
	if len(allowlist.Wzorce) == 0 {
		t.Fatal("pusty zakres przy braku pliku")
	}
	if allowlist.Dozwolona("/etc/shadow") {
		t.Error("lista domyslna dopuszcza /etc/shadow")
	}
	if !allowlist.Dozwolona("/var/log/syslog") {
		t.Error("lista domyslna nie dopuszcza typowego logu")
	}
}
