package czas

import (
	"context"
	"math"
	"strings"
	"testing"
)

func TestTrackingCzytaPrzesuniecieIStratum(t *testing.T) {
	wyjscie := "C0248F97,192.168.1.1,3,1755978000.123456,-0.000123,-0.000045," +
		"0.000234,-1.234,0.001,0.123,0.002345,0.012345,64,Normal\n"
	snapshot := ParsujTracking(wyjscie)

	if snapshot.ReferenceName != "192.168.1.1" {
		t.Fatalf("referencja: %q", snapshot.ReferenceName)
	}
	if snapshot.Stratum == nil || *snapshot.Stratum != 3 {
		t.Fatalf("stratum: %v", snapshot.Stratum)
	}
	if snapshot.OffsetSeconds == nil || math.Abs(*snapshot.OffsetSeconds+0.000123) > 1e-9 {
		t.Fatalf("przesuniecie: %v", snapshot.OffsetSeconds)
	}
	if snapshot.LeapStatus != "Normal" {
		t.Fatalf("leap: %q", snapshot.LeapStatus)
	}
	if !snapshot.Zsynchronizowany() {
		t.Fatal("demon z wybranym zrodlem ma byc zsynchronizowany")
	}
}

// Demon bez wybranego zrodla dziala, ale nie jest zsynchronizowany. To dwie
// rozne odpowiedzi i wynik nie moze ich zlewac.
func TestTrackingBezZrodlaNieJestZsynchronizowany(t *testing.T) {
	wyjscie := "00000000,0.0.0.0,0,0.000000,0.000000,0.000000,0.000000," +
		"0.000,0.000,0.000,0.000000,0.000000,0,Not synchronised\n"
	snapshot := ParsujTracking(wyjscie)

	if snapshot.ReferenceName != "" {
		t.Fatalf("pusta referencja zostala nazwa: %q", snapshot.ReferenceName)
	}
	if snapshot.Stratum != nil {
		t.Fatalf("stratum zero nie jest stratum: %v", *snapshot.Stratum)
	}
	if snapshot.Zsynchronizowany() {
		t.Fatal("demon bez zrodla nie jest zsynchronizowany")
	}
}

func TestZrodlaTlumaczaZnakiNaSlowa(t *testing.T) {
	zrodla := ParsujZrodla("^,*,192.168.1.1,3,6,377,23,-0.000123,-0.000125,0.000456\n" +
		"^,?,10.0.0.9,0,6,0,-,0.000000,0.000000,0.000000\n")
	if len(zrodla) != 2 {
		t.Fatalf("zrodla: %d", len(zrodla))
	}
	if zrodla[0].Mode != "server" || zrodla[0].State != "selected" {
		t.Fatalf("pierwsze zrodlo: %+v", zrodla[0])
	}
	if zrodla[0].PollSeconds == nil || *zrodla[0].PollSeconds != 64 {
		t.Fatalf("odstep odpytywania: %v", zrodla[0].PollSeconds)
	}
	if zrodla[1].State != "unreachable" {
		t.Fatalf("drugie zrodlo: %+v", zrodla[1])
	}
	if zrodla[1].LastRxSeconds != nil {
		t.Fatalf("brak pomiaru nie jest zerem: %v", *zrodla[1].LastRxSeconds)
	}
}

func TestKatalogDropInWybieraKatalogWlaczanyPrzezDemona(t *testing.T) {
	przypadki := []struct {
		nazwa   string
		tresc   string
		katalog string
		rodzaj  string
	}{
		{"confdir", "pool 2.debian.pool.ntp.org iburst\nconfdir /etc/chrony/conf.d\n",
			"/etc/chrony/conf.d", RodzajKonfiguracji},
		{"sourcedir", "sourcedir /etc/chrony/sources.d\n",
			"/etc/chrony/sources.d", RodzajZrodel},
		{"include", "include /etc/chrony.d/*.conf\n", "/etc/chrony.d", RodzajKonfiguracji},
		{"komentarz", "# confdir /etc/chrony/conf.d\n", "", ""},
		{"brak", "server 10.0.0.1 iburst\n", "", ""},
	}
	for _, przypadek := range przypadki {
		t.Run(przypadek.nazwa, func(t *testing.T) {
			katalog, rodzaj := KatalogDropIn(przypadek.tresc)
			if katalog != przypadek.katalog || rodzaj != przypadek.rodzaj {
				t.Fatalf("wyszlo %q/%q, oczekiwano %q/%q",
					katalog, rodzaj, przypadek.katalog, przypadek.rodzaj)
			}
		})
	}
}

// Katalog zrodel z DHCP zyje w /run i znika po restarcie. Panel trzyma tam
// stan docelowy tylko wtedy, gdyby chcial go stracic.
func TestKatalogDropInPomijaKatalogUlotny(t *testing.T) {
	katalog, _ := KatalogDropIn("sourcedir /run/chrony-dhcp\n")
	if katalog != "" {
		t.Fatalf("katalog w /run zostal wybrany: %q", katalog)
	}
}

func TestSkladanieKonfiguracji(t *testing.T) {
	tresc, err := SkladajChrony([]string{"10.0.0.1", "ntp.example.org"}, RodzajKonfiguracji)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tresc, NaglowekPliku) {
		t.Fatalf("plik konfiguracji bez naglowka panelu: %q", tresc)
	}
	if !strings.Contains(tresc, "server 10.0.0.1 iburst") {
		t.Fatalf("brak wpisu serwera: %q", tresc)
	}

	// Katalog zrodel przyjmuje wylacznie dyrektywy serwerow, wiec naglowka
	// tam nie ma - wlascicielem pliku jest jego nazwa.
	zrodla, err := SkladajChrony([]string{"10.0.0.1"}, RodzajZrodel)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(zrodla, "#") {
		t.Fatalf("plik zrodel z komentarzem: %q", zrodla)
	}
}

func TestOdrzuconeSerweryIStrefy(t *testing.T) {
	if err := WalidujSerwer("10.0.0.1 iburst\nallow all"); err == nil {
		t.Fatal("adres z nowa linia przeszedl walidacje")
	}
	if err := WalidujSerwery([]string{"10.0.0.1", "10.0.0.1"}); err == nil {
		t.Fatal("powtorzony serwer przeszedl walidacje")
	}
	if err := WalidujSerwery(nil); err == nil {
		t.Fatal("pusta lista przeszla walidacje")
	}
	if err := WalidujStrefe("../../etc/passwd"); err == nil {
		t.Fatal("sciezka wzgledna przeszla jako strefa")
	}
	if err := WalidujStrefe("Europe/Warsaw"); err != nil {
		t.Fatalf("poprawna strefa odrzucona: %v", err)
	}
}

func TestTimesyncCzytaKomunikatNTP(t *testing.T) {
	wyjscie := "SystemNTPServers=ntp.example.org\n" +
		"FallbackNTPServers=0.debian.pool.ntp.org\n" +
		"ServerName=ntp.example.org\nServerAddress=10.0.0.1\n" +
		"NTPMessage={ Leap=0, Version=4, Mode=4, Stratum=2, Precision=-24, " +
		"RootDelay=1.907ms, RootDispersion=15.945ms, Reference=C0248F97 }\n"
	stan := ParsujTimesync(wyjscie, "timesyncd.conf")

	if stan.Stratum == nil || *stan.Stratum != 2 {
		t.Fatalf("stratum: %v", stan.Stratum)
	}
	if stan.RootDelay == nil || math.Abs(*stan.RootDelay-0.001907) > 1e-9 {
		t.Fatalf("root delay: %v", stan.RootDelay)
	}
	if stan.LeapStatus != "Normal" {
		t.Fatalf("leap: %q", stan.LeapStatus)
	}
	if len(stan.Servers) != 2 || stan.Servers[1].Source != "systemd fallback" {
		t.Fatalf("serwery: %+v", stan.Servers)
	}
}

func TestSkokLiczySieOdProguSekundy(t *testing.T) {
	male := 0.2
	duze := -3.5
	opoznienieMale, opoznienieDuze := 0.01, 0.2
	pomiary := []Pomiar{
		{Server: "wolny", Reachable: true, OffsetSeconds: &duze, DelaySeconds: &opoznienieDuze},
		{Server: "szybki", Reachable: true, OffsetSeconds: &male, DelaySeconds: &opoznienieMale},
		{Server: "martwy"},
	}
	if Osiagalne(pomiary) != 2 {
		t.Fatalf("osiagalne: %d", Osiagalne(pomiary))
	}
	najlepszy := NajlepszyPomiar(pomiary)
	if najlepszy == nil || najlepszy.Server != "szybki" {
		t.Fatalf("wybrany pomiar: %+v", najlepszy)
	}
	if Skok(najlepszy) {
		t.Fatal("dwie dziesiate sekundy nie sa skokiem")
	}
	if !Skok(&pomiary[0]) {
		t.Fatal("trzy i pol sekundy jest skokiem")
	}
}

// Systemd odpowiada "inactive" takze na pytanie o jednostke, ktorej na hoscie
// nie ma. Bez stanu wczytania panel nazywalby chronyego na hoscie, na ktorym
// go nie zainstalowano.
func TestJednostkaDemonaPomijaJednostkiNieznaneHostowi(t *testing.T) {
	wyjscie := "Id=chronyd.service\nLoadState=not-found\nActiveState=inactive\n\n" +
		"Id=chrony.service\nLoadState=not-found\nActiveState=inactive\n\n" +
		"ActiveState=active\nId=systemd-timesyncd.service\nLoadState=loaded\n"
	uruchom := func(_ context.Context, _ string, _ ...string) (string, error) { return wyjscie, nil }

	nazwa, aktywna := jednostkaDemona(context.Background(), uruchom)
	if nazwa != "systemd-timesyncd.service" {
		t.Fatalf("jednostka: %q", nazwa)
	}
	if aktywna == nil || !*aktywna {
		t.Fatalf("stan jednostki: %v", aktywna)
	}
}

// Jednostka zainstalowana, ale zatrzymana, jest inna odpowiedzia niz jej brak.
func TestJednostkaDemonaZglaszaZatrzymana(t *testing.T) {
	wyjscie := "Id=chronyd.service\nLoadState=loaded\nActiveState=inactive\n\n" +
		"Id=chrony.service\nLoadState=not-found\nActiveState=inactive\n\n" +
		"Id=systemd-timesyncd.service\nLoadState=masked\nActiveState=inactive\n"
	uruchom := func(_ context.Context, _ string, _ ...string) (string, error) { return wyjscie, nil }

	nazwa, aktywna := jednostkaDemona(context.Background(), uruchom)
	if nazwa != "chronyd.service" {
		t.Fatalf("jednostka: %q", nazwa)
	}
	if aktywna == nil || *aktywna {
		t.Fatalf("zatrzymana jednostka zgloszona jako aktywna: %v", aktywna)
	}
}
