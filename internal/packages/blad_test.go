package packages

import (
	"strings"
	"testing"
)

// Dnf wypisuje paski postepu na stderr. Branie pierwszej linii dawalo
// operatorowi komunikat prawdziwy, bezuzyteczny i nie do odroznienia od
// sukcesu - dokladnie to widac bylo w panelu przy nieudanej aktualizacji.
func TestPasekPostepuNieJestPrzyczynaBledu(t *testing.T) {
	stderr := strings.Join([]string{
		"[ 1/36] Verify package files            100% |  33.0   B/s |  16.0   B |  00m00s",
		"[ 2/36] Prepare transaction             100% | 1.2 KiB/s |  36.0   B |  00m00s",
		"Error: Transaction failed: package nfs-utils-2.8.7 cannot be verified",
	}, "\n")

	opis := opisBledu(stderr, "")
	if strings.Contains(opis, "Verify package files") {
		t.Errorf("opis zawiera pasek postepu: %q", opis)
	}
	if !strings.Contains(opis, "Transaction failed") {
		t.Errorf("opis nie zawiera przyczyny: %q", opis)
	}
}

// Szczegoly bledu ida po linii ze znacznikiem, wiec nie moga zostac uciete.
func TestSzczegolyPoLiniiBleduSaZachowane(t *testing.T) {
	stderr := strings.Join([]string{
		"Error: Transaction test failed",
		"  file /usr/bin/foo conflicts between attempted installs",
	}, "\n")

	opis := opisBledu(stderr, "")
	if !strings.Contains(opis, "conflicts between") {
		t.Errorf("szczegoly bledu przepadly: %q", opis)
	}
}

// Wyjscie bez znacznika bledu tez cos znaczy - liczy sie jego koniec,
// a nie poczatek.
func TestBezZnacznikaLiczySieKoniecWyjscia(t *testing.T) {
	stderr := "pierwsza\ndruga\ntrzecia\nczwarta\npiata"
	opis := opisBledu(stderr, "")
	if strings.Contains(opis, "pierwsza") {
		t.Errorf("opis zaczyna sie od poczatku wyjscia: %q", opis)
	}
	if !strings.Contains(opis, "piata") {
		t.Errorf("opis pomija koniec wyjscia: %q", opis)
	}
}

// Apt pisze przyczyne na stdout, gdy stderr milczy.
func TestPrzyczynaZeStdoutGdyStderrMilczy(t *testing.T) {
	stdout := "Reading database ... 45%\nE: Sub-process /usr/bin/dpkg returned an error code (1)"
	opis := opisBledu("", stdout)
	if !strings.Contains(opis, "Sub-process") {
		t.Errorf("opis pomija przyczyne ze stdout: %q", opis)
	}
	if strings.Contains(opis, "Reading database") {
		t.Errorf("opis zawiera linie postepu: %q", opis)
	}
}

// Wyjscie zlozone wylacznie z paskow postepu nie niesie przyczyny i lepiej
// powiedziec to wprost niz zacytowac pasek.
func TestSameePaskiPostepuNieDajaOpisu(t *testing.T) {
	stderr := "[ 1/36] Verify package files 100% |  33.0   B/s |  16.0   B |  00m00s"
	if opis := opisBledu(stderr, ""); opis != "" {
		t.Errorf("opis = %q, oczekiwano pustego", opis)
	}
}

// Dlugie wyjscie jest przycinane widocznie: urwany komunikat bez znaku
// wygladalby na pelna tresc bledu.
func TestDlugiOpisJestPrzycietyWidocznie(t *testing.T) {
	stderr := "Error: " + strings.Repeat("a", 1000)
	opis := opisBledu(stderr, "")
	if len([]rune(opis)) > maksymalnaDlugoscPowodu+1 {
		t.Errorf("opis ma %d znakow", len([]rune(opis)))
	}
	if !strings.HasSuffix(opis, "…") {
		t.Error("przyciecie nie jest oznaczone")
	}
}
