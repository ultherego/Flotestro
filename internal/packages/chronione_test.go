package packages

import (
	"context"
	"os"
	"testing"
)

// Usuniecie agenta odcina host od panelu, a wiec takze od naprawy tego, co
// wlasnie zostalo zepsute. Usuniecie jadra albo bootloadera zostawia maszyne,
// ktora nie wstanie.
func TestChronionePakietySaRozpoznawane(t *testing.T) {
	chronione := []string{
		"flotestro-agent", "openssh-server", "systemd", "sudo",
		"linux-image-6.12.48+deb13-amd64", "grub-pc", "grub-efi-amd64",
		"apt", "dpkg", "dnf", "rpm", "kernel-core", "systemd-sysv",
		"SYSTEMD", "systemd:amd64",
	}
	for _, pakiet := range chronione {
		if !Chroniony(pakiet) {
			t.Errorf("pakiet %q nie zostal rozpoznany jako chroniony", pakiet)
		}
	}
}

// Ochrona nie moze rozlac sie na wszystko: panel, ktory odmawia usuniecia
// czegokolwiek, nie jest panelem zarzadzania.
func TestZwyklePakietyNieSaChronione(t *testing.T) {
	zwykle := []string{"nginx", "htop", "sl", "postgresql-16", "vim", "curl", "", "  "}
	for _, pakiet := range zwykle {
		if Chroniony(pakiet) {
			t.Errorf("pakiet %q zostal uznany za chroniony", pakiet)
		}
	}
}

// Operator ma wiedziec, ktory pakiet blokuje operacje, a nie tylko ze cos ja
// blokuje.
func TestChronioneWZbiorzeWskazujaWinowajce(t *testing.T) {
	wynik := ChronioneWZbiorze([]string{"nginx", "systemd", "htop", "linux-image-6.12"})
	if len(wynik) != 2 {
		t.Fatalf("znaleziono %d chronionych, oczekiwano 2: %v", len(wynik), wynik)
	}
	if wynik[0] != "systemd" || wynik[1] != "linux-image-6.12" {
		t.Errorf("chronione = %v", wynik)
	}
	if ChronioneWZbiorze([]string{"nginx", "htop"}) != nil {
		t.Error("zbior bez chronionych zwrocil niepusta liste")
	}
}

// TestSrodowiskoWstrzymujeNeedrestart pilnuje granicy, ktora kosztowala
// zadanie w laboratorium: needrestart restartowal helpera w srodku transakcji,
// ktora helper wlasnie prowadzil, i wynik konczyl sie "odpowiedz helpera: EOF".
// Restart jest decyzja panelu, a nie efektem ubocznym aktualizacji.
func TestSrodowiskoWstrzymujeNeedrestart(t *testing.T) {
	srodowiskoTestu := srodowisko()
	szukane := map[string]bool{
		"NEEDRESTART_MODE=l":             false,
		"DEBIAN_FRONTEND=noninteractive": false,
	}
	for _, wpis := range srodowiskoTestu {
		if _, ok := szukane[wpis]; ok {
			szukane[wpis] = true
		}
	}
	for wpis, jest := range szukane {
		if !jest {
			t.Errorf("srodowisko transakcji nie ustawia %s", wpis)
		}
	}
}

// TestPorzuconeWstrzymanieZwalniaSieTylkoWlasne pilnuje granicy sprzatania:
// wstrzymanie zalozone przez administratora hosta zostaje, a nasze wlasne -
// zostawione przez transakcje, ktora zginela razem z procesem - znika.
// Bez tego host z przerwana aktualizacja mial pakiet agenta wstrzymany na
// zawsze i zadna pozniejsza wymiana agenta nie mogla przejsc.
func TestPorzuconeWstrzymanieZwalniaSieTylkoWlasne(t *testing.T) {
	katalog := t.TempDir()
	if err := SetRuntimeDir(katalog); err != nil {
		t.Fatal(err)
	}

	// Bez sladu nie ma czego zwalniac: cudze wstrzymanie zostaje nietkniete.
	zwolniono, err := ZwolnijPorzuconeWstrzymanie(context.Background())
	if err != nil {
		t.Fatalf("sprzatanie bez sladu: %v", err)
	}
	if zwolniono {
		t.Error("zwolniono wstrzymanie, ktorego nie zalozylismy")
	}

	// Slad znika nawet wtedy, gdy narzedzia nie ma: inaczej proba
	// powtarzalaby sie przy kazdym starcie helpera.
	if err := os.WriteFile(sladWstrzymania(), []byte(PakietAgenta), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ZwolnijPorzuconeWstrzymanie(context.Background()); err != nil {
		t.Fatalf("sprzatanie ze sladem: %v", err)
	}
	if _, err := os.Stat(sladWstrzymania()); !os.IsNotExist(err) {
		t.Error("slad wstrzymania zostal po sprzataniu")
	}
}
