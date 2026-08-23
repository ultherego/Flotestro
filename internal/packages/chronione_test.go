package packages

import "testing"

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
