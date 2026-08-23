package ssh

import (
	"strings"
	"testing"
)

// Wyjscie przepisane z hosta floty testowej.
const wyjscieEffective = `port 22
addressfamily any
listenaddress [::]:22
listenaddress 0.0.0.0:22
usepam yes
maxauthtries 6
permitrootlogin no
pubkeyauthentication yes
passwordauthentication yes
kbdinteractiveauthentication no
gssapiauthentication no
allowgroups sudo flotestro`

func TestKonfiguracjaCzytanaZSerwera(t *testing.T) {
	stan := ParsujEffective(wyjscieEffective)

	if len(stan.Ports) != 1 || stan.Ports[0] != "22" {
		t.Errorf("porty = %v", stan.Ports)
	}
	if len(stan.ListenAddresses) != 2 {
		t.Errorf("adresy nasluchu = %v", stan.ListenAddresses)
	}
	// "prohibit-password" nie jest ani yes, ani no - dlatego wartosc jest
	// tekstem, a nie flaga.
	if stan.PermitRootLogin != "no" || stan.PasswordAuthentication != "yes" {
		t.Errorf("stan = %+v", stan)
	}
	if stan.MaxAuthTries != 6 {
		t.Errorf("maxauthtries = %d", stan.MaxAuthTries)
	}
	if len(stan.AllowGroups) != 2 || stan.AllowGroups[1] != "flotestro" {
		t.Errorf("grupy = %v", stan.AllowGroups)
	}
}

func TestOdciskKluczaHostaBezKluczaPrywatnego(t *testing.T) {
	klucz, ok := ParsujOdcisk(
		"256 SHA256:qLkjgPdb7MHXjfjzjsoBE8UhRXoe353g82iwnYYNmS4 root@debian-13 (ED25519)",
		"/etc/ssh/ssh_host_ed25519_key.pub")
	if !ok {
		t.Fatal("nie rozpoznano odcisku")
	}
	if klucz.Type != "ed25519" || klucz.Bits != 256 {
		t.Errorf("klucz = %+v", klucz)
	}
	if !strings.HasPrefix(klucz.Fingerprint, "SHA256:") {
		t.Errorf("odcisk = %q", klucz.Fingerprint)
	}
	if _, ok := ParsujOdcisk("cokolwiek", "/etc/ssh/x"); ok {
		t.Error("rozpoznano odcisk w smieciach")
	}
}

// Zapisujemy wylacznie to, o co operator poprosil: wypisanie calej
// konfiguracji zamrozilby na hoscie wartosci domyslne z dnia zapisu.
func TestDropInZawieraTylkoZleconeUstawienia(t *testing.T) {
	tresc, err := SkladajDropIn(Ustawienia{
		PermitRootLogin: "prohibit-password",
		MaxAuthTries:    "3",
		AllowGroups:     []string{"sudo", "flotestro"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(tresc, "PermitRootLogin prohibit-password") ||
		!strings.Contains(tresc, "AllowGroups sudo flotestro") {
		t.Errorf("tresc = %q", tresc)
	}
	if strings.Contains(tresc, "PasswordAuthentication") {
		t.Errorf("plik niesie ustawienie, o ktore nikt nie prosil: %q", tresc)
	}
	if !strings.HasPrefix(tresc, NaglowekPliku) {
		t.Errorf("plik bez naglowka: %q", tresc)
	}
	if _, err := SkladajDropIn(Ustawienia{}); err == nil {
		t.Error("przyjeto zmiane bez zadnego ustawienia")
	}
}

func TestZlaKonfiguracjaJestOdrzucana(t *testing.T) {
	przypadki := []Ustawienia{
		{Port: "0"},
		{Port: "70000"},
		{PermitRootLogin: "moze"},
		{PasswordAuthentication: "prohibit-password"},
		{MaxAuthTries: "0"},
		{AllowUsers: []string{"zly wpis"}},
		{DenyUsers: []string{"a;reboot"}},
	}
	for _, ustawienia := range przypadki {
		if err := Waliduj(ustawienia); err == nil {
			t.Errorf("przyjeto %+v", ustawienia)
		}
	}
	if err := Waliduj(Ustawienia{PermitRootLogin: "prohibit-password",
		AllowUsers: []string{"ulther", "admin@10.0.0.1", "flot*"}}); err != nil {
		t.Errorf("odrzucono poprawna konfiguracje: %v", err)
	}
}

// Serwer, do ktorego nie da sie zalogowac zadna metoda, nie jest
// zabezpieczony - jest niedostepny.
func TestZmianaOdcinajacaWszystkieMetodyJestRozpoznawana(t *testing.T) {
	stan := ParsujEffective(wyjscieEffective)

	if OdcinaWszystkieMetody(Ustawienia{PasswordAuthentication: "no"}, stan) {
		t.Error("wylaczenie hasla przy dzialajacych kluczach uznane za odciecie")
	}
	if !OdcinaWszystkieMetody(Ustawienia{
		PasswordAuthentication: "no", PubkeyAuthentication: "no"}, stan) {
		t.Error("wylaczenie hasla i kluczy nie zostalo rozpoznane")
	}
	// Host w domenie moze polegac na GSSAPI, wiec liczy sie takze ono.
	zDomena := stan
	zDomena.GSSAPIAuthentication = "yes"
	if OdcinaWszystkieMetody(Ustawienia{
		PasswordAuthentication: "no", PubkeyAuthentication: "no"}, zDomena) {
		t.Error("pominieto GSSAPI jako dzialajaca metode")
	}
}

// W sshd wygrywa pierwsza wartosc, a pliki dolaczane maja kolejnosc
// alfabetyczna: wczesniejszy plik administratora przeslania nasz i zmiana
// wyglada na wykonana, choc nic nie zmienia.
func TestRozbieznoscMiedzyZleceniemAStanemJestNazwana(t *testing.T) {
	stan := ParsujEffective(wyjscieEffective)

	rozbiezne := RozbiezneUstawienia(Ustawienia{
		PasswordAuthentication: "no", MaxAuthTries: "3"}, stan)
	if len(rozbiezne) != 2 {
		t.Fatalf("rozbieznosci = %v", rozbiezne)
	}
	if !strings.Contains(rozbiezne[0], "PasswordAuthentication") &&
		!strings.Contains(rozbiezne[1], "PasswordAuthentication") {
		t.Errorf("rozbieznosci = %v", rozbiezne)
	}
	if len(RozbiezneUstawienia(Ustawienia{PermitRootLogin: "no"}, stan)) != 0 {
		t.Error("zgodne ustawienie uznane za rozbiezne")
	}
}
