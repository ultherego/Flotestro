package ssh

import (
	"strings"
	"testing"
)

func stanTestowy() Snapshot {
	return Snapshot{
		Ports: []string{"22"}, PermitRootLogin: "prohibit-password",
		PasswordAuthentication: "yes", PubkeyAuthentication: "yes",
		KbdInteractive: "no", MaxAuthTries: 6,
	}
}

func TestPlanSSHOdrozniaZmianeOdStanuDocelowego(t *testing.T) {
	zmiana := Zaplanuj(stanTestowy(), Ustawienia{PasswordAuthentication: "no"}, false)
	if zmiana.Action != PlanZmienia || zmiana.Refusal != "" {
		t.Fatalf("plan zmiany: %+v", zmiana)
	}
	if len(zmiana.Changes) != 2 || !strings.Contains(zmiana.Changes[0], "PasswordAuthentication z yes na no") ||
		zmiana.Changes[1] != "plik panelu powstanie" {
		t.Errorf("zmiany: %v", zmiana.Changes)
	}
	if zmiana.Current["PasswordAuthentication"] != "yes" {
		t.Errorf("stan zastany: %v", zmiana.Current)
	}

	stan := stanTestowy()
	stan.PasswordAuthentication = "no"
	stan.ManagedPresent = true
	stan.Managed, _ = SkladajDropIn(Ustawienia{PasswordAuthentication: "no"})
	bez := Zaplanuj(stan, Ustawienia{PasswordAuthentication: "no"}, false)
	if bez.Action != PlanBezZmian || len(bez.Changes) != 0 {
		t.Errorf("stan docelowy policzony jako zmiana: %+v", bez)
	}
	if bez.PlanHash == zmiana.PlanHash || bez.ManagedHash == "" {
		t.Error("odciski planow nie roznia sie albo brak odcisku pliku")
	}

	// Serwer stosuje juz zadana wartosc, ale z innego pliku: plik panelu
	// i tak zostanie nadpisany, wiec to jest zmiana.
	stan.Managed = "# inny plik\nMaxAuthTries 3\n"
	inny := Zaplanuj(stan, Ustawienia{PasswordAuthentication: "no"}, false)
	if inny.Action != PlanZmienia || inny.Changes[0] != "plik panelu zostanie nadpisany" {
		t.Errorf("nadpisanie pliku panelu bez zmiany: %+v", inny)
	}
}

func TestPlanSSHOdmawiaOdcieciaIZlejWartosci(t *testing.T) {
	odciecie := Zaplanuj(stanTestowy(), Ustawienia{
		PasswordAuthentication: "no", PubkeyAuthentication: "no"}, false)
	if !strings.Contains(odciecie.Refusal, "metoda uwierzytelnienia") {
		t.Errorf("odciecie bez odmowy: %+v", odciecie)
	}
	zgoda := Zaplanuj(stanTestowy(), Ustawienia{
		PasswordAuthentication: "no", PubkeyAuthentication: "no"}, true)
	if zgoda.Refusal != "" {
		t.Errorf("jawna zgoda nie zdjela odmowy: %+v", zgoda)
	}
	zla := Zaplanuj(stanTestowy(), Ustawienia{PermitRootLogin: "moze"}, false)
	if zla.Refusal == "" {
		t.Error("zla wartosc przeszla bez odmowy")
	}
	pusta := Zaplanuj(stanTestowy(), Ustawienia{}, false)
	if pusta.Refusal == "" {
		t.Error("zmiana bez ustawien przeszla bez odmowy")
	}
	bezSerwera := Zaplanuj(Snapshot{UnavailableReason: "ten host nie ma serwera sshd"},
		Ustawienia{Port: "22"}, false)
	if bezSerwera.Refusal == "" || bezSerwera.PlanHash == "" {
		t.Errorf("host bez sshd: %+v", bezSerwera)
	}
}
