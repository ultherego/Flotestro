package security

import "testing"

func TestTrybDzialajacyIKonfiguracjaToDwaPola(t *testing.T) {
	if tryb := ParsujTrybWymuszania("1\n"); tryb != TrybEnforcing {
		t.Fatalf("tryb = %q", tryb)
	}
	if tryb := ParsujTrybWymuszania("0"); tryb != TrybPermissive {
		t.Fatalf("tryb = %q", tryb)
	}
	// Plik, ktorego nie ma, nie oznacza trybu permissive.
	if tryb := ParsujTrybWymuszania(""); tryb != "" {
		t.Fatalf("pusty odczyt stal sie trybem %q", tryb)
	}

	tryb, polityka := ParsujKonfiguracjeSELinux("# komentarz\nSELINUX=enforcing\nSELINUXTYPE=targeted\n")
	if tryb != TrybEnforcing || polityka != "targeted" {
		t.Fatalf("konfiguracja = %q/%q", tryb, polityka)
	}
}

// Profil w trybie skarg nie chroni, tylko notuje - liczenie go razem
// z wymuszanymi zamienialo by brak ochrony w ochrone.
func TestProfileAppArmoraLiczaSieOsobno(t *testing.T) {
	wymuszane, skargi := ParsujProfileAppArmor(
		"docker-default (enforce)\nlibreoffice (complain)\nwike (unconfined)\nfoo (enforce)\n")
	if wymuszane != 2 || skargi != 1 {
		t.Fatalf("wymuszane = %d, skargi = %d", wymuszane, skargi)
	}

	// Host z samymi profilami w trybie skarg nie jest chroniony.
	zero, jeden := 0, 1
	chroniony := Mandatory{System: SystemAppArmor, ProfilesEnforcing: &zero, ProfilesComplain: &jeden}
	if chroniony.Chroni() {
		t.Error("same profile w trybie skarg uznane za ochrone")
	}
	if !(Mandatory{System: SystemAppArmor, ProfilesEnforcing: &jeden}).Chroni() {
		t.Error("profil wymuszany nie uznany za ochrone")
	}
	if !(Mandatory{System: SystemSELinux, Mode: TrybEnforcing}).Chroni() {
		t.Error("SELinux w trybie enforcing nie uznany za ochrone")
	}
	if (Mandatory{System: SystemSELinux, Mode: TrybPermissive}).Chroni() {
		t.Error("SELinux w trybie permissive uznany za ochrone")
	}
}

func TestNasluchKlasyfikujeZasiegGniazda(t *testing.T) {
	wyjscie := `udp   UNCONN 0 0    127.0.0.53%lo:53    0.0.0.0:* users:(("systemd-resolve",pid=560,fd=16))
tcp   LISTEN 0 128        0.0.0.0:22    0.0.0.0:* users:(("sshd",pid=1200,fd=3))
tcp   LISTEN 0 128           [::]:22       [::]:* users:(("sshd",pid=1200,fd=4))
udp   UNCONN 0 0        127.0.0.1:323    0.0.0.0:*
raw   UNCONN 0 0          0.0.0.0:1      0.0.0.0:*
`
	gniazda := ParsujNasluch(wyjscie)
	if len(gniazda) != 4 {
		t.Fatalf("gniazd = %d: %+v", len(gniazda), gniazda)
	}
	if gniazda[0].Reach != ZasiegPetla {
		t.Errorf("gniazdo na petli zwrotnej ma zasieg %q", gniazda[0].Reach)
	}
	if gniazda[1].Port != 22 || gniazda[1].Process != "sshd" || gniazda[1].PID != 1200 {
		t.Errorf("gniazdo sshd = %+v", gniazda[1])
	}
	// Nasluch na wszystkich interfejsach jest inna sytuacja niz nasluch na
	// jednym adresie hosta - i zadna z nich nie znaczy "widoczne z internetu".
	if gniazda[1].Reach != ZasiegWszystkie || gniazda[2].Reach != ZasiegWszystkie {
		t.Errorf("zasiegi = %q, %q", gniazda[1].Reach, gniazda[2].Reach)
	}
	if Zasieg("192.168.56.30") != ZasiegAdresHosta {
		t.Errorf("adres hosta sklasyfikowany jako %q", Zasieg("192.168.56.30"))
	}
	if Zasieg("203.0.113.7") != ZasiegAdresHosta {
		t.Error("adres publiczny nie jest sam z siebie inna klasa niz prywatny")
	}
	// Adres IPv6 sam zawiera dwukropki: port bierzemy po ostatnim.
	if gniazda[2].Address != "::" || gniazda[2].Port != 22 {
		t.Errorf("gniazdo IPv6 = %+v", gniazda[2])
	}
	snapshot := Snapshot{Listening: gniazda}
	if len(snapshot.PozaPetla()) != 2 {
		t.Errorf("poza petla = %d", len(snapshot.PozaPetla()))
	}
	if liczby := snapshot.WedlugZasiegu(); liczby[ZasiegWszystkie] != 2 || liczby[ZasiegPetla] != 2 {
		t.Errorf("podzial wedlug zasiegu = %v", liczby)
	}
}

// Reguly zapisane w plikach i reguly zaladowane do jadra to dwa pytania.
func TestRegulyZPlikuNieLiczaKomentarzy(t *testing.T) {
	tresc := "# reguly panelu\n\n-D\n-w /etc/passwd -p wa -k tozsamosc\n" +
		"-a always,exit -F arch=b64 -S execve\n"
	if reguly := ParsujRegulyZPliku(tresc); reguly != 2 {
		t.Fatalf("reguly z pliku = %d", reguly)
	}
}

// Fakt, o ktory nie pytano, i fakt nieodczytany to dwie rozne odpowiedzi.
func TestUzupelnienieZamykaBrakiAlboZostawiaPowod(t *testing.T) {
	dwa := 2
	snapshot := Snapshot{
		MAC:       Mandatory{System: SystemAppArmor, Mode: TrybEnforcing},
		Audit:     Audyt{Present: true},
		Listening: []Nasluch{{Protocol: "tcp", Address: "0.0.0.0", Port: 22, Reach: ZasiegWszystkie}},
		Missing: map[string]string{
			FaktProfileAppArmor:   "profile AppArmora leza w securityfs",
			FaktWlascicieleGniazd: "wlascicieli gniazd widzi tylko root",
			FaktRegulyAudytu:      "reguly audytu czyta tylko root",
		},
	}

	uzupelniony := snapshot.Uzupelnij(Uzupelnienie{
		ProfilesEnforcing: &dwa,
		SocketOwners: map[string]Wlasciciel{
			KluczGniazda("tcp", "0.0.0.0", 22): {Process: "sshd", PID: 1200},
		},
		Errors: map[string]string{FaktRegulyAudytu: "auditctl: brak uprawnien"},
	})

	if uzupelniony.MAC.ProfilesEnforcing == nil || *uzupelniony.MAC.ProfilesEnforcing != 2 {
		t.Errorf("profile = %v", uzupelniony.MAC.ProfilesEnforcing)
	}
	if !uzupelniony.OwnersKnown || uzupelniony.Listening[0].Process != "sshd" {
		t.Errorf("wlasciciele = %+v", uzupelniony.Listening[0])
	}
	// Fakt, ktorego helper nie odczytal, zostaje brakiem razem z powodem.
	if uzupelniony.Missing[FaktRegulyAudytu] == "" {
		t.Error("nieudany odczyt regul zniknal z listy brakow")
	}
	if _, wciazBrakuje := uzupelniony.Missing[FaktProfileAppArmor]; wciazBrakuje {
		t.Error("odczytany fakt zostal na liscie brakow")
	}
}

func TestRegulyIStanyPomocnicze(t *testing.T) {
	if reguly := ParsujReguly("No rules\n"); reguly != 0 {
		t.Fatalf("reguly = %d", reguly)
	}
	if reguly := ParsujReguly("-a never,task\n-w /etc/passwd -p wa\n"); reguly != 2 {
		t.Fatalf("reguly = %d", reguly)
	}
	if tryb := ParsujLockdown("[none] integrity confidentiality\n"); tryb != "none" {
		t.Fatalf("lockdown = %q", tryb)
	}
	if stan := ParsujSecureBoot([]byte{6, 0, 0, 0, 1}); stan == nil || !*stan {
		t.Fatalf("secure boot = %v", stan)
	}
	// Zmienna krotsza niz naglowek nie mowi nic; nie zmyslamy falszu.
	if stan := ParsujSecureBoot([]byte{6, 0, 0, 0}); stan != nil {
		t.Fatalf("niepelna zmienna stala sie %v", *stan)
	}
}

// Panel przelacza miedzy enforcing i permissive; wylaczenia nie ustawia, bo
// powrot wymaga przeetykietowania systemu plikow i restartu.
func TestPanelNieWylaczaSELinuksa(t *testing.T) {
	if err := WalidujTryb(TrybEnforcing); err != nil {
		t.Errorf("enforcing odrzucony: %v", err)
	}
	if err := WalidujTryb(TrybPermissive); err != nil {
		t.Errorf("permissive odrzucony: %v", err)
	}
	if err := WalidujTryb(TrybDisabled); err == nil {
		t.Error("panel przyjal wylaczenie SELinuksa")
	}
	if err := WalidujTryb("cokolwiek"); err == nil {
		t.Error("nieznany tryb przeszedl walidacje")
	}
}
