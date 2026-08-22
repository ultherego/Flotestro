package opspec

import "testing"

func TestWalidacjaKontaLokalnego(t *testing.T) {
	klucz := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHZ8Kx3vQOZKq0M0hDPuJHf5Zx1kJHgqRqYqGZ6XxLm1 jan@stacja"

	poprawne := Payload{LocalUser: &LocalUserPayload{
		Name: "kowalski", Shell: "/bin/bash", Groups: []string{"sudo"}, SSHKeys: []string{klucz},
	}}
	if err := Validate(ActionLocalUserCreate, poprawne); err != nil {
		t.Fatalf("poprawny payload odrzucony: %v", err)
	}

	// Pusta lista kluczy jest swiadomym odebraniem dostepu, a nie brakiem danych.
	pusta := Payload{LocalUser: &LocalUserPayload{Name: "kowalski", SSHKeys: []string{}}}
	if err := Validate(ActionLocalSSHKeysSet, pusta); err != nil {
		t.Fatalf("odebranie kluczy musi byc dozwolone: %v", err)
	}

	przypadki := map[string]LocalUserPayload{
		"nazwa z wielka litera": {Name: "Kowalski"},
		"nazwa ze sciezka":      {Name: "../root"},
		"nazwa pusta":           {Name: ""},
		"powloka wzgledna":      {Name: "kowalski", Shell: "bash"},
		"dwukropek w opisie":    {Name: "kowalski", Gecos: "Jan:Kowalski"},
		"grupa nieprawidlowa":   {Name: "kowalski", Groups: []string{"su do"}},
		"klucz prywatny":        {Name: "kowalski", SSHKeys: []string{"-----BEGIN OPENSSH PRIVATE KEY-----"}},
		"klucz z nowa linia":    {Name: "kowalski", SSHKeys: []string{klucz + "\nssh-rsa AAAA"}},
		"typ klucza nieznany":   {Name: "kowalski", SSHKeys: []string{"ssh-dss AAAAB3Nz jan"}},
		"klucz bez materialu":   {Name: "kowalski", SSHKeys: []string{"ssh-ed25519"}},
		"klucz pusty":           {Name: "kowalski", SSHKeys: []string{"   "}},
	}
	for nazwa, payload := range przypadki {
		if err := Validate(ActionLocalUserCreate, payload.copy()); err == nil {
			t.Errorf("%s: payload powinien zostac odrzucony", nazwa)
		}
	}

	if err := Validate(ActionLocalUserLock, Payload{}); err == nil {
		t.Error("operacja bez payloadu musi byc odrzucona")
	}
}

// copy pozwala uzyc tej samej struktury w tabeli przypadkow bez wspoldzielenia.
func (p LocalUserPayload) copy() Payload {
	kopia := p
	return Payload{LocalUser: &kopia}
}

func TestOperacjeKontLokalnychMajaOsobneUprawnienia(t *testing.T) {
	// Blokada i odblokowanie sa rozdzielone celowo: w reakcji na incydent
	// odciecie konta bywa dozwolone tam, gdzie przywrocenie dostepu nie jest.
	if ActionLocalUserLock.Permission() == ActionLocalUserUnlock.Permission() {
		t.Error("blokada i odblokowanie musza miec osobne uprawnienia")
	}
	for _, action := range []ActionType{
		ActionLocalUserCreate, ActionLocalUserLock, ActionLocalUserUnlock, ActionLocalSSHKeysSet,
	} {
		if !action.Mutating() {
			t.Errorf("%s zmienia stan hosta", action)
		}
		// Konta lokalne dzialaja tez tam, gdzie nie ma systemd ani katalogu.
		if action.RequiredCapability() != "" {
			t.Errorf("%s nie powinna wymagac zdolnosci hosta", action)
		}
	}
}

// TestWalidacjaNaprawyPakietow pilnuje granic operacji naprawy. Odpowiedz na
// pytanie konfiguracyjne trafia do wejscia debconfa, gdzie kazdy wiersz jest
// osobnym ustawieniem: wartosc ze znakiem nowej linii pozwalalaby dopisac
// ustawienia, o ktore nikt nie prosil.
func TestWalidacjaNaprawyPakietow(t *testing.T) {
	poprawna := Payload{PackageRepair: &PackageRepairPayload{
		Answers: []DebconfAnswer{{
			Package: "grub-pc", Question: "grub-pc/install_devices",
			Type: "multiselect", Value: "/dev/sda",
		}},
	}}
	if err := Validate(ActionPackageRepair, poprawna); err != nil {
		t.Fatalf("poprawna odpowiedz odrzucona: %v", err)
	}

	// Naprawa bez odpowiedzi jest dozwolona: samo dokonczenie konfiguracji
	// wystarcza, gdy poprzednia transakcja zostala przerwana.
	if err := Validate(ActionPackageRepair, Payload{PackageRepair: &PackageRepairPayload{}}); err != nil {
		t.Fatalf("naprawa bez odpowiedzi odrzucona: %v", err)
	}

	przypadki := map[string]DebconfAnswer{
		"nazwa pytania bez pakietu": {Package: "grub-pc", Question: "install_devices", Type: "string", Value: "x"},
		"pytanie ze sciezka":        {Package: "grub-pc", Question: "../../etc/passwd", Type: "string", Value: "x"},
		"typ nieznany":              {Package: "grub-pc", Question: "grub-pc/x", Type: "shell", Value: "x"},
		"wartosc z nowa linia":      {Package: "grub-pc", Question: "grub-pc/x", Type: "string", Value: "a\nb c d"},
		"pakiet nieprawidlowy":      {Package: "grub pc", Question: "grub-pc/x", Type: "string", Value: "x"},
	}
	for nazwa, answer := range przypadki {
		payload := Payload{PackageRepair: &PackageRepairPayload{Answers: []DebconfAnswer{answer}}}
		if err := Validate(ActionPackageRepair, payload); err == nil {
			t.Errorf("%s: payload powinien zostac odrzucony", nazwa)
		}
	}

	if ActionPackageRepair.Permission() == ActionPackageUpgrade.Permission() {
		t.Error("naprawa musi miec uprawnienie osobne od aktualizacji")
	}
	if !ActionPackageRepair.Mutating() {
		t.Error("naprawa zmienia stan hosta")
	}
}
