package agent

import (
	"os"
	"path/filepath"
	"testing"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
)

func TestPorownanieStanuKonta(t *testing.T) {
	prawda, falsz := true, false

	konto := func() *LocalAccount {
		return &LocalAccount{
			Name: "kowalski", Shell: "/bin/bash", Groups: []string{"sudo", "kowalski"},
			Locked: &falsz, PasswordSet: &falsz,
			SSHKeys: []SSHKeyInfo{{Fingerprint: "SHA256:aaa"}},
		}
	}

	if !sameAccountState(konto(), konto()) {
		t.Error("identyczny stan musi byc rozpoznany jako niezmieniony")
	}

	// Kolejnosc grup i kluczy zalezy od systemu i nie jest zmiana stanu.
	inna := konto()
	inna.Groups = []string{"kowalski", "sudo"}
	if !sameAccountState(konto(), inna) {
		t.Error("kolejnosc grup nie jest zmiana")
	}

	zablokowane := konto()
	zablokowane.Locked = &prawda
	if sameAccountState(konto(), zablokowane) {
		t.Error("zmiana blokady musi byc wykryta")
	}

	// Stan nieznany rozni sie od kazdego znanego: przejscie z "nie wiadomo"
	// na "zablokowane" jest zmiana wiedzy panelu, a nie brakiem zmiany.
	nieznane := konto()
	nieznane.Locked = nil
	if sameAccountState(konto(), nieznane) {
		t.Error("stan nieznany nie moze byc rowny stanowi znanemu")
	}

	bezKlucza := konto()
	bezKlucza.SSHKeys = nil
	if sameAccountState(konto(), bezKlucza) {
		t.Error("odebranie klucza musi byc wykryte")
	}

	if sameAccountState(nil, konto()) {
		t.Error("zalozenie konta jest zmiana")
	}
	if !sameAccountState(nil, nil) {
		t.Error("brak konta przed i po nie jest zmiana")
	}
}

func TestUzupelnienieDanychUprzywilejowanych(t *testing.T) {
	prawda := true
	accounts := []LocalAccount{{Name: "kowalski"}, {Name: "nowak"}}
	result := &helperv1.LocalAccountsResult{
		Accounts: []*helperv1.LocalAccountDetail{{
			Name:        "kowalski",
			Locked:      &prawda,
			PasswordSet: &prawda,
			SshKeys:     []*helperv1.LocalSSHKey{{Fingerprint: "SHA256:aaa", Type: "ED25519"}},
		}},
	}

	merged := mergePrivilegedAccounts(accounts, result)
	if merged[0].Locked == nil || !*merged[0].Locked {
		t.Error("stan blokady nie zostal przeniesiony")
	}
	if len(merged[0].SSHKeys) != 1 || merged[0].SSHKeys[0].Source != "authorized_keys" {
		t.Error("klucze nie zostaly przeniesione ze zrodlem")
	}
	// Konto, o ktorym helper nic nie powiedzial, zostaje ze stanem nieznanym.
	// Wpisanie tu "odblokowane" byloby zmyslonym faktem.
	if merged[1].Locked != nil {
		t.Error("brak danych musi zostac stanem nieznanym")
	}
}

func TestZakresUIDZLoginDefs(t *testing.T) {
	katalog := t.TempDir()
	sciezka := filepath.Join(katalog, "login.defs")
	zawartosc := "# komentarz\nUID_MIN\t\t 500\nUID_MAX\t\t 50000\nGID_MIN 1000\n"
	if err := os.WriteFile(sciezka, []byte(zawartosc), 0o644); err != nil {
		t.Fatal(err)
	}

	uidMin, uidMax := parseUIDRange(sciezka)
	if uidMin != 500 || uidMax != 50000 {
		t.Fatalf("odczytano zakres %d-%d, oczekiwano 500-50000", uidMin, uidMax)
	}

	// Brak pliku nie moze przesunac klasyfikacji: wartosci awaryjne odpowiadaja
	// ustawieniom dystrybucji.
	uidMin, uidMax = parseUIDRange(filepath.Join(katalog, "nie-istnieje"))
	if uidMin != defaultUIDMin || uidMax != defaultUIDMax {
		t.Fatalf("brak pliku dal zakres %d-%d", uidMin, uidMax)
	}
}

func TestKlasyfikacjaKont(t *testing.T) {
	katalog := t.TempDir()
	sciezka := filepath.Join(katalog, "passwd")
	zawartosc := "root:x:0:0:root:/root:/bin/bash\n" +
		"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n" +
		"kowalski:x:1001:1001:Jan Kowalski,,,:/home/kowalski:/bin/bash\n" +
		// "nobody" lezy powyzej zakresu kont ludzi i jest kontem systemowym
		// mimo wysokiego UID; sam prog dolny by tego nie wykryl.
		"nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n" +
		"uszkodzony:x:nie-liczba:0::/tmp:/bin/sh\n"
	if err := os.WriteFile(sciezka, []byte(zawartosc), 0o644); err != nil {
		t.Fatal(err)
	}

	accounts := parsePasswd(sciezka, 1000, 60000, func(string) []string { return nil })
	zrodla := map[string]AccountSource{}
	for _, konto := range accounts {
		zrodla[konto.Name] = konto.Source
	}

	if len(accounts) != 4 {
		t.Fatalf("odczytano %d kont, oczekiwano 4 (wiersz uszkodzony pomijany)", len(accounts))
	}
	for nazwa, oczekiwane := range map[string]AccountSource{
		"root": SourceSystem, "daemon": SourceSystem,
		"kowalski": SourceLocal, "nobody": SourceSystem,
	} {
		if zrodla[nazwa] != oczekiwane {
			t.Errorf("konto %s sklasyfikowane jako %s, oczekiwano %s", nazwa, zrodla[nazwa], oczekiwane)
		}
	}

	for _, konto := range accounts {
		if konto.Name == "kowalski" && konto.Gecos != "Jan Kowalski" {
			t.Errorf("opis konta odczytany jako %q", konto.Gecos)
		}
	}
}
