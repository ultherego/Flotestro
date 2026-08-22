//go:build integration

package integration

import (
	"fmt"
	"net/http"
	"testing"
	"time"
)

// klucz testowy jest kluczem publicznym; material prywatny nie istnieje po
// stronie testu i nie jest do niczego potrzebny.
const kluczTestowy = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHZ8Kx3vQOZKq0M0hDPuJHf5Zx1kJHgqRqYqGZ6XxLm1 test@flotestro"

type kontoView struct {
	Name        string   `json:"name"`
	UID         int64    `json:"uid"`
	Source      string   `json:"source"`
	Groups      []string `json:"groups"`
	Locked      *bool    `json:"locked"`
	PasswordSet *bool    `json:"password_set"`
	SSHKeys     []struct {
		Fingerprint string `json:"fingerprint"`
		Type        string `json:"type"`
	} `json:"ssh_keys"`
	ObservedAt string `json:"observed_at"`
}

func konta(h *harness, hostID, filtr string) []kontoView {
	h.t.Helper()
	var result struct {
		Accounts []kontoView `json:"accounts"`
	}
	path := "/api/v1/hosts/" + hostID + "/local-accounts"
	if filtr != "" {
		path += "?source=" + filtr
	}
	h.get(path, &result)
	return result.Accounts
}

func konto(h *harness, hostID, nazwa string) *kontoView {
	h.t.Helper()
	for _, k := range konta(h, hostID, "") {
		if k.Name == nazwa {
			return &k
		}
	}
	return nil
}

func operacjaKonta(h *harness, hostID, akcja string, payload map[string]any) (jobView, []attemptView) {
	h.t.Helper()
	return h.runOperation(hostID, map[string]any{
		"action":  akcja,
		"payload": map[string]any{"local_user": payload},
	}, 120*time.Second)
}

// TestCyklZyciaKontaLokalnego sprawdza modul kont lokalnych od zalozenia do
// odebrania dostepu. Modul jest przeznaczony dla instalacji bez katalogu
// tozsamosci, wiec musi dzialac bez zadnej integracji zewnetrznej.
func TestCyklZyciaKontaLokalnego(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	nazwa := fmt.Sprintf("test%d", time.Now().UnixNano()%100000)

	t.Cleanup(func() {
		// Konto testowe nie moze przetrwac testu: zostawione konto z kluczem
		// bylo by realna droga dostepu do hosta.
		operacjaKonta(h, host.ID, "localuser.sshkeys.set", map[string]any{
			"name": nazwa, "ssh_keys": []string{},
		})
		operacjaKonta(h, host.ID, "localuser.lock", map[string]any{"name": nazwa})
	})

	job, _ := operacjaKonta(h, host.ID, "localuser.create", map[string]any{
		"name": nazwa, "gecos": "Konto testowe", "shell": "/bin/bash",
		"ssh_keys": []string{kluczTestowy}, "create_home": true,
	})
	if job.State != "succeeded" {
		t.Fatalf("zalozenie konta zakonczylo sie stanem %s", job.State)
	}

	// Stan musi byc widoczny natychmiast po operacji, bez czekania na
	// nastepny raport inventory: agent odczytuje konto po zmianie.
	utworzone := konto(h, host.ID, nazwa)
	if utworzone == nil {
		t.Fatal("konto nie pojawilo sie w panelu po zalozeniu")
	}
	if utworzone.Source != "local" {
		t.Errorf("zrodlo konta = %q, oczekiwano local", utworzone.Source)
	}
	if utworzone.UID < 1000 {
		t.Errorf("konto dostalo UID %d z zakresu systemowego", utworzone.UID)
	}
	// Konto zalozone przez panel nie ma hasla, ale nie jest zablokowane:
	// dostep daje klucz SSH. Pokazanie go jako zablokowanego bylo by
	// falszywa informacja o odcieciu dostepu.
	if utworzone.Locked == nil || *utworzone.Locked {
		t.Errorf("konto na klucz SSH nie moze byc zablokowane: locked=%v", utworzone.Locked)
	}
	if utworzone.PasswordSet == nil || *utworzone.PasswordSet {
		t.Errorf("konto zalozone przez panel nie moze miec hasla: password_set=%v", utworzone.PasswordSet)
	}
	if len(utworzone.SSHKeys) != 1 {
		t.Fatalf("konto ma %d kluczy, oczekiwano 1", len(utworzone.SSHKeys))
	}
	if utworzone.SSHKeys[0].Type != "ED25519" {
		t.Errorf("typ klucza = %q", utworzone.SSHKeys[0].Type)
	}

	// Powtorzone zalozenie musi byc odrzucone jawnie, a nie cicho nadpisac
	// istniejace konto.
	powtorne, proby := operacjaKonta(h, host.ID, "localuser.create", map[string]any{
		"name": nazwa, "ssh_keys": []string{kluczTestowy},
	})
	if powtorne.State == "succeeded" {
		t.Error("powtorne zalozenie konta zakonczylo sie sukcesem")
	}
	if len(proby) > 0 && proby[len(proby)-1].ErrorCode != "account_exists" {
		t.Errorf("kod bledu = %q, oczekiwano account_exists", proby[len(proby)-1].ErrorCode)
	}

	blokada, _ := operacjaKonta(h, host.ID, "localuser.lock", map[string]any{"name": nazwa})
	if blokada.State != "succeeded" {
		t.Fatalf("blokada zakonczyla sie stanem %s", blokada.State)
	}
	if stan := konto(h, host.ID, nazwa); stan == nil || stan.Locked == nil || !*stan.Locked {
		t.Errorf("konto nie zostalo pokazane jako zablokowane: %+v", stan)
	}

	odblokowanie, _ := operacjaKonta(h, host.ID, "localuser.unlock", map[string]any{"name": nazwa})
	if odblokowanie.State != "succeeded" {
		t.Fatalf("odblokowanie zakonczylo sie stanem %s", odblokowanie.State)
	}
	if stan := konto(h, host.ID, nazwa); stan == nil || stan.Locked == nil || *stan.Locked {
		t.Errorf("konto pozostalo zablokowane po odblokowaniu: %+v", stan)
	}

	// Pusta lista kluczy jest swiadomym odebraniem dostepu.
	odebranie, _ := operacjaKonta(h, host.ID, "localuser.sshkeys.set", map[string]any{
		"name": nazwa, "ssh_keys": []string{},
	})
	if odebranie.State != "succeeded" {
		t.Fatalf("odebranie kluczy zakonczylo sie stanem %s", odebranie.State)
	}
	stan := konto(h, host.ID, nazwa)
	if stan == nil || len(stan.SSHKeys) != 0 {
		t.Errorf("klucze nie zostaly odebrane: %+v", stan)
	}
}

// TestKontaSystemoweSaChronione sprawdza, ze modul nie daje drogi do zmiany
// kont uslug ani do przeslonienia konta z katalogu.
func TestKontaSystemoweSaChronione(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	for _, nazwa := range []string{"root", "daemon", "bin"} {
		t.Run(nazwa, func(t *testing.T) {
			job, proby := operacjaKonta(h, host.ID, "localuser.lock", map[string]any{"name": nazwa})
			if job.State == "succeeded" {
				t.Fatalf("blokada konta systemowego %s zakonczyla sie sukcesem", nazwa)
			}
			if len(proby) > 0 && proby[len(proby)-1].ErrorCode != "system_account" {
				t.Errorf("kod bledu = %q, oczekiwano system_account", proby[len(proby)-1].ErrorCode)
			}
		})
	}

	// Konta systemowe sa poza domyslnym widokiem, ale musza byc dostepne
	// jawnym filtrem: czasem trzeba potwierdzic, ze konto uslugi istnieje.
	domyslne := konta(h, host.ID, "")
	for _, k := range domyslne {
		if k.Source == "system" {
			t.Errorf("konto systemowe %s trafilo do widoku domyslnego", k.Name)
		}
	}
	systemowe := konta(h, host.ID, "system")
	if len(systemowe) == 0 {
		t.Error("filtr kont systemowych nie zwrocil zadnego konta")
	}
	for _, k := range systemowe {
		if k.Name == "root" && k.UID != 0 {
			t.Errorf("konto root ma UID %d", k.UID)
		}
	}
}

// TestKluczPrywatnyJestOdrzucany sprawdza, ze panel nie przyjmuje materialu
// prywatnego nawet przez pomylke operatora. Odrzucenie nastepuje przy
// walidacji planu, wiec sekret nie trafia do bazy ani na host.
func TestKluczPrywatnyJestOdrzucany(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	for _, klucz := range []string{
		"-----BEGIN OPENSSH PRIVATE KEY-----",
		kluczTestowy + "\nssh-rsa AAAAB3NzaC1yc2E obcy@stacja",
		"ssh-dss AAAAB3NzaC1kc3M jan@stacja",
	} {
		var problem struct {
			Code string `json:"code"`
		}
		h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations", map[string]any{
			"action": "localuser.sshkeys.set",
			"payload": map[string]any{
				"local_user": map[string]any{"name": "nieistotne", "ssh_keys": []string{klucz}},
			},
		}, &problem, http.StatusBadRequest)
		if problem.Code != "invalid_payload" {
			t.Errorf("klucz %.30q: kod = %q, oczekiwano invalid_payload", klucz, problem.Code)
		}
	}
}
