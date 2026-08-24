package compliance

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/modules/kernel"
	"github.com/ultherego/flotestro/internal/modules/power"
	"github.com/ultherego/flotestro/internal/modules/security"
	sshmodul "github.com/ultherego/flotestro/internal/modules/ssh"
	czas "github.com/ultherego/flotestro/internal/modules/time"
	"github.com/ultherego/flotestro/internal/opspec"
)

func fragmentZ(t *testing.T, modul string, tresc any) Fragment {
	t.Helper()
	zakodowane, err := json.Marshal(tresc)
	if err != nil {
		t.Fatalf("serializacja %s: %v", modul, err)
	}
	return Fragment{
		Module: modul, Revision: "rew-" + modul, Payload: zakodowane,
		ObservedAt: time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC),
	}
}

func ustalenie(raport Raport, id string) Ustalenie {
	for _, wynik := range raport.Findings {
		if wynik.CheckID == id {
			return wynik
		}
	}
	return Ustalenie{}
}

// Host, ktory nie zglosil modulu, nie jest hostem niezgodnym: brak odczytu
// i zla wartosc to dwie rozne odpowiedzi.
func TestBrakModuluDajeStanNieznany(t *testing.T) {
	raport := Ocen("host", Wejscie{}, time.Now())

	for _, wynik := range raport.Findings {
		if wynik.Module == "" {
			continue
		}
		if !wynik.Unknown {
			t.Errorf("%s bez modulu ma stan znany: %+v", wynik.CheckID, wynik)
		}
		if wynik.Remediation != nil {
			t.Errorf("%s bez odczytu ma plan naprawy", wynik.CheckID)
		}
	}
	if raport.Counts["failed"] != 0 {
		t.Errorf("niezgodnosci bez odczytu: %d", raport.Counts["failed"])
	}
	// Plan bez ustalen wymagajacych dzialania jest pusty, ale nadal ma odcisk.
	if raport.PlanHash == "" {
		t.Error("raport bez odcisku planu")
	}
}

// Modul odczytany z bledem tez nie jest niezgodnoscia - niesie powod.
func TestNieodczytanyModulNiesiePowod(t *testing.T) {
	fragment := fragmentZ(t, modulSecurity, security.Snapshot{})
	fragment.UnavailableReason = "helper: brak odpowiedzi"
	raport := Ocen("host", Wejscie{Fragmenty: map[string]Fragment{modulSecurity: fragment}}, time.Now())

	wynik := ustalenie(raport, "mac.enforcing")
	if !wynik.Unknown {
		t.Fatalf("ustalenie = %+v", wynik)
	}
	if wynik.Observed == "" || wynik.Revision != "rew-security" {
		t.Errorf("ustalenie bez powodu albo bez rewizji: %+v", wynik)
	}
}

func TestSELinuxWTrybiePermissiveMaNaprawe(t *testing.T) {
	stan := security.Snapshot{
		MAC: security.Mandatory{
			System: security.SystemSELinux, Mode: security.TrybPermissive,
			ConfiguredMode: security.TrybEnforcing, Policy: "targeted",
		},
	}
	raport := Ocen("host", Wejscie{Fragmenty: map[string]Fragment{
		modulSecurity: fragmentZ(t, modulSecurity, stan)}}, time.Now())

	wynik := ustalenie(raport, "mac.enforcing")
	if wynik.Passed || wynik.Unknown {
		t.Fatalf("permissive uznane za ochrone: %+v", wynik)
	}
	if wynik.Remediation == nil || wynik.Remediation.Action != "selinux.mode.set" {
		t.Fatalf("naprawa = %+v", wynik.Remediation)
	}
	// Naprawa jest zwykla operacja modulu, wiec niesie gotowy payload.
	var payload struct {
		Security struct {
			Mode string `json:"mode"`
		} `json:"security"`
	}
	if err := json.Unmarshal(wynik.Remediation.Payload, &payload); err != nil {
		t.Fatalf("payload naprawy: %v", err)
	}
	if payload.Security.Mode != security.TrybEnforcing {
		t.Errorf("payload naprawy = %+v", payload)
	}
	// Rozjazd trybu dzialajacego i skonfigurowanego jest osobnym ustaleniem.
	trwalosc := ustalenie(raport, "mac.persistent")
	if trwalosc.Passed {
		t.Error("rozjazd trybu uznany za zgodnosc")
	}
}

// AppArmor z samymi profilami w trybie skarg nie chroni, ale panel nie ma
// czym tego naprawic - i mowi to zamiast proponowac operacje, ktorej nie ma.
func TestAppArmorBezProfiliWymuszanychNieMaOperacjiNaprawczej(t *testing.T) {
	zero, dwa := 0, 2
	stan := security.Snapshot{MAC: security.Mandatory{
		System: security.SystemAppArmor, Mode: security.TrybEnforcing,
		ProfilesEnforcing: &zero, ProfilesComplain: &dwa,
	}}
	raport := Ocen("host", Wejscie{Fragmenty: map[string]Fragment{
		modulSecurity: fragmentZ(t, modulSecurity, stan)}}, time.Now())

	wynik := ustalenie(raport, "mac.enforcing")
	if wynik.Passed {
		t.Fatal("profile w trybie skarg uznane za ochrone")
	}
	if wynik.Remediation == nil || wynik.Remediation.Action != "" {
		t.Fatalf("naprawa = %+v", wynik.Remediation)
	}
	if wynik.Remediation.Note == "" {
		t.Error("brak naprawy bez wyjasnienia")
	}
}

func TestUstalenieSpelnioneNieNiesieNaprawy(t *testing.T) {
	stan := security.Snapshot{
		MAC:   security.Mandatory{System: security.SystemSELinux, Mode: security.TrybEnforcing, ConfiguredMode: security.TrybEnforcing},
		Audit: security.Audyt{Present: true, Active: wskaznikPrawdy(), Rules: wskaznikLiczby(12)},
	}
	raport := Ocen("host", Wejscie{Fragmenty: map[string]Fragment{
		modulSecurity: fragmentZ(t, modulSecurity, stan)}}, time.Now())

	for _, id := range []string{"mac.enforcing", "mac.persistent", "audit.running"} {
		wynik := ustalenie(raport, id)
		if !wynik.Passed {
			t.Errorf("%s = %+v", id, wynik)
		}
		if wynik.Remediation != nil {
			t.Errorf("%s spelnione, a niesie naprawe", id)
		}
	}
}

// Odcisk planu wiaze zatwierdzenie ze stanem, ktory operator ogladal.
func TestOdciskPlanuZalezyOdStanu(t *testing.T) {
	permissive := security.Snapshot{MAC: security.Mandatory{
		System: security.SystemSELinux, Mode: security.TrybPermissive, ConfiguredMode: security.TrybPermissive}}
	enforcing := security.Snapshot{MAC: security.Mandatory{
		System: security.SystemSELinux, Mode: security.TrybEnforcing, ConfiguredMode: security.TrybEnforcing}}

	pierwszy := Ocen("host", Wejscie{Fragmenty: map[string]Fragment{
		modulSecurity: fragmentZ(t, modulSecurity, permissive)}}, time.Now())
	drugi := Ocen("host", Wejscie{Fragmenty: map[string]Fragment{
		modulSecurity: fragmentZ(t, modulSecurity, permissive)}}, time.Now().Add(time.Hour))
	trzeci := Ocen("host", Wejscie{Fragmenty: map[string]Fragment{
		modulSecurity: fragmentZ(t, modulSecurity, enforcing)}}, time.Now())

	// Ten sam stan daje ten sam odcisk niezaleznie od chwili policzenia.
	if pierwszy.PlanHash != drugi.PlanHash {
		t.Error("odcisk planu zmienil sie bez zmiany stanu")
	}
	if pierwszy.PlanHash == trzeci.PlanHash {
		t.Error("zmiana stanu nie zmienila odcisku planu")
	}
}

// Poprawki bezpieczenstwa licza sie z faktu, ktory panel zna sam.
func TestPoprawkiBezpieczenstwaZInwentarzaPanelu(t *testing.T) {
	zero, siedem := 0, 7
	spelnione := Ocen("host", Wejscie{Host: Host{PendingSecurityUpdates: &zero}}, time.Now())
	if !ustalenie(spelnione, "packages.security-updates").Passed {
		t.Error("brak poprawek uznany za niezgodnosc")
	}

	zalegle := Ocen("host", Wejscie{Host: Host{PendingSecurityUpdates: &siedem}}, time.Now())
	wynik := ustalenie(zalegle, "packages.security-updates")
	if wynik.Passed || wynik.Remediation == nil || wynik.Remediation.Action != "packages.plan" {
		t.Fatalf("ustalenie = %+v", wynik)
	}

	// Nieustalona liczba nie jest zerem.
	nieznana := Ocen("host", Wejscie{}, time.Now())
	if !ustalenie(nieznana, "packages.security-updates").Unknown {
		t.Error("nieustalona liczba poprawek uznana za brak poprawek")
	}
}

// Kazda naprawa musi wskazywac operacje, ktora panel zna. Sprawdzenie
// proponujace nieistniejacy typ operacji zostaloby odrzucone dopiero przy
// zlecaniu, a wtedy operator widzi blad zamiast planu.
func TestNaprawyWskazujaOperacjeZKatalogu(t *testing.T) {
	for _, check := range Checks {
		if check.ID == "" || check.Version == 0 || check.Severity == "" {
			t.Errorf("sprawdzenie bez tozsamosci: %+v", check)
		}
		if check.Rationale == "" || check.Expected == "" {
			t.Errorf("%s bez uzasadnienia albo stanu docelowego", check.ID)
		}
	}
	raport := Ocen("host", hostZeWszystkimiNiezgodnosciami(t), time.Now())
	naprawy := 0
	for _, wynik := range raport.Findings {
		if wynik.Remediation == nil || wynik.Remediation.Action == "" {
			continue
		}
		naprawy++
		akcja := opspec.ActionType(wynik.Remediation.Action)
		if !akcja.Known() {
			t.Errorf("%s proponuje nieznana operacje %q", wynik.CheckID, akcja)
			continue
		}
		// Payload naprawy musi przejsc walidacje tej operacji tak samo jak
		// payload wpisany recznie: plan, ktory da sie zlecic dopiero po
		// poprawce, nie jest planem.
		var payload opspec.Payload
		if err := json.Unmarshal(wynik.Remediation.Payload, &payload); err != nil {
			t.Errorf("%s: payload naprawy nie jest payloadem operacji: %v", wynik.CheckID, err)
			continue
		}
		if err := opspec.Validate(akcja, payload); err != nil {
			t.Errorf("%s: payload naprawy odrzucony przez %s: %v", wynik.CheckID, akcja, err)
		}
	}
	// Gdyby scenariusz przestal wywolywac niezgodnosci, test przechodzilby
	// nie sprawdziwszy niczego.
	if naprawy < 6 {
		t.Fatalf("scenariusz wywolal tylko %d napraw z operacja", naprawy)
	}
}

// hostZeWszystkimiNiezgodnosciami buduje stan, w ktorym kazde sprawdzenie
// z naprawa ma co naprawiac.
func hostZeWszystkimiNiezgodnosciami(t *testing.T) Wejscie {
	t.Helper()
	falsz, siedem := false, 7
	ochrona := security.Snapshot{
		MAC: security.Mandatory{
			System: security.SystemSELinux, Mode: security.TrybPermissive,
			ConfiguredMode: security.TrybEnforcing, Policy: "targeted",
		},
		Audit:          security.Audyt{Present: true, Active: &falsz},
		SecureBoot:     &falsz,
		ListeningKnown: true,
		Listening: []security.Nasluch{
			{Protocol: "tcp", Address: "0.0.0.0", Port: 22, Process: "sshd", Exposed: true},
		},
	}
	serwer := sshmodul.Snapshot{PermitRootLogin: "yes", PasswordAuthentication: "yes"}
	jadro := kernel.Snapshot{Settings: []kernel.Ustawienie{
		{Key: "net.ipv4.conf.all.rp_filter", Current: "0"},
		{Key: "net.ipv4.tcp_syncookies", Current: "0"},
	}}
	zegar := czas.Snapshot{Synchronized: &falsz, Service: czas.DemonChrony}
	prawda := true
	zasilanie := power.Snapshot{RebootRequired: &prawda, RebootReasons: []string{"linux-image-amd64"}}

	return Wejscie{
		Host: Host{PendingSecurityUpdates: &siedem},
		Fragmenty: map[string]Fragment{
			modulSecurity: fragmentZ(t, modulSecurity, ochrona),
			modulSSH:      fragmentZ(t, modulSSH, serwer),
			modulKernel:   fragmentZ(t, modulKernel, jadro),
			modulTime:     fragmentZ(t, modulTime, zegar),
			modulPower:    fragmentZ(t, modulPower, zasilanie),
		},
	}
}

func wskaznikPrawdy() *bool           { prawda := true; return &prawda }
func wskaznikLiczby(wartosc int) *int { return &wartosc }
