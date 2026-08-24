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

// odczytano jest chwila, w ktorej host zglosil fakty, a terazTestowe -
// chwila oceny. Roznica jest mala celowo: ocena liczona wobec starego odczytu
// konczy sie stanem nieustalonym, i to jest osobny test.
var odczytano = time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
var terazTestowe = odczytano.Add(time.Minute)

func fragmentZ(t *testing.T, modul string, tresc any) Fragment {
	t.Helper()
	zakodowane, err := json.Marshal(tresc)
	if err != nil {
		t.Fatalf("serializacja %s: %v", modul, err)
	}
	return Fragment{
		Module: modul, Revision: "rew-" + modul, Payload: zakodowane,
		ObservedAt: odczytano,
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
	raport := Ocen("host", Wejscie{}, terazTestowe)

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
	raport := Ocen("host", Wejscie{Fragmenty: map[string]Fragment{modulSecurity: fragment}}, terazTestowe)

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
		modulSecurity: fragmentZ(t, modulSecurity, stan)}}, terazTestowe)

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
		modulSecurity: fragmentZ(t, modulSecurity, stan)}}, terazTestowe)

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
		MAC: security.Mandatory{System: security.SystemSELinux, Mode: security.TrybEnforcing, ConfiguredMode: security.TrybEnforcing},
		Audit: security.Audyt{Present: true, Active: wskaznikPrawdy(),
			RulesLoaded: wskaznikLiczby(12), RulesConfigured: wskaznikLiczby(12)},
	}
	raport := Ocen("host", Wejscie{Fragmenty: map[string]Fragment{
		modulSecurity: fragmentZ(t, modulSecurity, stan)}}, terazTestowe)

	for _, id := range []string{"mac.enforcing", "mac.persistent", "audit.running", "audit.rules-loaded"} {
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
		modulSecurity: fragmentZ(t, modulSecurity, permissive)}}, terazTestowe)
	drugi := Ocen("host", Wejscie{Fragmenty: map[string]Fragment{
		modulSecurity: fragmentZ(t, modulSecurity, permissive)}}, terazTestowe.Add(time.Hour))
	trzeci := Ocen("host", Wejscie{Fragmenty: map[string]Fragment{
		modulSecurity: fragmentZ(t, modulSecurity, enforcing)}}, terazTestowe)

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
	spelnione := Ocen("host", Wejscie{Host: Host{PendingSecurityUpdates: &zero}}, terazTestowe)
	if !ustalenie(spelnione, "packages.security-updates").Passed {
		t.Error("brak poprawek uznany za niezgodnosc")
	}

	zalegle := Ocen("host", Wejscie{Host: Host{PendingSecurityUpdates: &siedem}}, terazTestowe)
	wynik := ustalenie(zalegle, "packages.security-updates")
	if wynik.Passed || wynik.Remediation == nil || wynik.Remediation.Action != "packages.plan" {
		t.Fatalf("ustalenie = %+v", wynik)
	}

	// Nieustalona liczba nie jest zerem.
	nieznana := Ocen("host", Wejscie{}, terazTestowe)
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
	raport := Ocen("host", hostZeWszystkimiNiezgodnosciami(t), terazTestowe)
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
		// Operacja bez payloadu jest poprawna: skan czy przeladowanie regul
		// nie maja czego niesc.
		var payload opspec.Payload
		if len(wynik.Remediation.Payload) == 0 {
			if err := opspec.Validate(akcja, payload); err != nil {
				t.Errorf("%s: operacja %s wymaga payloadu, ktorego naprawa nie niesie: %v",
					wynik.CheckID, akcja, err)
			}
			continue
		}
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
		Audit:          security.Audyt{Present: true, Active: &falsz, RulesLoaded: wskaznikLiczby(0), RulesConfigured: wskaznikLiczby(4)},
		SecureBoot:     &falsz,
		ListeningKnown: true,
		OwnersKnown:    true,
		Listening: []security.Nasluch{
			{Protocol: "tcp", Address: "0.0.0.0", Port: 22, Process: "sshd", Reach: security.ZasiegWszystkie},
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

// Host z AppArmorem nie przegrywa sprawdzenia wymagajacego SELinuksa. Stan
// "nie dotyczy" jest osobna odpowiedzia: nie wchodzi ani do zgodnosci, ani do
// niezgodnosci, i nie tworzy kroku planu.
func TestSprawdzenieNiedotyczaceNieJestPorazka(t *testing.T) {
	trzy, zero := 3, 0
	stan := security.Snapshot{
		MAC: security.Mandatory{
			System: security.SystemAppArmor, Mode: security.TrybEnforcing,
			ProfilesEnforcing: &trzy, ProfilesComplain: &zero,
		},
	}
	raport := Ocen("host", Wejscie{Fragmenty: map[string]Fragment{
		modulSecurity: fragmentZ(t, modulSecurity, stan)}}, terazTestowe)

	trwalosc := ustalenie(raport, "mac.persistent")
	if trwalosc.Applicable {
		t.Fatalf("sprawdzenie SELinuksa dotyczy hosta z AppArmorem: %+v", trwalosc)
	}
	if trwalosc.Passed || trwalosc.Unknown {
		t.Error("stan nie dotyczy zmieszany ze zgodnoscia albo z nieustalonym")
	}
	if trwalosc.ReasonCode != PowodNieobslugiwane {
		t.Errorf("kod powodu = %q", trwalosc.ReasonCode)
	}
	if trwalosc.Remediation != nil {
		t.Error("sprawdzenie niedotyczace niesie naprawe")
	}
	if raport.Counts["not_applicable"] == 0 {
		t.Errorf("podsumowanie bez stanu nie dotyczy: %v", raport.Counts)
	}

	// Host bez sshd i bez demona audytu tez nie przegrywa ich sprawdzen.
	bezUslug := Ocen("host", Wejscie{Fragmenty: map[string]Fragment{
		modulSecurity: fragmentZ(t, modulSecurity, security.Snapshot{MAC: stan.MAC}),
		modulSSH:      fragmentZ(t, modulSSH, sshmodul.Snapshot{}),
	}}, terazTestowe)
	for _, id := range []string{"ssh.root-login", "ssh.password-auth", "audit.rules-loaded"} {
		if wynik := ustalenie(bezUslug, id); wynik.Applicable {
			t.Errorf("%s dotyczy hosta bez tej uslugi: %+v", id, wynik)
		}
	}
}

// Kazdy stan nieustalony niesie kod powodu: bez niego operator nie wie, czy
// czekac na odczyt, naprawic agenta, czy nadac uprawnienia.
func TestKazdeNieustaloneMaKodPowodu(t *testing.T) {
	przypadki := map[string]Wejscie{
		"bez modulow": {},
		"modul z bledem": {Fragmenty: map[string]Fragment{
			modulSecurity: fragmentZBledem(t, modulSecurity, "helper: brak odpowiedzi"),
		}},
		"brakujace fakty": {Fragmenty: map[string]Fragment{
			modulSecurity: fragmentZ(t, modulSecurity, security.Snapshot{
				MAC:   security.Mandatory{System: security.SystemAppArmor, Mode: security.TrybEnforcing},
				Audit: security.Audyt{Present: true},
				Missing: map[string]string{
					security.FaktProfileAppArmor: "profile AppArmora leza w securityfs",
					security.FaktRegulyAudytu:    "auditctl: brak uprawnien",
					security.FaktSecureBoot:      "nie odczytano zmiennej EFI: permission denied",
				},
			}),
		}},
	}
	dozwolone := map[string]bool{
		PowodBrakFaktu: true, PowodBladOdczytu: true,
		PowodBrakUprawnienia: true, PowodNieaktualny: true,
	}
	for nazwa, wejscie := range przypadki {
		t.Run(nazwa, func(t *testing.T) {
			raport := Ocen("host", wejscie, terazTestowe)
			nieustalone := 0
			for _, wynik := range raport.Findings {
				if !wynik.Unknown {
					continue
				}
				nieustalone++
				if !dozwolone[wynik.ReasonCode] {
					t.Errorf("%s: kod powodu = %q", wynik.CheckID, wynik.ReasonCode)
				}
				if wynik.Observed == "" {
					t.Errorf("%s: stan nieustalony bez opisu", wynik.CheckID)
				}
			}
			if nieustalone == 0 {
				t.Fatal("przypadek nie wywolal zadnego stanu nieustalonego")
			}
		})
	}
}

// Odmowa dostepu i nieudany odczyt prowadza do dwoch roznych dzialan
// operatora, wiec maja dwa rozne kody.
func TestKodPowoduRozrozniaBrakUprawnienia(t *testing.T) {
	stan := security.Snapshot{
		MAC:   security.Mandatory{System: security.SystemAppArmor, Mode: security.TrybEnforcing},
		Audit: security.Audyt{Present: true},
		Missing: map[string]string{
			security.FaktProfileAppArmor: "profile AppArmora leza w securityfs",
			security.FaktRegulyAudytu:    "helper: polaczenie zerwane",
		},
	}
	raport := Ocen("host", Wejscie{Fragmenty: map[string]Fragment{
		modulSecurity: fragmentZ(t, modulSecurity, stan)}}, terazTestowe)

	if kod := ustalenie(raport, "mac.enforcing").ReasonCode; kod != PowodBrakUprawnienia {
		t.Errorf("brak uprawnienia zgloszony jako %q", kod)
	}
	if kod := ustalenie(raport, "audit.rules-loaded").ReasonCode; kod != PowodBladOdczytu {
		t.Errorf("blad odczytu zgloszony jako %q", kod)
	}
}

// Odczyt sprzed doby opisuje hosta sprzed doby: ocena na nim oparta mowilaby
// o stanie, ktorego juz moze nie byc.
func TestNieaktualnyOdczytNieJestZgodnoscia(t *testing.T) {
	stan := security.Snapshot{MAC: security.Mandatory{
		System: security.SystemSELinux, Mode: security.TrybEnforcing, ConfiguredMode: security.TrybEnforcing}}
	wejscie := Wejscie{Fragmenty: map[string]Fragment{
		modulSecurity: fragmentZ(t, modulSecurity, stan)}}

	swiezy := Ocen("host", wejscie, odczytano.Add(MaksymalnyWiekOdczytu-time.Minute))
	if !ustalenie(swiezy, "mac.enforcing").Passed {
		t.Fatal("swiezy odczyt nie dal wyniku")
	}

	stary := Ocen("host", wejscie, odczytano.Add(MaksymalnyWiekOdczytu+time.Minute))
	przeterminowane := ustalenie(stary, "mac.enforcing")
	if !przeterminowane.Unknown || przeterminowane.ReasonCode != PowodNieaktualny {
		t.Fatalf("stary odczyt = %+v", przeterminowane)
	}
}

// Odcisk planu ma stala postac kanoniczna, wersjonowana i zwiazana z hostem.
// Wektory sa przybite na sztywno: zmiana postaci ma zepsuc ten test, a nie
// po cichu uniewaznic zatwierdzone plany.
func TestWektoryOdciskuPlanu(t *testing.T) {
	pusty := HashPlanu("host-a", nil)
	if pusty != "974678b3d16d9c31041a89a484c91bf837cb0921e5584c9a6d634ccc51ad38e8" {
		t.Errorf("odcisk pustego planu = %q", pusty)
	}

	krok := []Ustalenie{{
		CheckID: "mac.enforcing", CheckVersion: 1, Applicable: true,
		Module: "security", Revision: "rew-1", Observed: "SELinux: permissive",
		Remediation: &Naprawa{
			Action:  "selinux.mode.set",
			Payload: json.RawMessage(`{"security":{"mode":"enforcing"}}`),
		},
	}}
	odcisk := HashPlanu("host-a", krok)
	if odcisk != "17c5837bb4b81f944318287154302912f59e00f2294e4c27057fdc1eaab5e77a" {
		t.Errorf("odcisk kroku = %q", odcisk)
	}

	// Ten sam krok na innym hoscie to inny plan.
	if HashPlanu("host-b", krok) == odcisk {
		t.Error("odcisk nie zalezy od hosta")
	}
	// Zmiana wersji sprawdzenia zmienia znaczenie kroku.
	inna := append([]Ustalenie(nil), krok...)
	inna[0].CheckVersion = 2
	if HashPlanu("host-a", inna) == odcisk {
		t.Error("odcisk nie zalezy od wersji sprawdzenia")
	}
	// Zmiana rewizji odczytu znaczy, ze plan liczono z innych faktow.
	inna[0].CheckVersion = 1
	inna[0].Revision = "rew-2"
	if HashPlanu("host-a", inna) == odcisk {
		t.Error("odcisk nie zalezy od rewizji inwentarza")
	}
	// Zmiana payloadu naprawy zmienia to, co zostanie wykonane.
	inna[0].Revision = "rew-1"
	inna[0].Remediation = &Naprawa{
		Action:  "selinux.mode.set",
		Payload: json.RawMessage(`{"security":{"mode":"permissive"}}`),
	}
	if HashPlanu("host-a", inna) == odcisk {
		t.Error("odcisk nie zalezy od payloadu naprawy")
	}
}

func fragmentZBledem(t *testing.T, modul, powod string) Fragment {
	t.Helper()
	fragment := fragmentZ(t, modul, security.Snapshot{})
	fragment.UnavailableReason = powod
	return fragment
}
