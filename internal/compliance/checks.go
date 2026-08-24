package compliance

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/ultherego/flotestro/internal/modules/kernel"
	"github.com/ultherego/flotestro/internal/modules/power"
	"github.com/ultherego/flotestro/internal/modules/security"
	sshmodul "github.com/ultherego/flotestro/internal/modules/ssh"
	czas "github.com/ultherego/flotestro/internal/modules/time"
)

// Nazwy modulow inwentarza, z ktorych licza sie sprawdzenia.
const (
	modulSecurity = "security"
	modulSSH      = "ssh"
	modulKernel   = "kernel"
	modulTime     = "time"
	modulPower    = "power"
	modulPackages = "packages"
)

// Checks to profil hardeningu panelu.
//
// Lista jest krotka i celowo: kazde sprawdzenie musi dac sie wytlumaczyc
// jednym zdaniem, wskazac dowod i - jesli naprawa istnieje - konkretna
// typowana operacje. Sprawdzenie, ktore nie spelnia tych trzech warunkow,
// jest opinia, a nie sprawdzeniem.
var Checks = []Check{
	{
		ID: "mac.enforcing", Version: 1, Severity: WagaHigh, Module: modulSecurity,
		Title:     "Obowiazkowa kontrola dostepu wymusza polityke",
		Expected:  "SELinux w trybie enforcing albo AppArmor z profilami wymuszanymi",
		Rationale: "Bez MAC bledna usluga siega tam, dokad pozwala jej samo prawo pliku.",
		Ocen:      ocenMAC,
	},
	{
		ID: "mac.persistent", Version: 1, Severity: WagaHigh, Module: modulSecurity,
		Title:     "Ochrona przetrwa restart hosta",
		Expected:  "tryb dzialajacy jest tym samym, co tryb z konfiguracji",
		Rationale: "Host, ktory po restarcie wstaje bez ochrony, wyglada na chroniony do pierwszego restartu.",
		Ocen:      ocenTrwaloscMAC,
	},
	{
		ID: "audit.running", Version: 1, Severity: WagaMedium, Module: modulSecurity,
		Title:     "Demon audytu dziala",
		Expected:  "auditd aktywny",
		Rationale: "Bez audytu nie da sie po fakcie powiedziec, kto co zrobil na hoscie.",
		Ocen:      ocenAudyt,
	},
	{
		ID: "boot.secure-boot", Version: 1, Severity: WagaInfo, Module: modulSecurity,
		Title:     "Secure boot",
		Expected:  "secure boot wlaczony",
		Rationale: "Bez secure boota nikt nie sprawdza, co host uruchamia przed startem systemu.",
		Ocen:      ocenSecureBoot,
	},
	{
		ID: "exposure.listening", Version: 1, Severity: WagaMedium, Module: modulSecurity,
		Title:     "Uslugi wystawione poza host",
		Expected:  "wystawione wylacznie uslugi, ktore maja byc wystawione",
		Rationale: "Kazde gniazdo poza petla zwrotna jest droga do hosta dla kazdego, kto widzi jego siec.",
		Ocen:      ocenWystawienie,
	},
	{
		ID: "ssh.root-login", Version: 1, Severity: WagaHigh, Module: modulSSH,
		Title:     "Logowanie roota po SSH",
		Expected:  "PermitRootLogin no",
		Rationale: "Konto roota jest wspolne, wiec logowanie na nie nie zostawia sladu, kto to byl.",
		Ocen:      ocenRootLogin,
	},
	{
		ID: "ssh.password-auth", Version: 1, Severity: WagaMedium, Module: modulSSH,
		Title:     "Logowanie haslem po SSH",
		Expected:  "PasswordAuthentication no",
		Rationale: "Haslo da sie zgadnac zdalnie; klucz nie.",
		Ocen:      ocenHasla,
	},
	{
		ID: "kernel.rp-filter", Version: 1, Severity: WagaLow, Module: modulKernel,
		Title:     "Filtrowanie po adresie zrodlowym",
		Expected:  "net.ipv4.conf.all.rp_filter = 1",
		Rationale: "Bez tego host przyjmuje pakiety z podszytym adresem zrodlowym.",
		Ocen:      ocenUstawienia("net.ipv4.conf.all.rp_filter", "1"),
	},
	{
		ID: "kernel.syncookies", Version: 1, Severity: WagaLow, Module: modulKernel,
		Title:     "Ciasteczka SYN",
		Expected:  "net.ipv4.tcp_syncookies = 1",
		Rationale: "Bez nich zalew polaczen wyczerpuje kolejke i usluga przestaje odpowiadac.",
		Ocen:      ocenUstawienia("net.ipv4.tcp_syncookies", "1"),
	},
	{
		ID: "time.synchronized", Version: 1, Severity: WagaMedium, Module: modulTime,
		Title:     "Zegar zsynchronizowany",
		Expected:  "host synchronizuje czas ze zrodlem",
		Rationale: "Przesuniety zegar odrzuca bilety Kerberosa i certyfikaty, a dziennik uklada w zla kolejnosc.",
		Ocen:      ocenCzas,
	},
	{
		ID: "packages.security-updates", Version: 1, Severity: WagaHigh, Module: "",
		Title:     "Poprawki bezpieczenstwa zainstalowane",
		Expected:  "brak oczekujacych poprawek bezpieczenstwa",
		Rationale: "Kazda oczekujaca poprawka jest publicznie opisana - razem z tym, co bez niej mozna zrobic.",
		Ocen:      ocenPoprawek,
	},
	{
		ID: "reboot.pending", Version: 1, Severity: WagaMedium, Module: modulPower,
		Title:     "Host nie czeka na restart",
		Expected:  "restart niewymagany",
		Rationale: "Host, ktory czeka na restart, dziala na starym jadrze albo starych bibliotekach mimo zainstalowanej poprawki.",
		Ocen:      ocenRestartu,
	},
}

// ocenMAC sprawdza, czy hosta chroni obowiazkowa kontrola dostepu.
func ocenMAC(wejscie Wejscie) Wynik {
	stan, ok := stanOchrony(wejscie)
	if !ok {
		return nieznane("nie odczytano stanu ochronnego")
	}
	if stan.MAC.System == "" {
		return Wynik{
			Observed: "host nie ma ani SELinuksa, ani AppArmora",
			Evidence: stan.MAC.Reason,
			Remediation: &Naprawa{Note: "wlaczenie MAC na dzialajacym hoscie wymaga instalacji polityki " +
				"i przeetykietowania systemu plikow; panel tego nie robi jedna operacja"},
		}
	}
	if stan.MAC.Chroni() {
		return Wynik{Passed: true, Observed: opisMAC(stan.MAC)}
	}

	wynik := Wynik{Observed: opisMAC(stan.MAC), Evidence: stan.MAC.Reason}
	// Naprawa istnieje tylko tam, gdzie zmiana dziala od reki: SELinux
	// w permissive wraca do enforcing jednym poleceniem, AppArmor bez
	// profili wymuszanych potrzebuje profili, a tych panel nie pisze.
	if stan.MAC.System == security.SystemSELinux && stan.MAC.Mode == security.TrybPermissive {
		wynik.Remediation = &Naprawa{
			Action:  "selinux.mode.set",
			Payload: json.RawMessage(`{"security":{"mode":"enforcing"}}`),
			Note:    "przelaczenie dziala od reki i zostaje zapisane w konfiguracji",
		}
		return wynik
	}
	if stan.MAC.System == security.SystemSELinux {
		wynik.Remediation = &Naprawa{Note: "SELinux jest wylaczony w jadrze; powrot wymaga " +
			"przeetykietowania systemu plikow i restartu"}
		return wynik
	}
	wynik.Remediation = &Naprawa{Note: "AppArmor nie ma profili wymuszanych; profile pochodza z pakietow, " +
		"a nie z panelu"}
	return wynik
}

// ocenTrwaloscMAC sprawdza, czy ochrona przetrwa restart.
func ocenTrwaloscMAC(wejscie Wejscie) Wynik {
	stan, ok := stanOchrony(wejscie)
	if !ok {
		return nieznane("nie odczytano stanu ochronnego")
	}
	if stan.MAC.System != security.SystemSELinux {
		// AppArmor nie ma osobnego trybu w konfiguracji: jest albo go nie ma.
		return Wynik{Passed: true, Observed: "host nie uzywa SELinuksa, wiec nie ma tu dwoch trybow"}
	}
	if stan.MAC.ConfiguredMode == "" {
		return nieznane("host nie zglosil trybu z konfiguracji")
	}
	if stan.MAC.ConfiguredMode == stan.MAC.Mode {
		return Wynik{Passed: true, Observed: "teraz i po restarcie: " + stan.MAC.Mode}
	}
	wynik := Wynik{
		Observed: "teraz " + stan.MAC.Mode + ", po restarcie " + stan.MAC.ConfiguredMode,
		Evidence: security.KonfiguracjaMAC,
	}
	// Zmiana trybu przez panel zapisuje takze konfiguracje, wiec ta sama
	// operacja usuwa rozjazd - o ile SELinux w ogole dziala w jadrze.
	if stan.MAC.Mode == security.TrybEnforcing || stan.MAC.Mode == security.TrybPermissive {
		wynik.Remediation = &Naprawa{
			Action:  "selinux.mode.set",
			Payload: json.RawMessage(`{"security":{"mode":"` + stan.MAC.Mode + `"}}`),
			Note:    "utrwala tryb, ktory obowiazuje teraz",
		}
	} else {
		wynik.Remediation = &Naprawa{Note: "SELinux jest wylaczony w jadrze; wlaczenie wymaga " +
			"przeetykietowania systemu plikow i restartu"}
	}
	return wynik
}

func ocenAudyt(wejscie Wejscie) Wynik {
	stan, ok := stanOchrony(wejscie)
	if !ok {
		return nieznane("nie odczytano stanu ochronnego")
	}
	if !stan.Audit.Present {
		return Wynik{
			Observed:    "host nie ma demona audytu",
			Evidence:    stan.Audit.Reason,
			Remediation: &Naprawa{Note: "auditd trzeba najpierw zainstalowac operacja packages.install"},
		}
	}
	if stan.Audit.Active == nil {
		return nieznane("nie ustalono stanu demona audytu")
	}
	if *stan.Audit.Active {
		opis := "auditd dziala"
		if stan.Audit.Rules != nil {
			opis += ", regul: " + strconv.Itoa(*stan.Audit.Rules)
		}
		return Wynik{Passed: true, Observed: opis}
	}
	return Wynik{
		Observed: "auditd jest zainstalowany, ale nie dziala",
		Remediation: &Naprawa{
			Action:  "unit.enable.set",
			Payload: json.RawMessage(`{"unit_toggle":{"unit":"auditd.service","enabled":true}}`),
			Note:    "wlacza jednostke na trwale; uruchomienie teraz to osobna operacja unit.start",
		},
	}
}

func ocenSecureBoot(wejscie Wejscie) Wynik {
	stan, ok := stanOchrony(wejscie)
	if !ok {
		return nieznane("nie odczytano stanu ochronnego")
	}
	if stan.SecureBoot == nil {
		// Pytanie bez odpowiedzi zostaje pytaniem: host w trybie BIOS nie ma
		// secure boota wylaczonego, tylko nie ma go w ogole.
		return nieznane(pierwszyNiepusty(stan.SecureBootReason, "stanu secure boot nie ustalono"))
	}
	if *stan.SecureBoot {
		return Wynik{Passed: true, Observed: "wlaczony"}
	}
	return Wynik{
		Observed:    "wylaczony",
		Remediation: &Naprawa{Note: "secure boot wlacza sie w firmware maszyny, nie z panelu"},
	}
}

func ocenWystawienie(wejscie Wejscie) Wynik {
	stan, ok := stanOchrony(wejscie)
	if !ok {
		return nieznane("nie odczytano stanu ochronnego")
	}
	if !stan.ListeningKnown {
		return nieznane("nie odczytano listy gniazd nasluchujacych")
	}
	wystawione := stan.Wystawione()
	if len(wystawione) == 0 {
		return Wynik{Passed: true, Observed: "host nie nasluchuje poza petla zwrotna"}
	}
	opisy := make([]string, 0, len(wystawione))
	for _, gniazdo := range wystawione {
		opis := gniazdo.Protocol + "/" + strconv.Itoa(gniazdo.Port)
		if gniazdo.Process != "" {
			opis += " (" + gniazdo.Process + ")"
		}
		opisy = append(opisy, opis)
	}
	// To ustalenie zawsze wymaga czlowieka: panel nie wie, ktora usluga ma
	// prawo byc wystawiona, a zamkniecie zlej odcina dostep do hosta.
	return Wynik{
		Observed: fmt.Sprintf("%d gniazd poza petla zwrotna", len(wystawione)),
		Evidence: strings.Join(opisy, ", "),
		Remediation: &Naprawa{Note: "kazde gniazdo zamyka sie inaczej: regula zapory, konfiguracja uslugi " +
			"albo jej wylaczenie; panel nie zgaduje, ktora z tych rzeczy jest tu wlasciwa"},
	}
}

func ocenRootLogin(wejscie Wejscie) Wynik {
	stan, ok := stanSSH(wejscie)
	if !ok {
		return nieznane("nie odczytano konfiguracji sshd")
	}
	wartosc := strings.ToLower(stan.PermitRootLogin)
	if wartosc == "" {
		return nieznane("sshd nie zglosil ustawienia PermitRootLogin")
	}
	if wartosc == "no" {
		return Wynik{Passed: true, Observed: wartosc}
	}
	return Wynik{
		Observed: wartosc,
		Evidence: "sshd -T",
		Remediation: &Naprawa{
			Action:  "ssh.config.apply",
			Payload: json.RawMessage(`{"ssh":{"permit_root_login":"no"}}`),
			Note:    "upewnij sie, ze ktos poza rootem ma dostep do tego hosta",
		},
	}
}

func ocenHasla(wejscie Wejscie) Wynik {
	stan, ok := stanSSH(wejscie)
	if !ok {
		return nieznane("nie odczytano konfiguracji sshd")
	}
	wartosc := strings.ToLower(stan.PasswordAuthentication)
	if wartosc == "" {
		return nieznane("sshd nie zglosil ustawienia PasswordAuthentication")
	}
	if wartosc == "no" {
		return Wynik{Passed: true, Observed: wartosc}
	}
	return Wynik{
		Observed: wartosc,
		Evidence: "sshd -T",
		Remediation: &Naprawa{
			Action:  "ssh.config.apply",
			Payload: json.RawMessage(`{"ssh":{"password_authentication":"no"}}`),
			Note:    "host odrzuci zmiane, ktora nie zostawia zadnej dzialajacej metody logowania",
		},
	}
}

// ocenUstawienia buduje sprawdzenie jednego klucza sysctl.
func ocenUstawienia(klucz, oczekiwana string) func(Wejscie) Wynik {
	return func(wejscie Wejscie) Wynik {
		fragment, ok := wejscie.Fragment(modulKernel)
		if !ok {
			return nieznane("nie odczytano ustawien jadra")
		}
		var stan kernel.Snapshot
		if err := json.Unmarshal(fragment.Payload, &stan); err != nil {
			return nieznane("nie odczytano ustawien jadra: " + err.Error())
		}
		for _, ustawienie := range stan.Settings {
			if ustawienie.Key != klucz {
				continue
			}
			if ustawienie.Current == "" {
				return nieznane("host nie zglosil wartosci " + klucz)
			}
			if ustawienie.Current == oczekiwana {
				return Wynik{Passed: true, Observed: klucz + " = " + ustawienie.Current}
			}
			return Wynik{
				Observed: klucz + " = " + ustawienie.Current,
				Evidence: pierwszyNiepusty(ustawienie.Source, "wartosc domyslna jadra"),
				Remediation: &Naprawa{
					Action:  "sysctl.ensure",
					Payload: json.RawMessage(`{"kernel":{"settings":{"` + klucz + `":"` + oczekiwana + `"}}}`),
				},
			}
		}
		return nieznane("host nie zglosil klucza " + klucz)
	}
}

func ocenCzas(wejscie Wejscie) Wynik {
	fragment, ok := wejscie.Fragment(modulTime)
	if !ok {
		return nieznane("nie odczytano stanu czasu")
	}
	var stan czas.Snapshot
	if err := json.Unmarshal(fragment.Payload, &stan); err != nil {
		return nieznane("nie odczytano stanu czasu: " + err.Error())
	}
	if stan.Synchronized == nil {
		return nieznane("host nie zglosil stanu synchronizacji")
	}
	if *stan.Synchronized {
		opis := "zsynchronizowany"
		if stan.ReferenceName != "" {
			opis += " z " + stan.ReferenceName
		}
		return Wynik{Passed: true, Observed: opis}
	}
	return Wynik{
		Observed: "niezsynchronizowany",
		Evidence: pierwszyNiepusty(stan.Service, "brak demona czasu"),
		Remediation: &Naprawa{Note: "wskazanie serwerow czasu jest decyzja o infrastrukturze; " +
			"zrob to operacja time.config.apply po sprawdzeniu zrodel testem"},
	}
}

func ocenPoprawek(wejscie Wejscie) Wynik {
	// To sprawdzenie nie liczy sie z fragmentu: liczbe poprawek panel zna
	// z inwentarza pakietow, ktory normalizuje sam.
	if wejscie.Host.PendingSecurityUpdates == nil {
		return nieznane("host nie zglosil liczby poprawek bezpieczenstwa")
	}
	liczba := *wejscie.Host.PendingSecurityUpdates
	if liczba == 0 {
		return Wynik{Passed: true, Observed: "brak oczekujacych poprawek"}
	}
	return Wynik{
		Observed: strconv.Itoa(liczba) + " oczekujacych poprawek bezpieczenstwa",
		Remediation: &Naprawa{
			Action:  "packages.plan",
			Payload: json.RawMessage(`{"package_plan":{"mode":"upgrade","security_only":true}}`),
			Note:    "aktualizacja idzie dopiero po zatwierdzonym planie; plan pokazuje, co sie zmieni",
		},
	}
}

func ocenRestartu(wejscie Wejscie) Wynik {
	fragment, ok := wejscie.Fragment(modulPower)
	if !ok {
		return nieznane("nie odczytano stanu startu")
	}
	var stan power.Snapshot
	if err := json.Unmarshal(fragment.Payload, &stan); err != nil {
		return nieznane("nie odczytano stanu startu: " + err.Error())
	}
	if stan.RebootRequired == nil {
		return nieznane("host nie zglosil, czy wymaga restartu")
	}
	if !*stan.RebootRequired {
		return Wynik{Passed: true, Observed: "restart niewymagany"}
	}
	return Wynik{
		Observed: "host czeka na restart",
		Evidence: strings.Join(stan.RebootReasons, ", "),
		Remediation: &Naprawa{
			Action:  "system.reboot",
			Payload: json.RawMessage(`{"reboot":{"delay_seconds":15,"reason":"restart po poprawkach"}}`),
			Note:    "restart jest osobna faza; w kampanii idzie falami z health checkiem",
		},
	}
}

func stanOchrony(wejscie Wejscie) (security.Snapshot, bool) {
	fragment, ok := wejscie.Fragment(modulSecurity)
	if !ok {
		return security.Snapshot{}, false
	}
	var stan security.Snapshot
	if err := json.Unmarshal(fragment.Payload, &stan); err != nil {
		return security.Snapshot{}, false
	}
	return stan, true
}

func stanSSH(wejscie Wejscie) (sshmodul.Snapshot, bool) {
	fragment, ok := wejscie.Fragment(modulSSH)
	if !ok {
		return sshmodul.Snapshot{}, false
	}
	var stan sshmodul.Snapshot
	if err := json.Unmarshal(fragment.Payload, &stan); err != nil {
		return sshmodul.Snapshot{}, false
	}
	return stan, true
}

func opisMAC(mac security.Mandatory) string {
	switch mac.System {
	case security.SystemSELinux:
		return "SELinux: " + pierwszyNiepusty(mac.Mode, "tryb nieustalony")
	case security.SystemAppArmor:
		opis := "AppArmor"
		if mac.ProfilesEnforcing != nil {
			opis += ": profili wymuszanych " + strconv.Itoa(*mac.ProfilesEnforcing)
		}
		if mac.ProfilesComplain != nil {
			opis += ", w trybie skarg " + strconv.Itoa(*mac.ProfilesComplain)
		}
		return opis
	}
	return "brak"
}

func nieznane(powod string) Wynik {
	return Wynik{Unknown: true, Observed: powod}
}

func pierwszyNiepusty(wartosci ...string) string {
	for _, wartosc := range wartosci {
		if wartosc != "" {
			return wartosc
		}
	}
	return ""
}
