package security

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Wykonawca uruchamia narzedzie hosta i zwraca jego wyjscie.
type Wykonawca func(ctx context.Context, sciezka string, argumenty ...string) (string, error)

const sciezkaSystemctl = "/usr/bin/systemctl"

// jednostkaAudytu jest jednostka demona audytu. Nazwa jest ta sama na obu
// rodzinach systemow, wiec nie ma tu czego wykrywac.
const jednostkaAudytu = "auditd.service"

// Zbierz czyta to, co da sie przeczytac bez roota.
//
// Modul nie idzie przez roota w calosci. Tryb SELinuksa, przelacznik
// AppArmora, FIPS, lockdown, lista gniazd i stan jednostki audytu sa czytelne
// dla kazdego - i to jest wiekszosc obrazu. Root jest potrzebny do czterech
// rzeczy, o ktore agent pyta helpera osobno i po nazwie.
func Zbierz(ctx context.Context, uruchom Wykonawca) Snapshot {
	snapshot := Snapshot{ObservedAt: time.Now().UTC(), Missing: map[string]string{}}
	snapshot.MAC = StanMAC()
	snapshot.Audit = stanAudytu(ctx, uruchom)

	if tresc, err := os.ReadFile(PlikFIPS); err == nil {
		wlaczony := strings.TrimSpace(string(tresc)) == "1"
		snapshot.FIPSEnabled = &wlaczony
	}
	if tresc, err := os.ReadFile(PlikLockdown); err == nil {
		snapshot.Lockdown = ParsujLockdown(string(tresc))
	}
	// Secure boot wymaga zmiennych EFI, a te czyta tylko root. Host bez EFI
	// odpowiada od razu, bo pytanie nie ma wtedy sensu.
	if !exists(KatalogEFI) {
		snapshot.SecureBootReason = "host wstaje w trybie BIOS, wiec secure boot nie ma zastosowania"
	} else {
		snapshot.Missing[FaktSecureBoot] = "zmienne EFI czyta tylko root"
	}

	snapshot.Listening, snapshot.ListeningKnown = gniazda(ctx, uruchom)
	if snapshot.ListeningKnown {
		snapshot.Missing[FaktWlascicieleGniazd] = "wlascicieli gniazd widzi tylko root"
	}
	if snapshot.MAC.System == SystemAppArmor {
		snapshot.Missing[FaktProfileAppArmor] = "profile AppArmora leza w securityfs"
	}
	if snapshot.Audit.Present {
		snapshot.Missing[FaktRegulyAudytu] = "reguly audytu czyta tylko root"
	}
	return snapshot
}

// Brakujace wylicza fakty, o ktore trzeba zapytac helpera.
func (s Snapshot) Brakujace() []string {
	nazwy := make([]string, 0, len(s.Missing))
	for nazwa := range s.Missing {
		nazwy = append(nazwy, nazwa)
	}
	sort.Strings(nazwy)
	return nazwy
}

// Uzupelnij dopisuje do obrazu fakty zebrane przez helpera.
//
// Fakt, o ktory pytano i ktorego nie udalo sie odczytac, zostaje na liscie
// brakow razem z powodem: sprawdzenie zamieni go na stan nieustalony, a nie
// na wartosc domyslna.
func (s Snapshot) Uzupelnij(dodatki Uzupelnienie) Snapshot {
	if s.Missing == nil {
		s.Missing = map[string]string{}
	}
	if dodatki.ProfilesEnforcing != nil || dodatki.ProfilesComplain != nil {
		s.MAC.ProfilesEnforcing = dodatki.ProfilesEnforcing
		s.MAC.ProfilesComplain = dodatki.ProfilesComplain
		delete(s.Missing, FaktProfileAppArmor)
	}
	if dodatki.RulesLoaded != nil || dodatki.RulesConfigured != nil {
		s.Audit.RulesLoaded = dodatki.RulesLoaded
		s.Audit.RulesConfigured = dodatki.RulesConfigured
		delete(s.Missing, FaktRegulyAudytu)
	}
	if dodatki.SecureBoot != nil {
		s.SecureBoot = dodatki.SecureBoot
		s.SecureBootReason = ""
		delete(s.Missing, FaktSecureBoot)
	} else if dodatki.SecureBootReason != "" {
		s.SecureBootReason = dodatki.SecureBootReason
		delete(s.Missing, FaktSecureBoot)
	}
	if dodatki.SocketOwners != nil {
		for i := range s.Listening {
			klucz := KluczGniazda(s.Listening[i].Protocol, s.Listening[i].Address, s.Listening[i].Port)
			if wlasciciel, ok := dodatki.SocketOwners[klucz]; ok {
				s.Listening[i].Process = wlasciciel.Process
				s.Listening[i].PID = wlasciciel.PID
			}
		}
		s.OwnersKnown = true
		delete(s.Missing, FaktWlascicieleGniazd)
	}
	for nazwa, powod := range dodatki.Errors {
		s.Missing[nazwa] = powod
	}
	if len(s.Missing) == 0 {
		s.Missing = nil
	}
	return s
}

// StanMAC ustala, ktory system obowiazkowej kontroli dostepu chroni host.
//
// Odczyt nie wymaga roota: tryb SELinuksa, jego konfiguracja i przelacznik
// AppArmora sa czytelne dla kazdego. Liczba profili AppArmora juz nie - ta
// jest osobnym faktem, o ktory pyta sie helpera.
func StanMAC() Mandatory {
	// SELinux rozpoznajemy po jego systemie plikow, a nie po pliku
	// konfiguracyjnym: konfiguracja bywa zostawiona na hoscie, na ktorym
	// SELinux jest wylaczony w jadrze, i wygladalaby na ochrone.
	konfiguracja, _ := os.ReadFile(KonfiguracjaMAC)
	trybZKonfiguracji, polityka := ParsujKonfiguracjeSELinux(string(konfiguracja))

	if exists(KatalogSELinux) {
		mac := Mandatory{System: SystemSELinux, ConfiguredMode: trybZKonfiguracji, Policy: polityka}
		if tresc, err := os.ReadFile(PlikWymuszania); err == nil {
			mac.Mode = ParsujTrybWymuszania(string(tresc))
		} else {
			mac.Reason = "nie odczytano trybu: " + err.Error()
		}
		return mac
	}
	if trybZKonfiguracji != "" {
		// Konfiguracja mowi "enforcing", a jadro nie ma SELinuksa w ogole.
		// To jest dokladnie ten przypadek, ktory wyglada na ochrone.
		return Mandatory{
			System: SystemSELinux, Mode: TrybDisabled,
			ConfiguredMode: trybZKonfiguracji, Policy: polityka,
			Reason: "SELinux jest wylaczony w jadrze mimo wpisu w konfiguracji",
		}
	}

	if tresc, err := os.ReadFile(PlikAppArmor); err == nil {
		if strings.TrimSpace(string(tresc)) != "Y" {
			return Mandatory{
				System: SystemAppArmor, Mode: TrybDisabled,
				Reason: "AppArmor jest obecny, ale wylaczony w jadrze",
			}
		}
		return Mandatory{System: SystemAppArmor, Mode: TrybEnforcing}
	}
	return Mandatory{Reason: "ten host nie ma ani SELinuksa, ani AppArmora"}
}

// stanAudytu opisuje demona audytu na podstawie tego, co widac bez roota.
func stanAudytu(ctx context.Context, uruchom Wykonawca) Audyt {
	audyt := Audyt{Present: exists(SciezkaAuditctl)}
	wyjscie, err := uruchom(ctx, sciezkaSystemctl, "show", "-p", "LoadState", "-p", "ActiveState", jednostkaAudytu)
	if err == nil {
		wczytana, aktywna := stanJednostki(wyjscie)
		if wczytana {
			audyt.Present = true
			audyt.Active = &aktywna
		}
	}
	if !audyt.Present {
		audyt.Reason = "ten host nie ma demona audytu"
	}
	return audyt
}

// stanJednostki czyta odpowiedz "systemctl show".
func stanJednostki(wyjscie string) (wczytana, aktywna bool) {
	for _, linia := range strings.Split(wyjscie, "\n") {
		klucz, wartosc, ok := strings.Cut(strings.TrimSpace(linia), "=")
		if !ok {
			continue
		}
		switch klucz {
		case "LoadState":
			wczytana = wartosc != "not-found"
		case "ActiveState":
			aktywna = wartosc == "active" || wartosc == "activating"
		}
	}
	return wczytana, aktywna
}

// gniazda wylicza to, czym host wystaje na zewnatrz - bez wlascicieli.
func gniazda(ctx context.Context, uruchom Wykonawca) ([]Nasluch, bool) {
	sciezka := SciezkaSS
	if !exists(sciezka) {
		sciezka = SciezkaSSAlt
	}
	if !exists(sciezka) {
		return nil, false
	}
	// Bez -p: wlasciciel gniazda wymaga prawa do cudzych procesow, a sama
	// lista gniazd jest pelna takze bez niego.
	wyjscie, err := uruchom(ctx, sciezka, "-tulnH")
	if err != nil {
		return nil, false
	}
	return ParsujNasluch(wyjscie), true
}

// ZbierzUzupelnienie odczytuje fakty wymagajace roota. Zakres jest wyliczony:
// helper dostaje liste nazw, a nie polecenie do wykonania.
func ZbierzUzupelnienie(ctx context.Context, uruchom Wykonawca, fakty []string) Uzupelnienie {
	dodatki := Uzupelnienie{Errors: map[string]string{}}
	for _, fakt := range fakty {
		switch fakt {
		case FaktProfileAppArmor:
			tresc, err := os.ReadFile(ProfileAppArmor)
			if err != nil {
				dodatki.Errors[fakt] = "nie odczytano profili: " + err.Error()
				continue
			}
			wymuszane, skargi := ParsujProfileAppArmor(string(tresc))
			dodatki.ProfilesEnforcing = &wymuszane
			dodatki.ProfilesComplain = &skargi

		case FaktRegulyAudytu:
			if wyjscie, err := uruchom(ctx, SciezkaAuditctl, "-l"); err == nil {
				zaladowane := ParsujReguly(wyjscie)
				dodatki.RulesLoaded = &zaladowane
			} else {
				dodatki.Errors[fakt] = "nie odczytano regul jadra: " + err.Error()
			}
			skonfigurowane, err := regulyZPlikow()
			if err != nil {
				dodatki.Errors[fakt] = "nie odczytano plikow regul: " + err.Error()
				continue
			}
			dodatki.RulesConfigured = &skonfigurowane

		case FaktSecureBoot:
			dane, err := os.ReadFile(KatalogEFIVars + "/" + ZmiennaSecureBoot)
			if err != nil {
				dodatki.SecureBootReason = "nie odczytano zmiennej EFI: " + err.Error()
				continue
			}
			stan := ParsujSecureBoot(dane)
			if stan == nil {
				dodatki.SecureBootReason = "zmienna EFI ma nieoczekiwany rozmiar"
				continue
			}
			dodatki.SecureBoot = stan

		case FaktWlascicieleGniazd:
			sciezka := SciezkaSS
			if !exists(sciezka) {
				sciezka = SciezkaSSAlt
			}
			wyjscie, err := uruchom(ctx, sciezka, "-tulpnH")
			if err != nil {
				dodatki.Errors[fakt] = "nie odczytano wlascicieli: " + err.Error()
				continue
			}
			dodatki.SocketOwners = map[string]Wlasciciel{}
			for _, gniazdo := range ParsujNasluch(wyjscie) {
				dodatki.SocketOwners[KluczGniazda(gniazdo.Protocol, gniazdo.Address, gniazdo.Port)] =
					Wlasciciel{Process: gniazdo.Process, PID: gniazdo.PID}
			}

		default:
			dodatki.Errors[fakt] = "nieznany fakt"
		}
	}
	if len(dodatki.Errors) == 0 {
		dodatki.Errors = nil
	}
	return dodatki
}

// regulyZPlikow liczy reguly zapisane w konfiguracji audytu.
//
// Zrodlem jest katalog rules.d, jesli istnieje: augenrules sklada z niego plik
// audit.rules, wiec liczenie obu razem liczyloby te same reguly dwa razy.
func regulyZPlikow() (int, error) {
	wpisy, err := os.ReadDir(KatalogRegulAudytu)
	if err == nil {
		razem := 0
		for _, wpis := range wpisy {
			if wpis.IsDir() || !strings.HasSuffix(wpis.Name(), ".rules") {
				continue
			}
			tresc, err := os.ReadFile(filepath.Join(KatalogRegulAudytu, wpis.Name()))
			if err != nil {
				return 0, err
			}
			razem += ParsujRegulyZPliku(string(tresc))
		}
		return razem, nil
	} else if !os.IsNotExist(err) {
		return 0, err
	}
	tresc, err := os.ReadFile(PlikRegulAudytu)
	if err != nil {
		return 0, err
	}
	return ParsujRegulyZPliku(string(tresc)), nil
}

func exists(sciezka string) bool {
	_, err := os.Stat(sciezka)
	return err == nil
}
