// Package security opisuje stan ochronny hosta: obowiazkowa kontrole dostepu,
// audyt, tryb rozruchu i to, czym host wystaje na zewnatrz.
//
// Modul zbiera fakty, a nie oceny. Ocena - czyli zgodnosc z profilem - powstaje
// w panelu, bo tam sa wersjonowane sprawdzenia i tam widac cala flote. Host,
// ktory sam by sie oceniał, musialby dostawac nowe reguly przy kazdej zmianie
// polityki i nie dalo by sie powiedziec, czy dwa hosty oceniono tak samo.
package security

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Sciezki, z ktorych czytamy stan.
const (
	KatalogSELinux    = "/sys/fs/selinux"
	PlikWymuszania    = KatalogSELinux + "/enforce"
	KonfiguracjaMAC   = "/etc/selinux/config"
	PlikAppArmor      = "/sys/module/apparmor/parameters/enabled"
	ProfileAppArmor   = "/sys/kernel/security/apparmor/profiles"
	PlikFIPS          = "/proc/sys/crypto/fips_enabled"
	PlikLockdown      = "/sys/kernel/security/lockdown"
	KatalogEFI        = "/sys/firmware/efi"
	KatalogEFIVars    = "/sys/firmware/efi/efivars"
	SciezkaSetenforce = "/usr/sbin/setenforce"
	// Augenrules sklada reguly z katalogu rules.d i laduje je do jadra.
	// To jest droga, ktora auditd sam przewiduje: jednostka demona na czesci
	// dystrybucji odmawia recznego restartu.
	SciezkaAugenrules = "/usr/sbin/augenrules"
	SciezkaAuditctl   = "/usr/sbin/auditctl"
	// Reguly audytu leza w plikach, ktore czyta tylko root - a plik dopisany
	// i niezaladowany opisuje audyt, ktorego nie ma.
	KatalogRegulAudytu = "/etc/audit/rules.d"
	PlikRegulAudytu    = "/etc/audit/audit.rules"
	SciezkaSS          = "/usr/bin/ss"
	SciezkaSSAlt       = "/usr/sbin/ss"

	// ZmiennaSecureBoot jest nazwa zmiennej EFI ze stanem secure boot.
	// Sufiks jest identyfikatorem globalnej przestrzeni nazw EFI.
	ZmiennaSecureBoot = "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
)

// Systemy obowiazkowej kontroli dostepu.
const (
	SystemSELinux  = "selinux"
	SystemAppArmor = "apparmor"
)

// Tryby SELinuksa.
const (
	TrybEnforcing  = "enforcing"
	TrybPermissive = "permissive"
	TrybDisabled   = "disabled"
)

// Mandatory opisuje obowiazkowa kontrole dostepu hosta.
//
// Tryb dzialajacy i tryb skonfigurowany sa dwoma polami, bo bywaja rozne:
// host przelaczony recznie w permissive wroci po restarcie do enforcing,
// a host z "SELINUX=enforcing" w pliku i wylaczonym SELinuksem w jadrze
// wyglada na chroniony, a nie jest.
type Mandatory struct {
	System         string `json:"system,omitempty"`
	Mode           string `json:"mode,omitempty"`
	ConfiguredMode string `json:"configured_mode,omitempty"`
	Policy         string `json:"policy,omitempty"`
	// Profile AppArmora licza sie osobno: profil w trybie skarg nie chroni,
	// tylko notuje.
	ProfilesEnforcing *int `json:"profiles_enforcing"`
	ProfilesComplain  *int `json:"profiles_complain"`
	// Reason mowi, dlaczego stanu nie ustalono albo dlaczego hosta nie chroni
	// zaden system MAC.
	Reason string `json:"reason,omitempty"`
}

// Chroni mowi, czy host ma dzialajaca obowiazkowa kontrole dostepu.
func (m Mandatory) Chroni() bool {
	switch m.System {
	case SystemSELinux:
		return m.Mode == TrybEnforcing
	case SystemAppArmor:
		return m.ProfilesEnforcing != nil && *m.ProfilesEnforcing > 0
	}
	return false
}

// Audyt opisuje stan demona audytu.
//
// Reguly zaladowane i reguly skonfigurowane sa dwoma polami, bo bywaja rozne:
// plik regul dopisany i niezaladowany opisuje audyt, ktorego nie ma, a sama
// liczba regul nie mowi, czy jadro je zna.
type Audyt struct {
	Present bool  `json:"present"`
	Active  *bool `json:"active"`
	// RulesLoaded jest liczba regul, ktore zna jadro; RulesConfigured -
	// liczba regul w plikach. Pusty wskaznik oznacza odczyt, ktory sie nie
	// powiodl, a nie brak regul.
	RulesLoaded     *int   `json:"rules_loaded"`
	RulesConfigured *int   `json:"rules_configured"`
	Reason          string `json:"reason,omitempty"`
}

// Zasieg gniazda. Panel nie orzeka, czy usluga jest widoczna z internetu -
// tego nie wie ani host, ani panel: adres prywatny bywa dostepny w calej sieci
// firmy, a publiczny bywa za zapora brzegowa. Nazywamy wiec to, co widac:
// czy gniazdo stoi na petli zwrotnej, na konkretnym adresie hosta, czy na
// wszystkich interfejsach naraz.
const (
	ZasiegPetla      = "loopback"
	ZasiegAdresHosta = "host-network"
	ZasiegWszystkie  = "all-interfaces"
)

// Nasluch to jedno gniazdo nasluchujace na hoscie.
type Nasluch struct {
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Process  string `json:"process,omitempty"`
	PID      uint32 `json:"pid,omitempty"`
	// Reach nazywa zasieg gniazda. Usluga na petli zwrotnej i ta sama usluga
	// na adresie hosta to dwie rozne sytuacje - ale zadna z nich nie jest
	// automatycznie "widoczna z internetu".
	Reach string `json:"reach"`
}

// PozaPetla mowi, czy gniazdo stoi poza petla zwrotna.
func (n Nasluch) PozaPetla() bool { return n.Reach != ZasiegPetla && n.Reach != "" }

// Snapshot to obraz stanu ochronnego hosta.
type Snapshot struct {
	MAC   Mandatory `json:"mac"`
	Audit Audyt     `json:"audit"`
	// Puste pola oznaczaja stan nieustalony, nie wylaczony.
	FIPSEnabled *bool `json:"fips_enabled"`
	SecureBoot  *bool `json:"secure_boot"`
	// SecureBootReason mowi, dlaczego stanu secure boot nie ma - najczesciej
	// dlatego, ze host wstaje w trybie BIOS i pytanie nie ma sensu.
	SecureBootReason string `json:"secure_boot_reason,omitempty"`
	Lockdown         string `json:"lockdown,omitempty"`
	// Listening jest lista gniazd nasluchujacych, ListeningKnown mowi, czy
	// w ogole dalo sie ja odczytac.
	Listening      []Nasluch `json:"listening,omitempty"`
	ListeningKnown bool      `json:"listening_known"`
	// OwnersKnown mowi, czy przy gniazdach jest wlasciciel. Bez roota lista
	// gniazd jest pelna, ale bezimienna - i to dwie rozne odpowiedzi.
	OwnersKnown bool `json:"owners_known"`
	// Missing wylicza fakty, ktorych nie udalo sie zebrac, wraz z powodem.
	// Sprawdzenia zamieniaja je na stan nieustalony z kodem powodu, zamiast
	// zgadywac wartosc.
	Missing map[string]string `json:"missing,omitempty"`

	ObservedAt        time.Time `json:"observed_at"`
	UnavailableReason string    `json:"unavailable_reason,omitempty"`
}

// PozaPetla wylicza gniazda stojace poza petla zwrotna.
func (s Snapshot) PozaPetla() []Nasluch {
	var poza []Nasluch
	for _, gniazdo := range s.Listening {
		if gniazdo.PozaPetla() {
			poza = append(poza, gniazdo)
		}
	}
	return poza
}

// WedlugZasiegu liczy gniazda w kazdej klasie zasiegu.
func (s Snapshot) WedlugZasiegu() map[string]int {
	liczby := map[string]int{}
	for _, gniazdo := range s.Listening {
		liczby[gniazdo.Reach]++
	}
	return liczby
}

// WalidujTryb sprawdza tryb SELinuksa zlecony przez panel.
//
// Panel przelacza miedzy enforcing i permissive, bo obie zmiany dzialaja od
// reki i obie da sie cofnac tak samo. Wylaczenia SELinuksa nie ustawia: zeby
// wrocic, host potrzebuje przeetykietowania calego systemu plikow i restartu,
// a to nie jest operacja, ktora panel moze obiecac.
func WalidujTryb(tryb string) error {
	switch tryb {
	case TrybEnforcing, TrybPermissive:
		return nil
	case TrybDisabled:
		return fmt.Errorf("panel nie wylacza SELinuksa: powrot wymaga przeetykietowania systemu plikow i restartu")
	}
	return fmt.Errorf("nieznany tryb %q", tryb)
}

// ParsujTrybWymuszania czyta /sys/fs/selinux/enforce.
func ParsujTrybWymuszania(tresc string) string {
	switch strings.TrimSpace(tresc) {
	case "1":
		return TrybEnforcing
	case "0":
		return TrybPermissive
	}
	return ""
}

// ParsujKonfiguracjeSELinux czyta /etc/selinux/config.
func ParsujKonfiguracjeSELinux(tresc string) (tryb, polityka string) {
	for _, linia := range strings.Split(tresc, "\n") {
		linia = strings.TrimSpace(linia)
		if linia == "" || strings.HasPrefix(linia, "#") {
			continue
		}
		klucz, wartosc, ok := strings.Cut(linia, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(klucz) {
		case "SELINUX":
			tryb = strings.TrimSpace(wartosc)
		case "SELINUXTYPE":
			polityka = strings.TrimSpace(wartosc)
		}
	}
	return tryb, polityka
}

// ParsujProfileAppArmor czyta /sys/kernel/security/apparmor/profiles.
//
// Wiersz ma postac "nazwa (tryb)". Profil w trybie skarg nie chroni, tylko
// notuje naruszenia, wiec liczymy oba tryby osobno.
func ParsujProfileAppArmor(tresc string) (wymuszane, skargi int) {
	for _, linia := range strings.Split(tresc, "\n") {
		linia = strings.TrimSpace(linia)
		if linia == "" {
			continue
		}
		otwarcie := strings.LastIndex(linia, "(")
		zamkniecie := strings.LastIndex(linia, ")")
		if otwarcie < 0 || zamkniecie < otwarcie {
			continue
		}
		switch strings.TrimSpace(linia[otwarcie+1 : zamkniecie]) {
		case "enforce":
			wymuszane++
		case "complain":
			skargi++
		}
	}
	return wymuszane, skargi
}

// ParsujRegulyZPliku liczy reguly zapisane w pliku.
//
// Komentarze i puste linie nie sa regulami; "-D" kasuje wszystkie i tez nia
// nie jest, choc wyglada jak wpis.
func ParsujRegulyZPliku(tresc string) int {
	reguly := 0
	for _, linia := range strings.Split(tresc, "\n") {
		linia = strings.TrimSpace(linia)
		if linia == "" || strings.HasPrefix(linia, "#") || linia == "-D" {
			continue
		}
		reguly++
	}
	return reguly
}

// ParsujReguly czyta wyjscie "auditctl -l".
func ParsujReguly(wyjscie string) int {
	reguly := 0
	for _, linia := range strings.Split(wyjscie, "\n") {
		linia = strings.TrimSpace(linia)
		if linia == "" || strings.HasPrefix(linia, "No rules") {
			continue
		}
		reguly++
	}
	return reguly
}

// ParsujLockdown czyta /sys/kernel/security/lockdown.
//
// Plik wylicza wszystkie tryby, a obowiazujacy jest w nawiasach kwadratowych.
func ParsujLockdown(tresc string) string {
	for _, pole := range strings.Fields(tresc) {
		if strings.HasPrefix(pole, "[") && strings.HasSuffix(pole, "]") {
			return strings.Trim(pole, "[]")
		}
	}
	return ""
}

// ParsujSecureBoot czyta zmienna EFI SecureBoot.
//
// Zmienna ma piec bajtow: cztery to atrybuty, ostatni jest wartoscia.
func ParsujSecureBoot(dane []byte) *bool {
	if len(dane) < 5 {
		return nil
	}
	wlaczony := dane[4] == 1
	return &wlaczony
}

// ParsujNasluch czyta wyjscie "ss -tulpnH".
//
// Kolumny sa stale: protokol, stan, kolejki, adres lokalny, adres zdalny
// i opcjonalnie proces. Adres lokalny niesie port po ostatnim dwukropku, bo
// adres IPv6 sam zawiera dwukropki.
func ParsujNasluch(wyjscie string) []Nasluch {
	var gniazda []Nasluch
	for _, linia := range strings.Split(wyjscie, "\n") {
		pola := strings.Fields(linia)
		if len(pola) < 5 {
			continue
		}
		protokol := pola[0]
		if protokol != "tcp" && protokol != "udp" {
			continue
		}
		adres, port, ok := rozdzielAdres(pola[4])
		if !ok {
			continue
		}
		gniazdo := Nasluch{
			Protocol: protokol,
			Address:  adres,
			Port:     port,
			Reach:    Zasieg(adres),
		}
		if len(pola) >= 7 {
			gniazdo.Process, gniazdo.PID = wlascicielGniazda(strings.Join(pola[6:], " "))
		}
		gniazda = append(gniazda, gniazdo)
	}
	return gniazda
}

// rozdzielAdres rozdziela adres lokalny na adres i port.
func rozdzielAdres(pole string) (string, int, bool) {
	dwukropek := strings.LastIndex(pole, ":")
	if dwukropek < 0 {
		return "", 0, false
	}
	port, err := strconv.Atoi(pole[dwukropek+1:])
	if err != nil {
		return "", 0, false
	}
	adres := strings.Trim(pole[:dwukropek], "[]")
	// ss dopisuje do adresu nazwe interfejsu po znaku procenta.
	if procent := strings.Index(adres, "%"); procent >= 0 {
		adres = adres[:procent]
	}
	return adres, port, true
}

// Zasieg klasyfikuje adres, pod ktorym stoi gniazdo.
//
// Klasyfikacja konczy sie na tym, co host o sobie wie. "Widoczne z internetu"
// jest wnioskiem o trasach i zaporach brzegowych, ktorego ani host, ani panel
// nie moga wyciagnac z samego adresu.
func Zasieg(adres string) string {
	switch {
	case adres == "":
		return ""
	case adres == "*", adres == "0.0.0.0", adres == "::":
		return ZasiegWszystkie
	case strings.HasPrefix(adres, "127."), adres == "::1":
		return ZasiegPetla
	default:
		return ZasiegAdresHosta
	}
}

// KluczGniazda identyfikuje gniazdo w odpowiedzi helpera o wlascicieli.
func KluczGniazda(protokol, adres string, port int) string {
	return protokol + "|" + adres + "|" + strconv.Itoa(port)
}

// Nazwy faktow, ktorych nie da sie odczytac bez roota. Helper dostaje ich
// liste, a nie polecenie do wykonania: zakres jego pracy jest wyliczony.
const (
	FaktProfileAppArmor   = "apparmor_profiles"
	FaktRegulyAudytu      = "audit_rules"
	FaktSecureBoot        = "secure_boot"
	FaktWlascicieleGniazd = "socket_owners"
)

// Wlasciciel to proces trzymajacy gniazdo.
type Wlasciciel struct {
	Process string `json:"process,omitempty"`
	PID     uint32 `json:"pid,omitempty"`
}

// Uzupelnienie to fakty zebrane przez helpera na wyrazne zadanie.
//
// Puste pole oznacza fakt, o ktory nie pytano albo ktorego nie udalo sie
// odczytac - powod jest wtedy w Errors, pod nazwa faktu.
type Uzupelnienie struct {
	ProfilesEnforcing *int                  `json:"profiles_enforcing,omitempty"`
	ProfilesComplain  *int                  `json:"profiles_complain,omitempty"`
	RulesLoaded       *int                  `json:"rules_loaded,omitempty"`
	RulesConfigured   *int                  `json:"rules_configured,omitempty"`
	SecureBoot        *bool                 `json:"secure_boot,omitempty"`
	SecureBootReason  string                `json:"secure_boot_reason,omitempty"`
	SocketOwners      map[string]Wlasciciel `json:"socket_owners,omitempty"`
	Errors            map[string]string     `json:"errors,omitempty"`
}

// wlascicielGniazda czyta pole users:(("nazwa",pid=N,fd=M)).
func wlascicielGniazda(pole string) (string, uint32) {
	otwarcie := strings.Index(pole, `(("`)
	if otwarcie < 0 {
		return "", 0
	}
	reszta := pole[otwarcie+3:]
	nazwa, reszta, ok := strings.Cut(reszta, `"`)
	if !ok {
		return "", 0
	}
	_, reszta, ok = strings.Cut(reszta, "pid=")
	if !ok {
		return nazwa, 0
	}
	cyfry := reszta
	if koniec := strings.IndexAny(cyfry, ",)"); koniec >= 0 {
		cyfry = cyfry[:koniec]
	}
	pid, err := strconv.ParseUint(cyfry, 10, 32)
	if err != nil {
		return nazwa, 0
	}
	return nazwa, uint32(pid)
}
