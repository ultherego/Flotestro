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
	SciezkaAuditctl   = "/usr/sbin/auditctl"
	SciezkaSS         = "/usr/bin/ss"
	SciezkaSSAlt      = "/usr/sbin/ss"

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
type Audyt struct {
	Present bool  `json:"present"`
	Active  *bool `json:"active"`
	// Rules jest liczba regul zaladowanych do jadra. Pusty wskaznik oznacza
	// odczyt, ktory sie nie powiodl, a nie brak regul.
	Rules  *int   `json:"rules"`
	Reason string `json:"reason,omitempty"`
}

// Nasluch to jedno gniazdo nasluchujace na hoscie.
type Nasluch struct {
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Process  string `json:"process,omitempty"`
	PID      uint32 `json:"pid,omitempty"`
	// Exposed oznacza gniazdo widoczne spoza hosta. Usluga na petli zwrotnej
	// i ta sama usluga na adresie zewnetrznym to dwie rozne sytuacje.
	Exposed bool `json:"exposed"`
}

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

	ObservedAt        time.Time `json:"observed_at"`
	UnavailableReason string    `json:"unavailable_reason,omitempty"`
}

// Wystawione wylicza gniazda widoczne spoza hosta.
func (s Snapshot) Wystawione() []Nasluch {
	var wystawione []Nasluch
	for _, gniazdo := range s.Listening {
		if gniazdo.Exposed {
			wystawione = append(wystawione, gniazdo)
		}
	}
	return wystawione
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
			Exposed:  WystawionyAdres(adres),
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

// WystawionyAdres mowi, czy gniazdo pod tym adresem jest widoczne spoza hosta.
func WystawionyAdres(adres string) bool {
	switch {
	case adres == "":
		return false
	case adres == "*", adres == "0.0.0.0", adres == "::":
		return true
	case strings.HasPrefix(adres, "127."), adres == "::1":
		return false
	// Adres link-local nie wychodzi poza segment, ale jest widoczny dla
	// kazdego, kto w nim stoi - wiec liczy sie jako wystawiony.
	default:
		return true
	}
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
