package ssh

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Wzorzec konta dopuszcza forme "uzytkownik@host" i gwiazdke, bo tak dziala
// AllowUsers w sshd - i to jest cala jego skladnia.
var wzorzecKonta = regexp.MustCompile(`^[A-Za-z0-9_.*?@-]{1,64}$`)

// Wartosci logiczne sshd. "prohibit-password" nie jest ani yes, ani no,
// wiec wartosci trzymamy jako tekst i sprawdzamy z listy.
var (
	wartosciLogiczne = map[string]bool{"yes": true, "no": true}
	wartosciRoota    = map[string]bool{
		"yes": true, "no": true, "prohibit-password": true, "forced-commands-only": true,
	}
)

// Waliduj sprawdza zmiane konfiguracji przed zapisem.
func Waliduj(ustawienia Ustawienia) error {
	if ustawienia.Port != "" {
		port, err := strconv.Atoi(ustawienia.Port)
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("port %q jest poza zakresem 1-65535", ustawienia.Port)
		}
	}
	if ustawienia.PermitRootLogin != "" && !wartosciRoota[ustawienia.PermitRootLogin] {
		return fmt.Errorf("nieobslugiwana wartosc PermitRootLogin %q", ustawienia.PermitRootLogin)
	}
	for nazwa, wartosc := range map[string]string{
		"PasswordAuthentication":       ustawienia.PasswordAuthentication,
		"PubkeyAuthentication":         ustawienia.PubkeyAuthentication,
		"KbdInteractiveAuthentication": ustawienia.KbdInteractive,
	} {
		if wartosc != "" && !wartosciLogiczne[wartosc] {
			return fmt.Errorf("%s przyjmuje yes albo no, nie %q", nazwa, wartosc)
		}
	}
	if ustawienia.MaxAuthTries != "" {
		proby, err := strconv.Atoi(ustawienia.MaxAuthTries)
		if err != nil || proby < 1 || proby > 100 {
			return fmt.Errorf("MaxAuthTries %q jest poza zakresem 1-100", ustawienia.MaxAuthTries)
		}
	}
	for _, lista := range [][]string{ustawienia.AllowUsers, ustawienia.DenyUsers} {
		for _, wpis := range lista {
			if !wzorzecKonta.MatchString(wpis) {
				return fmt.Errorf("nieprawidlowy wzorzec konta %q", wpis)
			}
		}
	}
	for _, grupa := range ustawienia.AllowGroups {
		if !wzorzecKonta.MatchString(grupa) {
			return fmt.Errorf("nieprawidlowa nazwa grupy %q", grupa)
		}
	}
	return nil
}

// OdcinaWszystkieMetody mowi, czy po zmianie zostanie choc jedna metoda
// uwierzytelnienia.
//
// Serwer, do ktorego nie da sie zalogowac zadna metoda, nie jest
// zabezpieczony - jest niedostepny. To nie to samo i panel nie moze zrobic
// z jednego drugiego przez przeoczenie.
func OdcinaWszystkieMetody(chciane Ustawienia, stan Snapshot) bool {
	wartosc := func(chciana, obecna string) string {
		if chciana != "" {
			return chciana
		}
		return obecna
	}
	haslo := wartosc(chciane.PasswordAuthentication, stan.PasswordAuthentication)
	klucz := wartosc(chciane.PubkeyAuthentication, stan.PubkeyAuthentication)
	interaktywna := wartosc(chciane.KbdInteractive, stan.KbdInteractive)
	// GSSAPI zostawiamy po stronie stanu: panel go nie ustawia, ale host
	// w domenie moze na nim polegac.
	gssapi := stan.GSSAPIAuthentication

	for _, metoda := range []string{haslo, klucz, interaktywna, gssapi} {
		if strings.EqualFold(metoda, "yes") {
			return false
		}
	}
	return true
}
