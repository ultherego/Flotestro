package ssh

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// ParsujEffective czyta wyjscie "sshd -T".
//
// To jedyne zrodlo, ktore mowi, co serwer naprawde uwaza za swoja
// konfiguracje: pliki dolaczane maja wlasna kolejnosc i wygrywa w nich
// pierwsza wartosc, wiec skladanie tego samemu z tresci plikow konczy sie
// obrazem, ktorego host nie potwierdza.
func ParsujEffective(wyjscie string) Snapshot {
	snapshot := Snapshot{}
	for _, linia := range strings.Split(wyjscie, "\n") {
		linia = strings.TrimSpace(linia)
		if linia == "" {
			continue
		}
		klucz, wartosc, ok := strings.Cut(linia, " ")
		if !ok {
			continue
		}
		wartosc = strings.TrimSpace(wartosc)
		switch klucz {
		case "port":
			snapshot.Ports = append(snapshot.Ports, wartosc)
		case "listenaddress":
			snapshot.ListenAddresses = append(snapshot.ListenAddresses, wartosc)
		case "permitrootlogin":
			snapshot.PermitRootLogin = wartosc
		case "passwordauthentication":
			snapshot.PasswordAuthentication = wartosc
		case "pubkeyauthentication":
			snapshot.PubkeyAuthentication = wartosc
		case "kbdinteractiveauthentication":
			snapshot.KbdInteractive = wartosc
		case "gssapiauthentication":
			snapshot.GSSAPIAuthentication = wartosc
		case "maxauthtries":
			snapshot.MaxAuthTries, _ = strconv.Atoi(wartosc)
		case "allowusers":
			snapshot.AllowUsers = append(snapshot.AllowUsers, strings.Fields(wartosc)...)
		case "allowgroups":
			snapshot.AllowGroups = append(snapshot.AllowGroups, strings.Fields(wartosc)...)
		case "denyusers":
			snapshot.DenyUsers = append(snapshot.DenyUsers, strings.Fields(wartosc)...)
		case "denygroups":
			snapshot.DenyGroups = append(snapshot.DenyGroups, strings.Fields(wartosc)...)
		}
	}
	return snapshot
}

var odciskKlucza = regexp.MustCompile(`^(\d+)\s+(\S+)\s+.*\((\w+)\)\s*$`)

// ParsujOdcisk czyta jeden wiersz "ssh-keygen -l -f".
//
// Bierzemy odcisk i metadane, nigdy klucz prywatny: jego kopia w bazie panelu
// bylaby kopia tozsamosci hosta.
func ParsujOdcisk(linia, sciezka string) (HostKey, bool) {
	pola := odciskKlucza.FindStringSubmatch(strings.TrimSpace(linia))
	if pola == nil {
		return HostKey{}, false
	}
	bity, _ := strconv.Atoi(pola[1])
	return HostKey{
		Type:        strings.ToLower(pola[3]),
		Bits:        bity,
		Fingerprint: pola[2],
		Path:        sciezka,
	}, true
}

// SkladajDropIn sklada tresc pliku konfiguracyjnego panelu.
//
// Zapisujemy wylacznie te ustawienia, o ktore operator poprosil. Wypisanie
// calej konfiguracji "dla porzadku" zamrozilby na hoscie wartosci domyslne
// z dnia zapisu - a te zmieniaja sie razem z wersja OpenSSH.
func SkladajDropIn(ustawienia Ustawienia) (string, error) {
	if err := Waliduj(ustawienia); err != nil {
		return "", err
	}
	wiersze := []string{NaglowekPliku}
	dopisz := func(klucz, wartosc string) {
		if wartosc != "" {
			wiersze = append(wiersze, klucz+" "+wartosc)
		}
	}
	dopisz("Port", ustawienia.Port)
	dopisz("PermitRootLogin", ustawienia.PermitRootLogin)
	dopisz("PasswordAuthentication", ustawienia.PasswordAuthentication)
	dopisz("PubkeyAuthentication", ustawienia.PubkeyAuthentication)
	dopisz("KbdInteractiveAuthentication", ustawienia.KbdInteractive)
	dopisz("MaxAuthTries", ustawienia.MaxAuthTries)
	if len(ustawienia.AllowUsers) > 0 {
		dopisz("AllowUsers", strings.Join(ustawienia.AllowUsers, " "))
	}
	if len(ustawienia.AllowGroups) > 0 {
		dopisz("AllowGroups", strings.Join(ustawienia.AllowGroups, " "))
	}
	if len(ustawienia.DenyUsers) > 0 {
		dopisz("DenyUsers", strings.Join(ustawienia.DenyUsers, " "))
	}
	if len(wiersze) == 1 {
		return "", fmt.Errorf("zmiana nie zawiera zadnego ustawienia")
	}
	return strings.Join(wiersze, "\n") + "\n", nil
}

// RozbiezneUstawienia porownuje to, o co poprosil operator, z tym, co serwer
// naprawde stosuje.
//
// W konfiguracji sshd wygrywa pierwsza wartosc, a pliki dolaczane maja
// kolejnosc alfabetyczna: wczesniejszy plik administratora hosta przeslania
// nasz i zmiana wyglada na wykonana, choc nic nie zmienia. Zamiast udawac
// sukces, mowimy wprost, ktore ustawienie nie doszlo do skutku.
func RozbiezneUstawienia(chciane Ustawienia, stan Snapshot) []string {
	var rozbiezne []string
	porownaj := func(nazwa, chciana, obecna string) {
		if chciana == "" {
			return
		}
		if !strings.EqualFold(chciana, obecna) {
			rozbiezne = append(rozbiezne, fmt.Sprintf("%s: zlecono %q, serwer stosuje %q",
				nazwa, chciana, obecna))
		}
	}
	porownaj("PermitRootLogin", chciane.PermitRootLogin, stan.PermitRootLogin)
	porownaj("PasswordAuthentication", chciane.PasswordAuthentication, stan.PasswordAuthentication)
	porownaj("PubkeyAuthentication", chciane.PubkeyAuthentication, stan.PubkeyAuthentication)
	porownaj("KbdInteractiveAuthentication", chciane.KbdInteractive, stan.KbdInteractive)
	if chciane.MaxAuthTries != "" {
		porownaj("MaxAuthTries", chciane.MaxAuthTries, strconv.Itoa(stan.MaxAuthTries))
	}
	if chciane.Port != "" {
		obecny := ""
		if len(stan.Ports) > 0 {
			obecny = stan.Ports[0]
		}
		porownaj("Port", chciane.Port, obecny)
	}
	return rozbiezne
}
