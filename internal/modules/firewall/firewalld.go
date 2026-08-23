package firewall

import (
	"fmt"
	"regexp"
	"strings"
)

// SciezkaFirewallCmd wskazuje narzedzie firewalld.
const SciezkaFirewallCmd = "/usr/bin/firewall-cmd"

var naglowekStrefy = regexp.MustCompile(`^(\S+)(?:\s+\(([^)]*)\))?$`)

// ParsujStrefy czyta wyjscie "firewall-cmd --list-all-zones".
//
// firewalld opisuje dostep strefami, a nie regulami: pytanie operatora brzmi
// "co jest otwarte na tym interfejsie", a nie "ktora regula pasuje jako
// pierwsza". Przepisywanie tego na liste regul zgubiloby te roznice.
func ParsujStrefy(wyjscie, domyslna string) []Zone {
	var strefy []Zone
	var biezaca *Zone

	for _, surowa := range strings.Split(wyjscie, "\n") {
		if strings.TrimSpace(surowa) == "" {
			continue
		}
		// Naglowek strefy zaczyna sie od poczatku wiersza; pola strefy sa
		// wciete. To jedyne, co odroznia je w tym formacie.
		if !strings.HasPrefix(surowa, " ") && !strings.HasPrefix(surowa, "\t") {
			pola := naglowekStrefy.FindStringSubmatch(strings.TrimSpace(surowa))
			if pola == nil {
				continue
			}
			znaczniki := pola[2]
			strefy = append(strefy, Zone{
				Name:    pola[1],
				Active:  strings.Contains(znaczniki, "active"),
				Default: strings.Contains(znaczniki, "default") || pola[1] == domyslna,
			})
			biezaca = &strefy[len(strefy)-1]
			continue
		}
		if biezaca == nil {
			continue
		}
		klucz, wartosc, ok := strings.Cut(strings.TrimSpace(surowa), ":")
		if !ok {
			continue
		}
		wartosc = strings.TrimSpace(wartosc)
		switch klucz {
		case "target":
			biezaca.Target = wartosc
		case "interfaces":
			biezaca.Interfaces = strings.Fields(wartosc)
		case "sources":
			biezaca.Sources = strings.Fields(wartosc)
		case "services":
			biezaca.Services = strings.Fields(wartosc)
		case "ports":
			biezaca.Ports = strings.Fields(wartosc)
		}
	}
	return strefy
}

// ArgumentyOtwarciaPortu sklada polecenie otwarcia portu w strefie.
//
// Zmiana jest trwala i przeladowana od razu: firewalld trzyma osobno stan
// biezacy i stan trwaly, a zmiana tylko w jednym z nich znika po restarcie
// albo po przeladowaniu - i za kazdym razem w innym momencie.
func ArgumentyOtwarciaPortu(strefa, port, protokol string, otworz bool) ([][]string, error) {
	if err := walidujStrefe(strefa); err != nil {
		return nil, err
	}
	if err := walidujPort(port); err != nil {
		return nil, err
	}
	if protokol != "tcp" && protokol != "udp" {
		return nil, fmt.Errorf("port dotyczy tcp albo udp, nie %q", protokol)
	}
	operacja := "--add-port=" + port + "/" + protokol
	if !otworz {
		operacja = "--remove-port=" + port + "/" + protokol
	}
	return [][]string{
		{SciezkaFirewallCmd, "--permanent", "--zone=" + strefa, operacja},
		{SciezkaFirewallCmd, "--reload"},
	}, nil
}

// ArgumentyUslugi sklada polecenie wlaczenia uslugi w strefie.
func ArgumentyUslugi(strefa, usluga string, wlacz bool) ([][]string, error) {
	if err := walidujStrefe(strefa); err != nil {
		return nil, err
	}
	if !nazwaUslugi.MatchString(usluga) {
		return nil, fmt.Errorf("nieprawidlowa nazwa uslugi %q", usluga)
	}
	operacja := "--add-service=" + usluga
	if !wlacz {
		operacja = "--remove-service=" + usluga
	}
	return [][]string{
		{SciezkaFirewallCmd, "--permanent", "--zone=" + strefa, operacja},
		{SciezkaFirewallCmd, "--reload"},
	}, nil
}

var (
	nazwaStrefy = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,16}$`)
	nazwaUslugi = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,31}$`)
)

func walidujStrefe(strefa string) error {
	if !nazwaStrefy.MatchString(strefa) {
		return fmt.Errorf("nieprawidlowa nazwa strefy %q", strefa)
	}
	return nil
}
