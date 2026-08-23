package agent

import "github.com/ultherego/flotestro/internal/modules/network"

// Nazwy adapterow. Nazwa mowi, co host ma, a nie czego chce operacja:
// operacja pyta o "packages", host odpowiada "packages.apt".
const (
	CapSystemd  = "systemd"
	CapAPT      = "packages.apt"
	CapDNF      = "packages.dnf"
	CapJournald = "journald"
	CapDocker   = "docker"
	// Compose jest osobnym adapterem: silnik kontenerow bywa bez niego,
	// a projekt bez wtyczki compose nie da sie ani zaplanowac, ani wdrozyc.
	CapCompose = "docker.compose"
	// Zadania cykliczne. Cron i timery systemd sa dwoma mechanizmami tego
	// samego, wiec jedna zdolnosc obejmuje oba.
	CapSchedules = "schedules"
	// Siec. Odczyt dziala wszedzie, gdzie jest iproute2; zapis wymaga
	// mechanizmu, ktory potrafi wycofac zmiane.
	CapNetwork = "network"
)

// Wymagania operacji. Nazwa logiczna nie wskazuje adaptera, bo operacja nie ma
// znac rodziny systemu hosta.
const (
	WymaganiePakiety         = "packages"
	WymaganieNaprawaPakietow = "packages.repair"
	// Zapis konfiguracji sieci. Odczyt dziala wszedzie, gdzie jest iproute2,
	// wiec sam modul nie mowi jeszcze, ze da sie tu cokolwiek zmienic.
	WymaganieZapisSieci = "network.write"
)

// Wersja kontraktu adaptera. Podnosi sie, gdy zmienia sie znaczenie operacji
// adaptera, a nie gdy zmienia sie wersja narzedzia na hoscie.
const wersjaAdaptera = 1

// Capability opisuje jeden adapter wykryty na hoscie.
type Capability struct {
	Name      string          `json:"name"`
	Version   uint32          `json:"version"`
	Available bool            `json:"available"`
	ReadOnly  bool            `json:"read_only"`
	Reason    string          `json:"reason,omitempty"`
	Features  map[string]bool `json:"features,omitempty"`
}

// Capabilities to rejestr adapterow hosta.
type Capabilities []Capability

// Available mowi, czy adapter o tej nazwie dziala na hoscie.
func (c Capabilities) Available(name string) bool {
	for _, cap := range c {
		if cap.Name == name {
			return cap.Available
		}
	}
	return false
}

// Feature mowi, czy adapter ma dana czesc.
func (c Capabilities) Feature(name, feature string) bool {
	wartosc, _ := c.FeatureStan(name, feature)
	return wartosc
}

// FeatureStan oddziela "nie ma tej czesci" od "nie wiadomo, czy ma".
//
// Agent sprzed rejestru nie przysyla cech wcale, a jego rejestr jest
// odtwarzany z pol logicznych. Uznanie milczenia za odmowe odebraloby takiemu
// hostowi operacje, ktora u niego dziala - nieznana cecha nie jest cecha
// nieobecna.
func (c Capabilities) FeatureStan(name, feature string) (wartosc bool, znana bool) {
	for _, capability := range c {
		if capability.Name != name {
			continue
		}
		if !capability.Available {
			// Adapter, ktorego nie ma, na pewno nie ma zadnej czesci.
			return false, true
		}
		value, ok := capability.Features[feature]
		return value, ok
	}
	// Adaptera nie ma w rejestrze - to tez jest odpowiedz, a nie niewiedza.
	return false, true
}

// Spelnia sprawdza wymaganie operacji. Wymagania sa nazwami logicznymi, a nie
// nazwami adapterow: operacja aktualizacji nie ma wiedziec, czy host uzywa
// apta czy dnf-a, a naprawa bazy pakietow ma wiedziec, ze dziala tylko dla apta.
func (c Capabilities) Spelnia(wymaganie string) bool {
	switch wymaganie {
	case "":
		return true
	case WymaganiePakiety:
		return c.Available(CapAPT) || c.Available(CapDNF)
	case WymaganieNaprawaPakietow:
		for _, adapter := range []string{CapAPT, CapDNF} {
			wartosc, znana := c.FeatureStan(adapter, "repair")
			if wartosc {
				return true
			}
			// Adapter obecny, ale milczacy o cechach: decyzje podejmuje host
			// przy wykonaniu, tak jak przed wprowadzeniem rejestru.
			if !znana && c.Available(adapter) {
				return true
			}
		}
		return false
	case WymaganieZapisSieci:
		// Zapis sieci wymaga mechanizmu, ktory utrwali zmiane i pozwoli ja
		// wycofac. Host bez niego ma sie o tym dowiedziec przy zlecaniu,
		// a nie po dostarczeniu zadania.
		wartosc, znana := c.FeatureStan(CapNetwork, "write")
		if wartosc {
			return true
		}
		// Adapter obecny, ale milczacy o cechach: decyzje podejmuje host
		// przy wykonaniu, tak jak przed wprowadzeniem rejestru.
		return !znana && c.Available(CapNetwork)
	default:
		return c.Available(wymaganie)
	}
}

// DetectCapabilities sprawdza obecnosc adapterow bez uruchamiania procesow.
//
// Niedostepny adapter niesie powod. Bez niego interfejs musialby zgadywac,
// dlaczego zakladki nie ma - i zgadywalby w kodzie przegladarki, wiec zle:
// przyczyna jest faktem o hoscie i host ma ja podac.
func DetectCapabilities() Capabilities {
	systemd := isDir("/run/systemd/system")
	apt := isExecutable("/usr/bin/apt-get")
	dnf := isExecutable("/usr/bin/dnf") || isExecutable("/usr/bin/dnf5")
	docker := exists("/var/run/docker.sock") || exists("/run/docker.sock")
	compose := docker && wtyczkaCompose() != ""
	journald := exists("/run/systemd/journal/socket")
	// Wpisy zarzadzane trafiaja do /etc/cron.d, wiec bez tego katalogu modul
	// nie ma gdzie ich zalozyc - nawet gdy timery systemd dzialaja.
	harmonogramy := isDir("/etc/cron.d")
	odczytSieci := exists("/usr/sbin/ip") || exists("/sbin/ip") || exists("/usr/bin/ip")
	zapisSieci := network.WykryjAdapter(network.Istnieje)

	return Capabilities{
		{
			Name:      CapSystemd,
			Version:   wersjaAdaptera,
			Available: systemd,
			Reason:    powod(systemd, "this host does not run systemd"),
		},
		{
			Name:      CapAPT,
			Version:   wersjaAdaptera,
			Available: apt,
			Reason:    powod(apt, "apt-get is not installed on this host"),
			// Naprawa bazy pakietow odpowiada na pytania debconfa. Bez jego
			// narzedzi operacja padlaby dopiero na hoscie, po zatwierdzeniu.
			Features: map[string]bool{
				"repair": apt &&
					isExecutable("/usr/bin/debconf-show") &&
					isExecutable("/usr/bin/debconf-set-selections"),
			},
		},
		{
			Name:      CapDNF,
			Version:   wersjaAdaptera,
			Available: dnf,
			Reason:    powod(dnf, "dnf is not installed on this host"),
			// Blokada bazy rpm wyglada inaczej niz pytanie debconfa i naprawa
			// tez wygladalaby inaczej, wiec adapter jej nie ma.
			Features: map[string]bool{"repair": false},
		},
		{
			Name:      CapNetwork,
			Version:   wersjaAdaptera,
			Available: odczytSieci,
			// Host bez mechanizmu zapisu nie jest hostem bez sieci: modul
			// dziala, tylko w trybie odczytu - i mowi, dlaczego.
			ReadOnly: zapisSieci == "",
			Features: map[string]bool{
				"routes":                      odczytSieci,
				"write":                       zapisSieci != "",
				network.AdapterNetworkManager: zapisSieci == network.AdapterNetworkManager,
				network.AdapterNmstate:        zapisSieci == network.AdapterNmstate,
				network.AdapterNetplan:        zapisSieci == network.AdapterNetplan,
			},
			Reason: powodSieciowy(odczytSieci, zapisSieci),
		},
		{
			Name:      CapSchedules,
			Version:   wersjaAdaptera,
			Available: harmonogramy,
			Features:  map[string]bool{"cron": harmonogramy, "timers": systemd},
			Reason:    powod(harmonogramy, "this host has no /etc/cron.d directory"),
		},
		{
			Name:      CapJournald,
			Version:   wersjaAdaptera,
			Available: journald,
			Reason:    powod(journald, "this host has no journald socket"),
		},
		{
			Name:      CapCompose,
			Version:   wersjaAdaptera,
			Available: compose,
			Reason: powod(compose,
				"this host has no Docker Compose plugin"),
		},
		{
			Name:      CapDocker,
			Version:   wersjaAdaptera,
			Available: docker,
			// Adapter czyta stan silnika i wykonuje operacje na kontenerach.
			// Projekty Compose sa osobna cecha: silnik bywa bez wtyczki.
			Features: map[string]bool{"read": docker, "write": docker, "compose": compose},
			Reason:   powod(docker, "this host has no Docker socket"),
		},
	}
}

// sciezkiWtyczkiCompose to miejsca, w ktorych dystrybucje instaluja wtyczke.
var sciezkiWtyczkiCompose = []string{
	"/usr/libexec/docker/cli-plugins/docker-compose",
	"/usr/lib/docker/cli-plugins/docker-compose",
	"/usr/local/lib/docker/cli-plugins/docker-compose",
	"/root/.docker/cli-plugins/docker-compose",
}

// wtyczkaCompose zwraca sciezke wtyczki albo pustke. Sprawdzamy obecnosc
// pliku, a nie uruchamiamy narzedzia: wykrywanie zdolnosci nie moze
// uruchamiac procesow.
func wtyczkaCompose() string {
	for _, sciezka := range sciezkiWtyczkiCompose {
		if isExecutable(sciezka) {
			return sciezka
		}
	}
	return ""
}

// powod zwraca wyjasnienie tylko dla adaptera niedostepnego.
func powod(dostepny bool, gdyBrak string) string {
	if dostepny {
		return ""
	}
	return gdyBrak
}

// powodGdy wyjasnia oba stany: adapter obecny bywa ograniczony i to tez
// wymaga zdania, a nie ciszy.
func powodGdy(dostepny bool, gdyJest, gdyBrak string) string {
	if dostepny {
		return gdyJest
	}
	return gdyBrak
}

// powodSieciowy tlumaczy, czego modulowi sieci brakuje na tym hoscie.
// Brak zapisu i brak calego modulu to dwie rozne odpowiedzi.
func powodSieciowy(odczyt bool, adapter string) string {
	if !odczyt {
		return "this host has no iproute2 (ip) binary"
	}
	return network.PowodBrakuZapisu(adapter)
}
