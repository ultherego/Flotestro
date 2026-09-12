package agent

import (
	"github.com/ultherego/flotestro/internal/modules/backup"
	"github.com/ultherego/flotestro/internal/modules/certificates"
	"github.com/ultherego/flotestro/internal/modules/network"
	"github.com/ultherego/flotestro/internal/modules/security"
	czas "github.com/ultherego/flotestro/internal/modules/time"
)

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
	// Resolver hosta. Odczyt dziala wszedzie, gdzie jest resolv.conf; zapis
	// wymaga mechanizmu, ktory zmiane utrwali.
	CapDNS = "dns"
	// Zapora. Adapter mowi, kto na tym hoscie trzyma reguly.
	CapFirewall = "firewall"
	// Przestrzen dyskowa. Odczyt wymaga lsblk; LVM i macierze sa osobnymi
	// cechami, bo host bywa bez nich.
	CapStorage = "storage"
	// Serwer sshd. Konfiguracja idzie do wlasnego pliku w sshd_config.d.
	CapSSHD = "sshd"
	// Jadro: ustawienia sysctl i moduly.
	CapKernel = "kernel"
	// Czas hosta. Odczyt dziala wszedzie, gdzie jest timedatectl; zapis
	// wymaga demona, ktoremu panel ma gdzie dopisac serwery.
	CapTime = "time"
	// Stan ochronny hosta. Odczyt dziala wszedzie; przelaczenie trybu MAC
	// jest osobna zdolnoscia, bo host bez SELinuksa nie ma czego przelaczac.
	CapSecurity    = "security"
	CapSecurityMAC = "security.mac"
	// Audyt jest osobna zdolnoscia: host bez auditd nie ma czego przeladowac,
	// a przeladowanie idzie przez augenrules, nie przez restart jednostki.
	CapSecurityAudit = "security.audit"
	// Certyfikaty na hostach. Modul dziala wszedzie, bo oglada wskazane pliki
	// i wdraza nowe. Odnowienie jest osobna zdolnoscia: robi je demon hosta,
	// a host bez certmongera nie ma czym odnawiac.
	CapCertificates      = "certificates"
	CapCertificatesRenew = "certificates.renew"
	// Pliki konfiguracyjne. Zakres sciezek wyznacza administrator hosta.
	CapFiles = "files.managed"
	// Sonda z hosta. Dziala wszedzie: to zwykle polaczenie, bez roota
	// i bez dodatkowego narzedzia.
	CapMonitoring = "monitoring"
	// Backup. Modul steruje narzedziem, ktore host juz ma: bez narzedzia
	// i bez runbookow nie ma czym zrobic kopii.
	CapBackup = "backup"
)

// The requirements of operations. A logical name does not point at an
// adapter, because an operation is not to know the host's system family.
const (
	NeedPackages      = "packages"
	NeedPackageRepair = "packages.repair"
	// Writing the network configuration. Reading works everywhere iproute2
	// is, so the module alone does not yet say that anything can be changed
	// here.
	NeedNetworkWrite  = "network.write"
	NeedDNSWrite      = "dns.write"
	NeedFirewallWrite = "firewall.write"
	NeedFirewallZones = "firewall.zones"
	NeedLVM           = "storage.lvm"
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
	wartosc, _ := c.FeatureState(name, feature)
	return wartosc
}

// FeatureState separates "it does not have this part" from "it is not known
// whether it has it".
//
// An agent from before the registry sends no features at all, and its
// registry is reconstructed from logical fields. Treating silence as a
// refusal would take away from such a host an operation that works on it - an
// unknown feature is not an absent feature.
func (c Capabilities) FeatureState(name, feature string) (value bool, known bool) {
	for _, capability := range c {
		if capability.Name != name {
			continue
		}
		if !capability.Available {
			// An adapter that is not there certainly has no parts.
			return false, true
		}
		value, ok := capability.Features[feature]
		return value, ok
	}
	// The adapter is not in the registry - that is an answer too, not ignorance.
	return false, true
}

// Satisfies checks an operation's requirement. Requirements are logical names
// rather than adapter names: an upgrade operation is not to know whether the
// host uses apt or dnf, and repairing the package database is to know that it
// works for apt only.
func (c Capabilities) Satisfies(requirement string) bool {
	switch requirement {
	case "":
		return true
	case NeedPackages:
		return c.Available(CapAPT) || c.Available(CapDNF)
	case NeedPackageRepair:
		for _, adapter := range []string{CapAPT, CapDNF} {
			value, known := c.FeatureState(adapter, "repair")
			if value {
				return true
			}
			// The adapter is present but silent about its features: the host
			// decides at execution time, as it did before the registry was
			// introduced.
			if !known && c.Available(adapter) {
				return true
			}
		}
		return false
	case NeedFirewallWrite:
		value, known := c.FeatureState(CapFirewall, "write")
		if value {
			return true
		}
		return !known && c.Available(CapFirewall)
	case NeedLVM:
		value, _ := c.FeatureState(CapStorage, "lvm")
		return value
	case NeedFirewallZones:
		// Zones exist only where firewalld runs. A host with nftables alone
		// has nothing to show and nothing to change.
		value, _ := c.FeatureState(CapFirewall, "zones")
		return value
	case NeedDNSWrite:
		value, known := c.FeatureState(CapDNS, "write")
		if value {
			return true
		}
		return !known && c.Available(CapDNS)
	case NeedNetworkWrite:
		// Writing the network requires a mechanism that persists the change
		// and allows rolling it back. A host without one is to learn about it
		// when the operation is ordered, not after the task is delivered.
		value, known := c.FeatureState(CapNetwork, "write")
		if value {
			return true
		}
		// The adapter is present but silent about its features: the host
		// decides at execution time, as it did before the registry was
		// introduced.
		return !known && c.Available(CapNetwork)
	default:
		return c.Available(requirement)
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
	resolver := exists("/etc/resolv.conf")
	resolved := exists("/usr/bin/resolvectl") && exists("/run/systemd/resolve")
	nft := exists("/usr/sbin/nft")
	lsblk := exists("/usr/bin/lsblk")
	sshd := exists("/usr/sbin/sshd")
	sysctl := exists("/usr/sbin/sysctl") || exists("/sbin/sysctl")
	modprobe := exists("/usr/sbin/modprobe") || exists("/sbin/modprobe")
	// Panel zapisuje wylacznie do wlasnego pliku, wiec bez katalogu
	// dolaczanego moglby tylko czytac: sshd_config nalezy do dystrybucji.
	dropIn := isDir("/etc/ssh/sshd_config.d")
	lvm := exists("/usr/sbin/vgs") && exists("/usr/sbin/lvs")
	fsck := exists("/usr/sbin/fsck")
	firewalld := exists("/usr/bin/firewall-cmd") && isDir("/run/firewalld")
	timedatectl := exists(czas.SciezkaTimedatectl)
	selinux := isDir(security.KatalogSELinux) && exists(security.SciezkaSetenforce)
	audyt := exists(security.SciezkaAuditctl) && exists(security.SciezkaAugenrules)
	apparmor := exists(security.PlikAppArmor)
	certmonger := exists(certificates.SciezkaGetcert) || exists(certificates.SciezkaGetcertAlt)
	restic := exists("/usr/bin/restic") || exists("/usr/local/bin/restic")
	borg := exists("/usr/bin/borg") || exists("/usr/local/bin/borg")
	runbooki, _ := backup.WykazRunbookow()
	chrony := exists(czas.SciezkaChronyc)
	// Timesyncd bywa zainstalowany i zamaskowany, gdy host ma chronyego.
	// Obecnosc jednostki mowi tylko tyle, ze jest czym pisac - ktory demon
	// naprawde trzyma zegar, rozstrzyga dopiero odczyt stanu.
	timesyncd := exists("/usr/lib/systemd/systemd-timesyncd") ||
		exists("/lib/systemd/systemd-timesyncd")

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
			Name:    CapFiles,
			Version: wersjaAdaptera,
			// Modul dziala wszedzie: zakres pochodzi z allowlisty, a jej brak
			// oznacza liste domyslna, a nie brak modulu.
			Available: true,
			Features:  map[string]bool{"allowlist": exists("/etc/flotestro/files.allow")},
		},
		{
			Name:      CapTime,
			Version:   wersjaAdaptera,
			Available: timedatectl,
			// Host, na ktorym nie ma czego skonfigurowac, nadal pokazuje
			// czas i przesuniecie - modul jest wtedy do odczytu.
			ReadOnly: !chrony && !timesyncd,
			Features: map[string]bool{
				"chrony":    chrony,
				"timesyncd": timesyncd,
				"write":     chrony || timesyncd,
				"timezone":  timedatectl,
			},
			Reason: powod(timedatectl, "this host has no timedatectl"),
		},
		{
			Name:    CapSecurity,
			Version: wersjaAdaptera,
			// Modul dziala wszedzie: brak SELinuksa czy audytu jest faktem
			// o hoscie, a nie brakiem modulu.
			Available: true,
			Features: map[string]bool{
				"selinux":    selinux,
				"apparmor":   apparmor,
				"auditd":     exists(security.SciezkaAuditctl),
				"augenrules": exists(security.SciezkaAugenrules),
				"sockets":    exists(security.SciezkaSS) || exists(security.SciezkaSSAlt),
			},
		},
		{
			Name:    CapCertificates,
			Version: wersjaAdaptera,
			// Modul dziala wszedzie: brak certyfikatow jest faktem o hoscie,
			// a nie brakiem modulu.
			Available: true,
			Features: map[string]bool{
				"certmonger": certmonger,
				"deploy":     true,
			},
		},
		{
			Name:    CapMonitoring,
			Version: wersjaAdaptera,
			// Sonda nie wymaga niczego poza siecia, wiec modul dziala
			// wszedzie. Metryki i alerty czyta panel z systemow centralnych,
			// a nie agent - host nie dostaje z tego powodu ani jednego
			// dodatkowego collectora.
			Available: true,
			Features:  map[string]bool{"probe.http": true, "probe.tcp": true},
		},
		{
			Name:      CapBackup,
			Version:   wersjaAdaptera,
			Available: restic || borg || len(runbooki) > 0,
			Features: map[string]bool{
				"restic": restic, "borg": borg, "runbook": len(runbooki) > 0,
			},
			Reason: powod(restic || borg || len(runbooki) > 0,
				"this host has no backup tool the panel can drive"),
		},
		{
			Name:      CapCertificatesRenew,
			Version:   wersjaAdaptera,
			Available: certmonger,
			Reason:    powod(certmonger, "this host does not run certmonger"),
		},
		{
			Name:      CapSecurityAudit,
			Version:   wersjaAdaptera,
			Available: audyt,
			Reason:    powod(audyt, "this host has no auditd rule tooling"),
		},
		{
			Name:      CapSecurityMAC,
			Version:   wersjaAdaptera,
			Available: selinux,
			Reason:    powod(selinux, "this host has no SELinux to switch"),
		},
		{
			Name:      CapKernel,
			Version:   wersjaAdaptera,
			Available: sysctl,
			Features:  map[string]bool{"sysctl": sysctl, "modules": modprobe},
			Reason:    powod(sysctl, "this host has no sysctl binary"),
		},
		{
			Name:      CapSSHD,
			Version:   wersjaAdaptera,
			Available: sshd,
			ReadOnly:  !dropIn,
			Features:  map[string]bool{"dropin": dropIn, "hostkeys": exists("/usr/bin/ssh-keygen")},
			Reason:    powodSSHD(sshd, dropIn),
		},
		{
			Name:      CapStorage,
			Version:   wersjaAdaptera,
			Available: lsblk,
			Features: map[string]bool{
				"lvm":  lvm,
				"fsck": fsck,
				"raid": exists("/proc/mdstat"),
			},
			Reason: powod(lsblk, "this host has no lsblk binary"),
		},
		{
			Name:      CapFirewall,
			Version:   wersjaAdaptera,
			Available: nft || firewalld,
			ReadOnly:  !nft && !firewalld,
			Features: map[string]bool{
				"nftables":  nft,
				"firewalld": firewalld,
				"write":     nft,
				"zones":     firewalld,
			},
			Reason: powod(nft || firewalld, "this host has neither nftables nor firewalld"),
		},
		{
			Name:      CapDNS,
			Version:   wersjaAdaptera,
			Available: resolver,
			ReadOnly:  zapisSieci != network.AdapterNetworkManager,
			Features: map[string]bool{
				"resolved": resolved,
				"write":    zapisSieci == network.AdapterNetworkManager,
			},
			Reason: powodResolvera(resolver, zapisSieci),
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

// powodResolvera tlumaczy, czego brakuje modulowi DNS.
func powodResolvera(resolver bool, adapter string) string {
	if !resolver {
		return "this host has no /etc/resolv.conf"
	}
	if adapter != network.AdapterNetworkManager {
		return "resolver changes need NetworkManager; without it a write to resolv.conf " +
			"would be overwritten by whoever owns the file"
	}
	return ""
}

// powodSSHD tlumaczy, czego brakuje modulowi sshd.
func powodSSHD(sshd, dropIn bool) string {
	if !sshd {
		return "this host has no sshd"
	}
	if !dropIn {
		return "this sshd has no sshd_config.d include; the panel would have to rewrite " +
			"the distribution's sshd_config, so it only reads here"
	}
	return ""
}
