package agent

import (
	"context"

	"github.com/ultherego/flotestro/internal/modules/certificates"
	"github.com/ultherego/flotestro/internal/modules/docker"
	"github.com/ultherego/flotestro/internal/modules/files"
	"github.com/ultherego/flotestro/internal/modules/firewall"
	"github.com/ultherego/flotestro/internal/modules/kernel"
	"github.com/ultherego/flotestro/internal/modules/schedules"
	"github.com/ultherego/flotestro/internal/modules/security"
	sshmodul "github.com/ultherego/flotestro/internal/modules/ssh"
)

// KolejnoscModulow ustala porzadek zbierania.
//
// Kolejnosc jest jawna, bo mapa jej nie ma, a inwentarz ma powstawac tak samo
// przy kazdym cyklu: rewizja liczona z faktow zebranych w innej kolejnosci
// nadal jest ta sama, ale czas zbierania i obciazenie hosta juz nie.
//
// Nazwy sa te same, ktorymi inwentarz dzieli sie na fragmenty - operator
// prosi o odswiezenie tego, na co patrzy, a nie wewnetrznego pola faktow.
// ModulSystem nie ma tu wpisu: fakty podstawowe sa zbierane zawsze, bo to
// one rozstrzygaja, ktore pozostale moduly maja sens.
var KolejnoscModulow = []string{
	ModulServices, ModulPackages, ModulIdentity, ModulAccounts, ModulContainers,
	ModulSchedules, ModulNetwork, ModulDNS, ModulStorage, ModulFiles,
	ModulKernel, ModulSecurity, ModulBackups, ModulCerts, ModulPower,
	ModulTime, ModulSSH, ModulFirewall,
}

// ModulInwentarza zna sie na jednym module: umie go zebrac i umie przepisac
// poprzedni wynik, gdy odswiezenie go nie obejmuje.
type ModulInwentarza struct {
	zbierz   func(ctx context.Context, facts *Facts, adresZarzadzania string)
	przepisz func(facts *Facts, poprzednie Facts)
}

var zbieraczeModulow = map[string]ModulInwentarza{
	ModulServices: {
		zbierz: func(ctx context.Context, facts *Facts, _ string) {
			if facts.Capabilities.Available(CapSystemd) {
				facts.FailedUnits, facts.FailedUnitsKnown = failedUnits(ctx)
			}
		},
		przepisz: func(facts *Facts, poprzednie Facts) {
			facts.FailedUnits, facts.FailedUnitsKnown = poprzednie.FailedUnits, poprzednie.FailedUnitsKnown
		},
	},

	ModulPackages: {
		zbierz: func(ctx context.Context, facts *Facts, _ string) {
			switch {
			case facts.Capabilities.Available(CapAPT):
				facts.Packages = aptSummary(ctx)
			case facts.Capabilities.Available(CapDNF):
				facts.Packages = dnfSummary(ctx)
			}
			// Odcisk pelnej listy pakietow: sama lista jest za duza, zeby
			// jechac w kazdym cyklu, ale panel musi wiedziec, kiedy jego
			// kopia przestaje opisywac host.
			if facts.Packages.Manager != "" {
				odcisk, ile, powod := odciskPakietow(ctx, facts.Packages.Manager)
				facts.Packages.InstalledDigest = odcisk
				facts.Packages.InstalledReason = powod
				if powod == "" {
					liczba := uint32(ile)
					facts.Packages.InstalledCount = &liczba
				}
				// Zrodla pakietow czytamy razem z podsumowaniem: to jedna
				// zakladka i jedna odpowiedz na pytanie, skad host bierze
				// oprogramowanie. Odczyt idzie bez roota, bo pliki sa jawne.
				obraz := ZbierzRepozytoria(facts.Packages.Manager)
				facts.Repositories = &obraz
			}
		},
		przepisz: func(facts *Facts, poprzednie Facts) {
			facts.Packages = poprzednie.Packages
			facts.Repositories = poprzednie.Repositories
		},
	},

	ModulIdentity: {
		zbierz: func(ctx context.Context, facts *Facts, _ string) {
			// Stan domeny jest czescia inventory, wiec zbierany raz na cykl,
			// a nie przy kazdym heartbeacie.
			facts.Identity = ReadIdentityState(ctx)
			if facts.Identity.Enrolled && privilegedIdentity != nil {
				privileged, err := privilegedIdentity(ctx, facts.Identity.Domain)
				if err != nil {
					// Brak danych uprzywilejowanych nie uniewaznia reszty
					// inventory, ale musi byc widoczny jako powod, a nie
					// jako cisza.
					facts.Identity.UnavailableReason = "helper: " + err.Error()
					return
				}
				facts.Identity = facts.Identity.Merge(privileged)
			}
		},
		przepisz: func(facts *Facts, poprzednie Facts) { facts.Identity = poprzednie.Identity },
	},

	ModulAccounts: {
		zbierz: func(ctx context.Context, facts *Facts, _ string) {
			// Konta lokalne czytamy z pliku; stan blokady i klucze SSH
			// wymagaja roota i sa uzupelniane przez helpera.
			facts.LocalAccounts = ReadLocalAccounts()
			if privilegedAccounts == nil {
				return
			}
			names := make([]string, 0, len(facts.LocalAccounts))
			for _, account := range facts.LocalAccounts {
				if account.Source == SourceLocal {
					names = append(names, account.Name)
				}
			}
			if len(names) == 0 {
				return
			}
			if result, err := privilegedAccounts(ctx, names); err == nil {
				facts.LocalAccounts = mergePrivilegedAccounts(facts.LocalAccounts, result)
			}
		},
		przepisz: func(facts *Facts, poprzednie Facts) { facts.LocalAccounts = poprzednie.LocalAccounts },
	},

	ModulContainers: {
		zbierz: func(ctx context.Context, facts *Facts, _ string) {
			// Silnik kontenerow jest odpytywany raz na cykl inwentarza
			// i tylko o podsumowanie. Pelne listy pobiera operator, gdy
			// otworzy zakladke - odpytywanie silnika przy kazdym cyklu
			// obciazaloby host bez powodu.
			if !facts.Capabilities.Available(CapDocker) || dockerProbe == nil {
				return
			}
			snapshot, err := dockerProbe(ctx, false)
			if err != nil {
				// Nieodczytany silnik nie moze wygladac jak host bez
				// kontenerow.
				facts.Containers = &docker.Summary{UnavailableReason: "helper: " + err.Error()}
				return
			}
			podsumowanie := snapshot.Summary
			facts.Containers = &podsumowanie
		},
		przepisz: func(facts *Facts, poprzednie Facts) { facts.Containers = poprzednie.Containers },
	},

	ModulSchedules: {
		zbierz: func(ctx context.Context, facts *Facts, _ string) {
			// Harmonogramy zmieniaja sie rzadko, wiec ida w cyklu inwentarza,
			// a nie na zadanie: pelna lista zadan cyklicznych hosta to
			// kilkanascie wpisow, a nie setki jak przy pakietach.
			if !facts.Capabilities.Available(CapSchedules) || scheduleProbe == nil {
				return
			}
			snapshot, err := scheduleProbe(ctx)
			if err != nil {
				facts.Schedules = &schedules.Snapshot{UnavailableReason: "helper: " + err.Error()}
				return
			}
			facts.Schedules = &snapshot
		},
		przepisz: func(facts *Facts, poprzednie Facts) { facts.Schedules = poprzednie.Schedules },
	},

	ModulNetwork: {
		zbierz: func(ctx context.Context, facts *Facts, adresZarzadzania string) {
			// Siec czytamy z jadra w kazdym cyklu: odczyt jest tani, a stan
			// potrafi zmienic sie bez udzialu panelu (DHCP, kabel, kontener).
			siec := ZbierzSiec(ctx, adresZarzadzania)
			facts.Network = &siec
		},
		przepisz: func(facts *Facts, poprzednie Facts) { facts.Network = poprzednie.Network },
	},

	ModulDNS: {
		zbierz: func(ctx context.Context, facts *Facts, _ string) {
			// Resolver czytamy razem z siecia: to jedna decyzja hosta o tym,
			// dokad ida jego pytania i ktora droga.
			resolver := ZbierzDNS(ctx)
			facts.DNS = &resolver
		},
		przepisz: func(facts *Facts, poprzednie Facts) { facts.DNS = poprzednie.DNS },
	},

	ModulStorage: {
		zbierz: func(ctx context.Context, facts *Facts, _ string) {
			// Topologia dyskow zmienia sie rzadko, ale zajetosc miejsca juz
			// nie - dlatego czytamy calosc raz na cykl inwentarza.
			przestrzen := ZbierzPrzestrzen(ctx)
			facts.Storage = &przestrzen
		},
		przepisz: func(facts *Facts, poprzednie Facts) { facts.Storage = poprzednie.Storage },
	},

	ModulFiles: {
		zbierz: func(ctx context.Context, facts *Facts, _ string) {
			// Stan plikow zarzadzanych: host sam wie, ktore pliki panel
			// zapisal, wiec drift widac bez pytania panelu o liste.
			if fileProbe == nil {
				return
			}
			snapshot, err := fileProbe(ctx)
			if err != nil {
				facts.Files = &files.Snapshot{UnavailableReason: "helper: " + err.Error()}
				return
			}
			facts.Files = &snapshot
		},
		przepisz: func(facts *Facts, poprzednie Facts) { facts.Files = poprzednie.Files },
	},

	ModulKernel: {
		zbierz: func(ctx context.Context, facts *Facts, _ string) {
			// Ustawienia jadra czyta helper: czesc kluczy /proc/sys jest
			// czytelna wylacznie dla roota, a lista modulow i tak potrzebuje
			// jego oczu.
			if kernelProbe == nil {
				return
			}
			snapshot, err := kernelProbe(ctx)
			if err != nil {
				facts.Kernel = &kernel.Snapshot{UnavailableReason: "helper: " + err.Error()}
				return
			}
			facts.Kernel = &snapshot
		},
		przepisz: func(facts *Facts, poprzednie Facts) { facts.Kernel = poprzednie.Kernel },
	},

	ModulSecurity: {
		zbierz: func(ctx context.Context, facts *Facts, _ string) {
			// Stan ochronny sklada agent: wiekszosc faktow jest czytelna bez
			// roota, a te, ktore nie sa, zamawia u helpera po nazwie.
			if securityProbe == nil {
				return
			}
			snapshot, err := securityProbe(ctx)
			if err != nil {
				facts.Security = &security.Snapshot{UnavailableReason: err.Error()}
				return
			}
			facts.Security = &snapshot
		},
		przepisz: func(facts *Facts, poprzednie Facts) { facts.Security = poprzednie.Security },
	},

	ModulBackups: {
		zbierz: func(ctx context.Context, facts *Facts, _ string) {
			// Narzedzia backupu czyta agent bez roota: obecnosc binarki i jej
			// wersja sa jawne. Stanu repozytorium tu nie ma - ten wymaga
			// poswiadczen.
			stanBackupu := ZbierzBackup(ctx)
			facts.Backup = &stanBackupu
		},
		przepisz: func(facts *Facts, poprzednie Facts) { facts.Backup = poprzednie.Backup },
	},

	ModulCerts: {
		zbierz: func(ctx context.Context, facts *Facts, _ string) {
			// Certyfikaty czyta agent, a helper doklada to, czego bez roota
			// nie widac. Zakres jest wyliczony: rejestr celow panelu
			// i zlecenia certmongera, a nie przeszukanie systemu plikow.
			if certificateProbe == nil {
				return
			}
			snapshot, err := certificateProbe(ctx)
			if err != nil {
				facts.Certificates = &certificates.Snapshot{UnavailableReason: err.Error()}
				return
			}
			facts.Certificates = &snapshot
		},
		przepisz: func(facts *Facts, poprzednie Facts) { facts.Certificates = poprzednie.Certificates },
	},

	ModulPower: {
		zbierz: func(ctx context.Context, facts *Facts, _ string) {
			// Stan startu i blokad wylaczenia. Restart nie konczy sie na
			// wyslaniu polecenia, wiec panel potrzebuje boot_id i tego, co
			// restart wstrzymuje.
			zasilanie := ZbierzZasilanie(ctx, facts.BootID, facts.RebootRequired)
			facts.Power = &zasilanie
		},
		przepisz: func(facts *Facts, poprzednie Facts) { facts.Power = poprzednie.Power },
	},

	ModulTime: {
		zbierz: func(ctx context.Context, facts *Facts, _ string) {
			// Czas czyta agent, a nie helper: timedatectl i chronyc
			// odpowiadaja kazdemu, a kazde przejscie przez roota trzeba
			// uzasadnic.
			zegar := ZbierzCzas(ctx)
			facts.Time = &zegar
		},
		przepisz: func(facts *Facts, poprzednie Facts) { facts.Time = poprzednie.Time },
	},

	ModulSSH: {
		zbierz: func(ctx context.Context, facts *Facts, _ string) {
			// Konfiguracje sshd czyta helper: "sshd -T" wymaga roota, bo
			// serwer czyta przy okazji klucze hosta.
			if !facts.Capabilities.Available(CapSSHD) || sshProbe == nil {
				return
			}
			snapshot, err := sshProbe(ctx)
			if err != nil {
				facts.SSH = &sshmodul.Snapshot{UnavailableReason: "helper: " + err.Error()}
				return
			}
			facts.SSH = &snapshot
		},
		przepisz: func(facts *Facts, poprzednie Facts) { facts.SSH = poprzednie.SSH },
	},

	ModulFirewall: {
		zbierz: func(ctx context.Context, facts *Facts, _ string) {
			// Zapore czyta helper: tablice nftables sa widoczne wylacznie dla
			// roota. Odczyt jest tani, ale liczniki rosna same, wiec nie
			// robimy z niego zrodla metryk - od tego jest monitoring.
			if !facts.Capabilities.Available(CapFirewall) || firewallProbe == nil {
				return
			}
			snapshot, err := firewallProbe(ctx)
			if err != nil {
				facts.Firewall = &firewall.Snapshot{UnavailableReason: "helper: " + err.Error()}
				return
			}
			facts.Firewall = &snapshot
		},
		przepisz: func(facts *Facts, poprzednie Facts) { facts.Firewall = poprzednie.Firewall },
	},
}
