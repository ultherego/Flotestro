package packages

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
	"time"
)

// InstalledPackage opisuje jeden zainstalowany pakiet w postaci, ktora
// wystarcza do korelacji z trackerem bezpieczenstwa dystrybucji.
//
// Sama nazwa pakietu binarnego nie wystarcza. Debian prowadzi bezpieczenstwo
// po pakietach zrodlowych - jeden zrodlowy daje kilkanascie binarnych - a RPM
// wymaga pelnej NEVRA razem z epoka, bo bez niej "1.0" i "1:1.0" wygladaja
// tak samo, a znacza co innego. Dlatego zbieramy oba komplety pol, nawet gdy
// na danym hoscie czesc z nich jest pusta.
type InstalledPackage struct {
	Name string `json:"name"`
	// SourceName i SourceVersion sa pakietem zrodlowym. Dla apt biora sie
	// wprost z bazy dpkg, dla rpm - z nazwy pliku zrodlowego.
	SourceName    string `json:"source_name,omitempty"`
	SourceVersion string `json:"source_version,omitempty"`

	// Epoch jest pusty, gdy pakiet jej nie ma. Zero i brak epoki znacza dla
	// porownania to samo, ale w zapisie sa rozne i tak je zostawiamy.
	Epoch        string `json:"epoch,omitempty"`
	Version      string `json:"version"`
	Release      string `json:"release,omitempty"`
	Architecture string `json:"architecture,omitempty"`

	SourceRPM string `json:"source_rpm,omitempty"`
	Vendor    string `json:"vendor,omitempty"`
	// RepositoryID mowi, skad pakiet przyszedl. Puste oznacza, ze host tego
	// nie zapamietal - a nie, ze pakiet jest spoza repozytoriow.
	RepositoryID string `json:"repository_id,omitempty"`
	ModuleStream string `json:"module_stream,omitempty"`
}

// EVR sklada wersje w postaci, ktorej uzywa porownanie RPM.
func (p InstalledPackage) EVR() string {
	wersja := p.Version
	if p.Epoch != "" && p.Epoch != "0" {
		wersja = p.Epoch + ":" + wersja
	}
	if p.Release != "" {
		wersja += "-" + p.Release
	}
	return wersja
}

// WersjaDeb sklada wersje w postaci, ktorej uzywa porownanie Debiana.
//
// W dpkg rewizja jest czescia jednego napisu wersji, wiec skladamy ja z
// powrotem tylko wtedy, gdy zostala rozdzielona.
func (p InstalledPackage) WersjaDeb() string {
	wersja := p.Version
	if p.Epoch != "" {
		wersja = p.Epoch + ":" + wersja
	}
	if p.Release != "" {
		wersja += "-" + p.Release
	}
	return wersja
}

// ListaZainstalowanych jest obrazem pakietow hosta.
type ListaZainstalowanych struct {
	Manager  string             `json:"manager"`
	Packages []InstalledPackage `json:"packages,omitempty"`
	// Digest identyfikuje zawartosc listy. Panel trzyma go przy wierszach
	// i porownuje z odciskiem z inwentarza: rozjazd znaczy, ze lista w bazie
	// opisuje inny stan niz host, a nie ze host jest czysty.
	Digest string `json:"digest"`
	Count  int    `json:"count"`
	// ObservedAt jest chwila odczytu; korelacja bez wieku danych nie ma
	// sensu, bo nie wiadomo, czego dotyczy odpowiedz.
	ObservedAt time.Time `json:"observed_at"`
	// UnavailableReason mowi, dlaczego listy nie ma. Pusta lista i lista
	// nieodczytana to dwie rozne odpowiedzi - i tylko jedna z nich pozwala
	// powiedziec cokolwiek o podatnosciach.
	UnavailableReason string `json:"unavailable_reason,omitempty"`
}

// Odcisk liczy skrot listy pakietow w postaci kanonicznej.
//
// Kanonizacja jest jawna i wersjonowana: bez tego ta sama lista dawalaby rozne
// odciski po zmianie kolejnosci pol, a panel co cykl pobieralby ja od nowa.
const wersjaKanonizacjiListy = 1

// Odcisk liczy odcisk listy pakietow.
func Odcisk(pakiety []InstalledPackage) string {
	kopia := make([]InstalledPackage, len(pakiety))
	copy(kopia, pakiety)
	sort.Slice(kopia, func(i, j int) bool {
		if kopia[i].Name != kopia[j].Name {
			return kopia[i].Name < kopia[j].Name
		}
		if kopia[i].Architecture != kopia[j].Architecture {
			return kopia[i].Architecture < kopia[j].Architecture
		}
		return kopia[i].EVR() < kopia[j].EVR()
	})

	suma := sha256.New()
	suma.Write([]byte("flotestro/packages/v" + strconv.Itoa(wersjaKanonizacjiListy) + "\n"))
	for _, pakiet := range kopia {
		suma.Write([]byte(strings.Join([]string{
			pakiet.Name, pakiet.Epoch, pakiet.Version, pakiet.Release,
			pakiet.Architecture, pakiet.SourceName, pakiet.SourceVersion,
		}, "\x1f")))
		suma.Write([]byte{'\n'})
	}
	return hex.EncodeToString(suma.Sum(nil))
}

// Zainstalowane czyta pelna liste pakietow hosta.
//
// Odczyt nie wymaga roota: baza dpkg i baza RPM sa czytelne dla wszystkich.
// Lista jest duza, wiec pobiera sie ja na zadanie, a nie w kazdym cyklu
// inwentarza - inwentarz niesie sam odcisk i liczbe pakietow.
func Zainstalowane(ctx context.Context, menedzer string) ListaZainstalowanych {
	lista := ListaZainstalowanych{Manager: menedzer, ObservedAt: time.Now().UTC()}
	switch menedzer {
	case "apt":
		lista.Packages, lista.UnavailableReason = zainstalowaneAPT(ctx)
	case "dnf":
		lista.Packages, lista.UnavailableReason = zainstalowaneRPM(ctx)
	default:
		lista.UnavailableReason = "this package manager cannot list installed packages"
	}
	lista.Count = len(lista.Packages)
	lista.Digest = Odcisk(lista.Packages)
	return lista
}

// zainstalowaneAPT czyta baze dpkg razem z pakietami zrodlowymi.
func zainstalowaneAPT(ctx context.Context) ([]InstalledPackage, string) {
	// Pole source:Version jest puste, gdy wersja zrodlowa rowna sie binarnej;
	// dpkg-query wypelnia je tylko przy roznicy, wiec uzupelniamy je sami.
	format := `${db:Status-Status}\t${Package}\t${Version}\t${Architecture}\t` +
		`${source:Package}\t${source:Version}\n`
	result := run(ctx, 2*time.Minute, "/usr/bin/dpkg-query", "-W", "-f", format)
	if !result.Ran || result.ExitCode != 0 {
		return nil, "dpkg-query: " + result.Reason()
	}

	var pakiety []InstalledPackage
	for _, linia := range strings.Split(result.Stdout, "\n") {
		pola := strings.Split(linia, "\t")
		if len(pola) < 6 {
			continue
		}
		// Pakiet usuniety z pozostawiona konfiguracja nie jest zainstalowany:
		// jego kod juz na hoscie nie lezy, wiec nie jest tez podatny.
		if strings.TrimSpace(pola[0]) != "installed" {
			continue
		}
		pakiet := InstalledPackage{
			Name:          strings.TrimSpace(pola[1]),
			Version:       strings.TrimSpace(pola[2]),
			Architecture:  strings.TrimSpace(pola[3]),
			SourceName:    strings.TrimSpace(pola[4]),
			SourceVersion: strings.TrimSpace(pola[5]),
		}
		if pakiet.Name == "" || pakiet.Version == "" {
			continue
		}
		if pakiet.SourceName == "" {
			pakiet.SourceName = pakiet.Name
		}
		if pakiet.SourceVersion == "" {
			pakiet.SourceVersion = pakiet.Version
		}
		pakiety = append(pakiety, pakiet)
	}
	if len(pakiety) == 0 {
		return nil, "dpkg-query zwrocil pusta liste"
	}
	return pakiety, ""
}

// zainstalowaneRPM czyta baze RPM w pelnej postaci NEVRA.
func zainstalowaneRPM(ctx context.Context) ([]InstalledPackage, string) {
	format := `%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\t%{VENDOR}\n`
	result := run(ctx, 2*time.Minute, rpmPath, "-qa", "--qf", format)
	if !result.Ran || result.ExitCode != 0 {
		return nil, "rpm -qa: " + result.Reason()
	}

	var pakiety []InstalledPackage
	for _, linia := range strings.Split(result.Stdout, "\n") {
		pola := strings.Split(linia, "\t")
		if len(pola) < 7 {
			continue
		}
		pakiet := InstalledPackage{
			Name:         strings.TrimSpace(pola[0]),
			Epoch:        strings.TrimSpace(pola[1]),
			Version:      strings.TrimSpace(pola[2]),
			Release:      strings.TrimSpace(pola[3]),
			Architecture: strings.TrimSpace(pola[4]),
			SourceRPM:    strings.TrimSpace(pola[5]),
			Vendor:       strings.TrimSpace(pola[6]),
		}
		if pakiet.Name == "" || pakiet.Version == "" {
			continue
		}
		// EPOCHNUM daje "0" takze wtedy, gdy pakiet epoki nie ma; zapisujemy
		// to jako brak epoki, bo tak samo mowia o tym advisory.
		if pakiet.Epoch == "0" || pakiet.Epoch == "(none)" {
			pakiet.Epoch = ""
		}
		if pakiet.Vendor == "(none)" {
			pakiet.Vendor = ""
		}
		pakiet.SourceName, pakiet.SourceVersion = ZrodloZSourceRPM(pakiet.SourceRPM)
		pakiety = append(pakiety, pakiet)
	}
	if len(pakiety) == 0 {
		return nil, "rpm -qa zwrocil pusta liste"
	}
	return pakiety, ""
}

// ZrodloZSourceRPM wyciaga nazwe i wersje zrodla z nazwy pliku zrodlowego.
//
// Plik ma postac "nazwa-wersja-wydanie.src.rpm". Nazwa moze zawierac myslniki,
// wiec odcinamy od konca: najpierw wydanie, potem wersje.
func ZrodloZSourceRPM(sourceRPM string) (nazwa, wersja string) {
	plik := strings.TrimSuffix(strings.TrimSpace(sourceRPM), ".src.rpm")
	if plik == "" || plik == "(none)" {
		return "", ""
	}
	ostatni := strings.LastIndex(plik, "-")
	if ostatni <= 0 {
		return plik, ""
	}
	wydanie := plik[ostatni+1:]
	reszta := plik[:ostatni]
	przedostatni := strings.LastIndex(reszta, "-")
	if przedostatni <= 0 {
		return reszta, wydanie
	}
	return reszta[:przedostatni], reszta[przedostatni+1:] + "-" + wydanie
}
