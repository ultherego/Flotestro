package storage

import (
	"regexp"
	"strings"
)

// ZnacznikPanelu oznacza wpisy fstab zalozone przez panel. Wpis zastany
// nalezy do administratora hosta i panel go nie przepisuje.
const ZnacznikPanelu = "# flotestro"

// systemowePunkty wylicza montowania jadra, ktore nie sa przestrzenia
// dyskowa hosta. Pokazywanie ich zaslanialoby obraz: na zwyklym hoscie jest
// ich kilkadziesiat, a operator pyta o dyski.
var systemoweTypy = map[string]bool{
	"sysfs": true, "proc": true, "devtmpfs": true, "devpts": true, "tmpfs": true,
	"securityfs": true, "cgroup": true, "cgroup2": true, "pstore": true,
	"efivarfs": true, "bpf": true, "autofs": true, "hugetlbfs": true,
	"mqueue": true, "debugfs": true, "tracefs": true, "fusectl": true,
	"configfs": true, "ramfs": true, "binfmt_misc": true, "rpc_pipefs": true,
	"nsfs": true, "squashfs": true, "overlay": true,
}

// ParsujMountinfo czyta /proc/self/mountinfo.
//
// Czytamy mountinfo, a nie /etc/mtab: mtab bywa dowiazaniem do mountinfo,
// ale na czesci systemow jest zwyklym plikiem, ktory rozjezdza sie ze stanem
// jadra. Pytanie "co jest zamontowane teraz" ma tylko jedna wiarygodna
// odpowiedz i jest nia jadro.
func ParsujMountinfo(tresc string) []Mount {
	var montowania []Mount
	for _, linia := range strings.Split(tresc, "\n") {
		pola := strings.Fields(linia)
		if len(pola) < 10 {
			continue
		}
		// Format: id rodzic major:minor korzen cel opcje [pola opcjonalne] - typ zrodlo opcje
		separator := -1
		for i, pole := range pola {
			if pole == "-" {
				separator = i
				break
			}
		}
		if separator < 0 || separator+2 >= len(pola) {
			continue
		}
		montowanie := Mount{
			Target:  odkoduj(pola[4]),
			Options: pola[5],
			FSType:  pola[separator+1],
			Source:  odkoduj(pola[separator+2]),
			Mounted: true,
		}
		if systemoweTypy[montowanie.FSType] {
			continue
		}
		montowania = append(montowania, montowanie)
	}
	return montowania
}

// odkoduj zamienia sekwencje osemkowe, ktorymi jadro zapisuje znaki
// specjalne w sciezkach. Sciezka ze spacja bez tego rozpadlaby sie na dwa
// pola przy pierwszym podziale.
var sekwencja = regexp.MustCompile(`\\([0-7]{3})`)

func odkoduj(sciezka string) string {
	return sekwencja.ReplaceAllStringFunc(sciezka, func(dopasowanie string) string {
		var wartosc int
		for _, cyfra := range dopasowanie[1:] {
			wartosc = wartosc*8 + int(cyfra-'0')
		}
		return string(rune(wartosc))
	})
}

// WpisFstab to jeden wiersz /etc/fstab.
type WpisFstab struct {
	Source  string
	Target  string
	FSType  string
	Options string
	Dump    string
	Pass    string
	// Managed oznacza wpis zalozony przez panel.
	Managed bool
	Line    int
}

// ParsujFstab czyta /etc/fstab.
func ParsujFstab(tresc string) []WpisFstab {
	var wpisy []WpisFstab
	zarzadzany := false
	numer := 0
	for _, linia := range strings.Split(tresc, "\n") {
		numer++
		przyciety := strings.TrimSpace(linia)
		if przyciety == "" {
			zarzadzany = false
			continue
		}
		if strings.HasPrefix(przyciety, "#") {
			// Znacznik panelu stoi nad wpisem, ktory panel zalozyl.
			zarzadzany = strings.HasPrefix(przyciety, ZnacznikPanelu)
			continue
		}
		pola := strings.Fields(przyciety)
		if len(pola) < 3 {
			zarzadzany = false
			continue
		}
		// fstab zapisuje znaki specjalne tak samo jak jadro w mountinfo:
		// osemkowo. Bez odkodowania sciezka ze spacja nigdy nie dopasowalaby
		// sie do montowania, ktore ja realizuje.
		wpis := WpisFstab{
			Source: odkoduj(pola[0]), Target: odkoduj(pola[1]), FSType: pola[2],
			Managed: zarzadzany, Line: numer,
		}
		if len(pola) > 3 {
			wpis.Options = pola[3]
		}
		if len(pola) > 4 {
			wpis.Dump = pola[4]
		}
		if len(pola) > 5 {
			wpis.Pass = pola[5]
		}
		wpisy = append(wpisy, wpis)
		zarzadzany = false
	}
	return wpisy
}

// PolaczMontowania laczy stan jadra z trescia fstab.
//
// Cztery kombinacje znacza cztery rozne rzeczy i wszystkie sa dla operatora
// wazne: wpis zamontowany zgodnie z fstab, wpis w fstab niezamontowany
// (host po restarcie go podniesie albo i nie), montowanie bez wpisu (zniknie
// po restarcie) oraz montowanie o innych opcjach niz zapisane.
func PolaczMontowania(zJadra []Mount, zFstab []WpisFstab) []Mount {
	wynik := make([]Mount, 0, len(zJadra)+len(zFstab))
	uzyte := map[string]bool{}

	for _, montowanie := range zJadra {
		for _, wpis := range zFstab {
			if wpis.Target != montowanie.Target {
				continue
			}
			montowanie.InFstab = true
			montowanie.FstabOptions = wpis.Options
			montowanie.Managed = wpis.Managed
			uzyte[wpis.Target] = true
			break
		}
		wynik = append(wynik, montowanie)
	}

	for _, wpis := range zFstab {
		if uzyte[wpis.Target] || wpis.Target == "none" || wpis.Target == "swap" {
			continue
		}
		// Wpis, ktorego nikt nie zamontowal. Montowanie na zadanie (noauto)
		// jest tu normalne, ale wpis obowiazkowy oznacza host, ktory po
		// restarcie moze nie wstac tak, jak stoi teraz.
		wynik = append(wynik, Mount{
			Target: wpis.Target, Source: wpis.Source, FSType: wpis.FSType,
			FstabOptions: wpis.Options, InFstab: true, Managed: wpis.Managed,
		})
	}
	return wynik
}
