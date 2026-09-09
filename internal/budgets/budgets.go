// Package budgets odpowiada na pytanie, czy system ma pojemnosc, zeby
// uruchomic kolejna operacje.
//
// To nie jest to samo pytanie co blokada zasobu. Blokada mowi, czy dwie
// operacje sie wykluczaja na jednym hoscie; budzet mowi, czy flota, lokalizacja
// i kanal to udzwigna. Polaczenie ich w jedna liczbe daje pozorne
// bezpieczenstwo: limit pieciu hostow w kampanii nie chroni repozytorium przed
// setka rownoleglych pobran, a mutex pakietow nie mowi nic o obciazeniu
// lokalizacji.
package budgets

import (
	"fmt"
	"time"

	"github.com/ultherego/flotestro/internal/opspec"
)

// Klasa jest priorytetem, z jakim zadanie ubiega sie o pojemnosc.
//
// Kolejnosc ma znaczenie tylko przez czas awansu: operacja pilna przestaje byc
// ograniczana udzialem po chwili, kampania utrzymaniowa - po minutach. Zadna
// klasa nie omija samej pojemnosci: incydent tez nie moze uruchomic dwoch
// zmian sieci w lokalizacji, ktora dopuszcza jedna.
type Klasa string

const (
	// KlasaIncydent to reakcja na awarie: zablokowanie konta, zatrzymanie
	// uslugi. Czeka najkrocej.
	KlasaIncydent Klasa = "incident"
	// KlasaInterakcja to praca operatora na jednym hoscie.
	KlasaInterakcja Klasa = "interactive"
	// KlasaUtrzymanie to kampania zaplanowana i zatwierdzona.
	KlasaUtrzymanie Klasa = "maintenance"
	// KlasaTlo to prace wlasne panelu: przeglady, odczyty cykliczne.
	KlasaTlo Klasa = "background"
)

// WiekAwansu mowi, jak dlugo klasa czeka, zanim przestaje ja obowiazywac
// udzial.
//
// Udzial chroni male, pilne operacje przed zaglodzeniem przez duza kampanie.
// Sam udzial jednak takze potrafi zaglodzic - kampanie, ktora czeka w
// nieskonczonosc, bo ktos ciagle zglasza nowe zadania. Awans po czasie zamyka
// to okno: pojemnosci nadal trzeba dotrzymac, ale udzial przestaje wiazac.
func (k Klasa) WiekAwansu() time.Duration {
	switch k {
	case KlasaIncydent:
		return 0
	case KlasaInterakcja:
		return 15 * time.Second
	case KlasaUtrzymanie:
		return 2 * time.Minute
	default:
		return 5 * time.Minute
	}
}

// Znana mowi, czy klasa jest jedna ze znanych.
func Znana(k Klasa) bool {
	switch k {
	case KlasaIncydent, KlasaInterakcja, KlasaUtrzymanie, KlasaTlo:
		return true
	default:
		return false
	}
}

// Potrzeba jest jednym wymaganiem pojemnosci.
//
// Waga jest kosztem: jedno zadanie to zwykle jeden token, ale operacja, ktora
// sciaga gigabajty, ma kosztowac wiecej niz odczyt stanu.
type Potrzeba struct {
	Klucz string
	Waga  int
}

// Powody odmowy. Kazda odmowa musi dac sie odroznic: brak pojemnosci calej
// floty i przekroczony udzial jednej kampanii to dwie rozne sytuacje i dwie
// rozne odpowiedzi dla operatora.
const (
	// PowodPojemnosc oznacza budzet zajety w calosci.
	PowodPojemnosc = "capacity"
	// PowodUdzial oznacza pojemnosc wolna, ale nie dla tego roszczacego:
	// jedna kampania nie bierze wszystkich wolnych tokenow.
	PowodUdzial = "fair_share"
)

// Odmowa opisuje budzet, ktory nie mial miejsca.
//
// Cisza nie jest odpowiedzia: host czekajacy na tokeny ma pokazac, na ktory
// budzet czeka, ile jest zajete i jak dlugo trwa oczekiwanie.
type Odmowa struct {
	Klucz     string
	Powod     string
	Zajete    int
	Pojemnosc int
	// Udzial jest porcja przypadajaca na jednego roszczacego, a Trzymane -
	// tym, co ten roszczacy juz ma. Bez obu liczb odmowa "udzial wyczerpany"
	// nie mowi, czy zabraklo o jeden token, czy o sto.
	Udzial   int
	Trzymane int
	Czeka    time.Duration
}

// Opis nazywa przeszkode zdaniem, ktore da sie pokazac operatorowi.
func (o Odmowa) Opis() string {
	if o.Klucz == "" {
		return ""
	}
	if o.Powod == PowodUdzial {
		return fmt.Sprintf("budzet %s: udzial %d z %d tokenow, trzymamy %d, czekamy %s",
			o.Klucz, o.Udzial, o.Pojemnosc, o.Trzymane, o.Czeka.Round(time.Second))
	}
	return fmt.Sprintf("budzet %s: zajete %d z %d, czekamy %s",
		o.Klucz, o.Zajete, o.Pojemnosc, o.Czeka.Round(time.Second))
}

// Pusta mowi, czy odmowy nie bylo.
func (o Odmowa) Pusta() bool { return o.Klucz == "" }

// Klucze budzetow globalnych. Odczyt i mutacja maja osobne pojemnosci: sto
// odczytow stanu nie jest tym samym obciazeniem co sto transakcji pakietowych.
const (
	KluczGlobalneMutacje = "global:mutations"
	KluczGlobalneOdczyty = "global:reads"
)

// RodzinaLokalizacji nazywa rodzine zasobow, ktora operacja obciaza
// w lokalizacji.
//
// Podstawa jest klasa blokady z rejestru operacji: to ona nazywa zasob, ktorego
// operacja uzywa na wylacznosc. Restart nie ma klasy blokady, bo zabiera caly
// host - a mimo to jest tym, czego w jednej lokalizacji nie chcemy robic
// dziesiec razy naraz. Pusta wartosc znaczy operacje bez budzetu lokalizacji,
// a nie budzet zerowy: nadal obowiazuje budzet globalny.
func RodzinaLokalizacji(action opspec.ActionType) string {
	switch action {
	case opspec.ActionSystemReboot, opspec.ActionSystemShutdown:
		return "reboot"
	}
	return action.LockClass()
}

// KluczLokalizacji sklada klucz budzetu lokalizacji.
func KluczLokalizacji(site, rodzina string) string {
	if site == "" || rodzina == "" {
		return ""
	}
	return "site:" + site + ":" + rodzina
}

// Wzorzec zamienia klucz scisly na wzorzec polityki domyslnej.
//
// Lokalizacji jest tyle, ile ich zalozono, i nikt nie opisuje kazdej z osobna.
// Wzorzec pozwala miec polityke dla wszystkich, nie odbierajac mozliwosci
// opisania jednej inaczej.
func Wzorzec(klucz string) string {
	czesci := rozbij(klucz)
	if len(czesci) != 3 {
		return ""
	}
	return czesci[0] + ":*:" + czesci[2]
}

func rozbij(klucz string) []string {
	czesci := make([]string, 0, 3)
	poczatek := 0
	for i := 0; i < len(klucz); i++ {
		if klucz[i] == ':' {
			czesci = append(czesci, klucz[poczatek:i])
			poczatek = i + 1
		}
	}
	return append(czesci, klucz[poczatek:])
}

// Potrzeby wylicza budzety, ktore operacja obciaza na jednym hoscie.
//
// Czego tu nie ma: budzetu bramy, domeny awarii i backendu. Panel nie zna
// jeszcze topologii, ktora by je definiowala - i lepiej, zeby ich nie bylo
// widac, niz zeby udawaly limit liczony z niczego. Dolozenie ich to dolozenie
// pozycji do tej listy.
func Potrzeby(action opspec.ActionType, site string) []Potrzeba {
	globalny := KluczGlobalneOdczyty
	if action.Mutating() {
		globalny = KluczGlobalneMutacje
	}
	potrzeby := []Potrzeba{{Klucz: globalny, Waga: 1}}

	// Budzet lokalizacji dotyczy zmian. Odczyty obciazaja host i lacze, a te
	// maja wlasne limity po stronie agenta.
	if action.Mutating() {
		if klucz := KluczLokalizacji(site, RodzinaLokalizacji(action)); klucz != "" {
			potrzeby = append(potrzeby, Potrzeba{Klucz: klucz, Waga: 1})
		}
	}
	return potrzeby
}
