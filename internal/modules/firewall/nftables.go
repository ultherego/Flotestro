package firewall

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strconv"
	"strings"
)

// SciezkaNft wskazuje narzedzie nftables. Sciezka jest stala, a nie szukana
// w PATH: helper uruchamia wylacznie znane binaria.
const SciezkaNft = "/usr/sbin/nft"

var (
	naglowekTabeli = regexp.MustCompile(`^table\s+(\S+)\s+(\S+)\s*\{(?:\s*#\s*handle\s+(\d+))?`)
	naglowekLanc   = regexp.MustCompile(`^chain\s+(\S+)\s*\{(?:\s*#\s*handle\s+(\d+))?`)
	zaczepienie    = regexp.MustCompile(`^type\s+(\S+)\s+hook\s+(\S+)\s+priority\s+([^;]+);(?:\s*policy\s+(\S+);)?`)
	uchwytReguly   = regexp.MustCompile(`\s*#\s*handle\s+(\d+)\s*$`)
	licznikiReguly = regexp.MustCompile(`counter packets (\d+) bytes (\d+)`)
	komentarzRegul = regexp.MustCompile(`comment "([^"]*)"`)
	// Ostrzezenie nft konczy sie przecinkiem i rada "do not touch", wiec
	// nazwa wlasciciela urywa sie na pierwszym znaku interpunkcyjnym.
	ostrzezenie = regexp.MustCompile(`^#\s*Warning:\s*table\s+(\S+)\s+(\S+)\s+is managed by ([A-Za-z0-9_.-]+)`)
)

// ParsujRuleset czyta wyjscie "nft -a list ruleset".
//
// Czytamy postac tekstowa, a nie JSON, bo tresc reguly ma byc dokladnie ta,
// ktora operator zna z wiersza polecen. Wlasne skladanie tekstu z drzewa
// wyrazen rozjechaloby sie z tym, co host naprawde ma - a przy zaporze to
// jest roznica miedzy "przepuszcza" a "odrzuca".
func ParsujRuleset(wyjscie string) Snapshot {
	snapshot := Snapshot{Adapter: AdapterNftables}
	wlasciciele := map[string]string{}

	var tabela *Table
	var lancuch *Chain

	for _, surowa := range strings.Split(wyjscie, "\n") {
		linia := strings.TrimSpace(surowa)
		if linia == "" {
			continue
		}

		// nft sam ostrzega, ze tablica nalezy do innego programu.
		if pola := ostrzezenie.FindStringSubmatch(linia); pola != nil {
			wlasciciele[pola[1]+" "+pola[2]] = pola[3]
			continue
		}
		if strings.HasPrefix(linia, "#") {
			continue
		}
		if linia == "}" {
			if lancuch != nil {
				lancuch = nil
			} else {
				tabela = nil
			}
			continue
		}

		if pola := naglowekTabeli.FindStringSubmatch(linia); pola != nil {
			snapshot.Tables = append(snapshot.Tables, Table{
				Family: pola[1],
				Name:   pola[2],
				Handle: liczba(pola[3]),
			})
			tabela = &snapshot.Tables[len(snapshot.Tables)-1]
			continue
		}
		if tabela == nil {
			continue
		}

		if pola := naglowekLanc.FindStringSubmatch(linia); pola != nil {
			snapshot.Chains = append(snapshot.Chains, Chain{
				Family: tabela.Family,
				Table:  tabela.Name,
				Name:   pola[1],
				Handle: liczba(pola[2]),
			})
			lancuch = &snapshot.Chains[len(snapshot.Chains)-1]
			continue
		}
		if lancuch == nil {
			continue
		}

		if pola := zaczepienie.FindStringSubmatch(linia); pola != nil {
			lancuch.Type = pola[1]
			lancuch.Hook = pola[2]
			lancuch.Priority = strings.TrimSpace(pola[3])
			// Polityka dotyczy wylacznie lancuchow bazowych; jej brak zostaje
			// brakiem, bo "accept" wpisane na wszelki wypadek bylby falszem.
			lancuch.Policy = pola[4]
			continue
		}

		snapshot.Rules = append(snapshot.Rules, regulaZLinii(linia, *lancuch))
	}

	oznaczPochodzenie(&snapshot, wlasciciele)
	snapshot.Hash = Odcisk(wyjscie)
	return snapshot
}

// regulaZLinii sklada regule z jednego wiersza wyjscia nft.
func regulaZLinii(linia string, lancuch Chain) Rule {
	regula := Rule{
		Family: lancuch.Family,
		Table:  lancuch.Table,
		Chain:  lancuch.Name,
		Text:   linia,
	}
	if pola := uchwytReguly.FindStringSubmatch(linia); pola != nil {
		regula.Handle = liczba(pola[1])
		regula.Text = strings.TrimSpace(uchwytReguly.ReplaceAllString(linia, ""))
	}
	if pola := licznikiReguly.FindStringSubmatch(linia); pola != nil {
		pakiety := uliczba(pola[1])
		bajty := uliczba(pola[2])
		regula.Packets = &pakiety
		regula.Bytes = &bajty
	}
	if pola := komentarzRegul.FindStringSubmatch(linia); pola != nil {
		regula.Comment = pola[1]
	}
	return regula
}

// oznaczPochodzenie rozdziela reguly panelu od cudzych.
//
// Tablica nalezaca do dockera albo firewalld jest przepisywana bez udzialu
// panelu, wiec regula w niej nie jest ani nasza, ani trwala - i operator ma
// to widziec, zanim zacznie ja poprawiac.
func oznaczPochodzenie(snapshot *Snapshot, wlasciciele map[string]string) {
	pochodzenie := func(family, name string) (string, string) {
		if wlasciciel, obcy := wlasciciele[family+" "+name]; obcy {
			return SourceForeign, wlasciciel
		}
		if family == RodzinaFlotestro && name == TabelaFlotestro {
			return SourceManaged, ""
		}
		if name == "firewalld" || strings.HasPrefix(name, "docker") {
			return SourceForeign, name
		}
		return SourceManual, ""
	}

	for i := range snapshot.Tables {
		zrodlo, wlasciciel := pochodzenie(snapshot.Tables[i].Family, snapshot.Tables[i].Name)
		snapshot.Tables[i].Source = zrodlo
		snapshot.Tables[i].Owner = wlasciciel
	}
	for i := range snapshot.Chains {
		zrodlo, _ := pochodzenie(snapshot.Chains[i].Family, snapshot.Chains[i].Table)
		snapshot.Chains[i].Source = zrodlo
	}
	for i := range snapshot.Rules {
		zrodlo, _ := pochodzenie(snapshot.Rules[i].Family, snapshot.Rules[i].Table)
		snapshot.Rules[i].Source = zrodlo
	}
}

// Odcisk liczy skrot zestawu regul.
//
// Zmiana zlecona wobec innego zestawu nie jest ta sama zmiana, ktora operator
// ogladal: liczniki pomijamy, bo rosna same i kazdy odczyt dawalby inny
// odcisk tego samego zestawu.
func Odcisk(ruleset string) string {
	bezLicznikow := licznikiReguly.ReplaceAllString(ruleset, "counter")
	suma := sha256.Sum256([]byte(bezLicznikow))
	return hex.EncodeToString(suma[:12])
}

func liczba(wartosc string) int {
	numer, err := strconv.Atoi(wartosc)
	if err != nil {
		return 0
	}
	return numer
}

func uliczba(wartosc string) uint64 {
	numer, err := strconv.ParseUint(wartosc, 10, 64)
	if err != nil {
		return 0
	}
	return numer
}
