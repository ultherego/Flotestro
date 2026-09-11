package network

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// Plan opisuje roznice miedzy profilem sieci zastanym a zadanym na jednym
// hoscie.
//
// "Ustaw MTU 9000 na eth1" albo "adres statyczny na eth1" znaczy na kazdym
// hoscie co innego: inny profil NetworkManagera, inne trasy i DNS, ktore
// maja zostac, jeden host juz to ma. Zgoda operatora ma dotyczyc tych
// roznic, a nie samego zamiaru - i dlatego plan powstaje na hoscie.
type Plan struct {
	Interface string `json:"interface"`
	// Connection jest profilem NetworkManagera, ktory host ma na tym
	// interfejsie. Panel nie tworzy nowych profili: brak profilu jest odmowa.
	Connection string `json:"connection,omitempty"`
	// Operation nazywa, ktora zmiana byla planowana: mtu, routes albo profile.
	Operation string `json:"operation"`
	// Action nazywa to, co by sie stalo: update albo no_change.
	Action string `json:"action"`

	Current *Profil `json:"current,omitempty"`
	Desired *Profil `json:"desired,omitempty"`
	// Changes wylicza po ludzku, co sie zmieni.
	Changes []string `json:"changes,omitempty"`

	// Refusal nazywa powod, dla ktorego zmiana nie wejdzie na ten host: brak
	// NetworkManagera, brak profilu na interfejsie, konfiguracja, ktorej host
	// nie przyjmie. Plan z odmowa jest odpowiedzia, ktora operator ma
	// zobaczyc przed zgoda.
	Refusal string `json:"refusal,omitempty"`

	PlanHash string `json:"plan_hash"`
}

// Nazwy operacji i dzialan planu.
const (
	PlanMTU    = "mtu"
	PlanTrasy  = "routes"
	PlanProfil = "profile"
	PlanDNS    = "dns"

	PlanZmienia  = "update"
	PlanBezZmian = "no_change"
)

// ZaplanujMTU liczy roznice dla zmiany MTU profilu.
func ZaplanujMTU(interfejs string, obecny Profil, mtu string) Plan {
	plan := nowyPlan(interfejs, obecny, PlanMTU)
	if _, err := ArgumentyMTU(obecny.Polaczenie, mtu); err != nil {
		return plan.zOdmowa(err.Error())
	}
	docelowy := obecny
	docelowy.MTU = mtu
	return plan.zDocelowym(docelowy)
}

// ZaplanujTrasy liczy roznice dla pelnej listy tras profilu.
func ZaplanujTrasy(interfejs string, obecny Profil, trasy []string) Plan {
	plan := nowyPlan(interfejs, obecny, PlanTrasy)
	if _, err := ArgumentyTras(obecny.Polaczenie, trasy); err != nil {
		return plan.zOdmowa(err.Error())
	}
	docelowy := obecny
	docelowy.Trasy = append([]string(nil), trasy...)
	return plan.zDocelowym(docelowy)
}

// ZaplanujProfil liczy roznice dla profilu adresowego.
//
// Trasy i MTU zostaja takie, jakie host ma: profil adresowy jest osobna
// operacja i nie moze po cichu skasowac ustawien, o ktore operator nie
// byl pytany. Dlatego sa w Desired, ale nie w Changes.
func ZaplanujProfil(interfejs string, obecny Profil, metoda string, adresy []string,
	brama string, dns []string) Plan {
	plan := nowyPlan(interfejs, obecny, PlanProfil)
	docelowy := Profil{
		Polaczenie: obecny.Polaczenie, Interfejs: obecny.Interfejs,
		Metoda: metoda, Adresy: append([]string(nil), adresy...),
		Brama: brama, DNS: append([]string(nil), dns...),
		DNSSearch: obecny.DNSSearch, IgnoreAutoDNS: obecny.IgnoreAutoDNS,
		Trasy: obecny.Trasy, MTU: obecny.MTU,
	}
	if _, err := ArgumentyProfilu(docelowy); err != nil {
		return plan.zOdmowa(err.Error())
	}
	return plan.zDocelowym(docelowy)
}

// ZaplanujDNS liczy roznice dla samego resolvera: serwerow, domen
// wyszukiwania i tego, czy serwery z DHCP sa odrzucane. Reszta profilu
// zostaje taka, jaka host ma.
func ZaplanujDNS(interfejs string, obecny Profil, serwery, domeny []string,
	pomijajAuto bool) Plan {
	plan := nowyPlan(interfejs, obecny, PlanDNS)
	if _, err := ArgumentyDNS(obecny.Polaczenie, serwery, domeny, pomijajAuto); err != nil {
		return plan.zOdmowa(err.Error())
	}
	docelowy := obecny
	docelowy.DNS = append([]string(nil), serwery...)
	docelowy.DNSSearch = append([]string(nil), domeny...)
	docelowy.IgnoreAutoDNS = pomijajAuto
	return plan.zDocelowym(docelowy)
}

// OdmowaPlanu buduje plan dla hosta, na ktorym nie ma czego porownywac:
// bez NetworkManagera albo bez profilu na interfejsie.
func OdmowaPlanu(interfejs, operacja, powod string) Plan {
	plan := Plan{Interface: interfejs, Operation: operacja}
	return plan.zOdmowa(powod)
}

// Odmow wpisuje powod odmowy poznany po policzeniu roznic i liczy odcisk
// na nowo: plan z odmowa jest inna odpowiedzia niz plan bez niej.
func (p *Plan) Odmow(powod string) {
	p.Refusal = powod
	p.PlanHash = odciskPlanu(*p)
}

func nowyPlan(interfejs string, obecny Profil, operacja string) Plan {
	zastany := obecny
	return Plan{
		Interface: interfejs, Connection: obecny.Polaczenie,
		Operation: operacja, Current: &zastany,
	}
}

func (p Plan) zOdmowa(powod string) Plan {
	p.Refusal = powod
	p.PlanHash = odciskPlanu(p)
	return p
}

func (p Plan) zDocelowym(docelowy Profil) Plan {
	p.Desired = &docelowy
	p.Changes = roznice(*p.Current, docelowy)
	p.Action = PlanZmienia
	if len(p.Changes) == 0 {
		p.Action = PlanBezZmian
	}
	p.PlanHash = odciskPlanu(p)
	return p
}

// roznice wylicza zmiany widoczne dla czlowieka.
func roznice(obecny, docelowy Profil) []string {
	var zmiany []string
	if obecny.Metoda != docelowy.Metoda {
		zmiany = append(zmiany, fmt.Sprintf("metoda z %s na %s",
			lubBrak(obecny.Metoda), lubBrak(docelowy.Metoda)))
	}
	if !tenSamZbior(obecny.Adresy, docelowy.Adresy) {
		zmiany = append(zmiany, "adresy z "+lista(obecny.Adresy)+" na "+lista(docelowy.Adresy))
	}
	if obecny.Brama != docelowy.Brama {
		zmiany = append(zmiany, "brama z "+lubBrak(obecny.Brama)+" na "+lubBrak(docelowy.Brama))
	}
	if !tenSamZbior(obecny.DNS, docelowy.DNS) {
		zmiany = append(zmiany, "DNS z "+lista(obecny.DNS)+" na "+lista(docelowy.DNS))
	}
	if !tenSamZbior(obecny.DNSSearch, docelowy.DNSSearch) {
		zmiany = append(zmiany, "domeny wyszukiwania z "+lista(obecny.DNSSearch)+
			" na "+lista(docelowy.DNSSearch))
	}
	if obecny.IgnoreAutoDNS != docelowy.IgnoreAutoDNS {
		if docelowy.IgnoreAutoDNS {
			zmiany = append(zmiany, "serwery z DHCP beda odrzucane")
		} else {
			zmiany = append(zmiany, "serwery z DHCP beda przyjmowane")
		}
	}
	if !tenSamZbior(obecny.Trasy, docelowy.Trasy) {
		zmiany = append(zmiany, "trasy z "+lista(obecny.Trasy)+" na "+lista(docelowy.Trasy))
	}
	if obecny.MTU != docelowy.MTU {
		zmiany = append(zmiany, "MTU z "+lubBrak(obecny.MTU)+" na "+lubBrak(docelowy.MTU))
	}
	return zmiany
}

// tenSamZbior porownuje listy jako zbiory: kolejnosc adresow czy tras nie
// jest decyzja operatora.
func tenSamZbior(a, b []string) bool {
	return reflect.DeepEqual(posortowane(a), posortowane(b))
}

func posortowane(lista []string) []string {
	kopia := []string{}
	for _, element := range lista {
		if element = strings.TrimSpace(element); element != "" {
			kopia = append(kopia, element)
		}
	}
	sort.Strings(kopia)
	return kopia
}

func lista(elementy []string) string {
	if len(elementy) == 0 {
		return "brak"
	}
	return strings.Join(posortowane(elementy), ",")
}

func lubBrak(wartosc string) string {
	if wartosc == "" {
		return "brak"
	}
	return wartosc
}

// odciskPlanu liczy odcisk planu poza samym odciskiem.
//
// Obejmuje stan zastany i docelowy razem: ten sam diff policzony wobec
// profilu, ktory sie w miedzyczasie zmienil, jest inna zmiana.
func odciskPlanu(plan Plan) string {
	bezOdcisku := plan
	bezOdcisku.PlanHash = ""
	zakodowany, err := json.Marshal(bezOdcisku)
	if err != nil {
		return ""
	}
	suma := sha256.Sum256(zakodowany)
	return hex.EncodeToString(suma[:])
}
