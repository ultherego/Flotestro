package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
)

// MountPlan opisuje roznice miedzy montowaniem zastanym a zadanym na jednym
// hoscie.
//
// Zamowienie "zamontuj /dev/sdb w /data" znaczy na kazdym hoscie co innego:
// /dev/sdb jest inna partycja z innym UUID, a /data bywa juz zamontowane,
// zapisane w fstab albo puste. Plan rozwiazuje zrodlo do UUID filesystemu,
// ktory ten host naprawde ma, i to UUID jedzie w zmianie. Dzieki temu dysk,
// ktory po restarcie dostal inna sciezke, nie zostanie zamontowany w cudze
// miejsce - mount po UUID znajdzie ten wlasciwy albo nie znajdzie zadnego.
type MountPlan struct {
	Target string `json:"target"`
	// Action nazywa to, co by sie stalo: create, update, no_change, remove
	// albo remove_absent.
	Action string `json:"action"`

	// Stan zastany. Brak Current oznacza cel, ktorego host nie zna ani jako
	// montowania, ani jako wpisu w fstab.
	Current *Mount `json:"current,omitempty"`

	// RequestedSource jest zrodlem z zamowienia; ResolvedSource - tym samym
	// zrodlem po rozwiazaniu do UUID na tym hoscie. To drugie jedzie
	// w zmianie. Jesli zamowienie juz bylo po UUID, oba sa rowne.
	RequestedSource string `json:"requested_source,omitempty"`
	ResolvedSource  string `json:"resolved_source,omitempty"`
	// Device opisuje urzadzenie, ktore host ma pod zrodlem.
	Device *Device `json:"device,omitempty"`

	DesiredFSType  string `json:"desired_fs_type,omitempty"`
	DesiredOptions string `json:"desired_options,omitempty"`
	DesiredPersist bool   `json:"desired_persist,omitempty"`

	// Changes wylicza po ludzku, co sie zmieni.
	Changes []string `json:"changes,omitempty"`
	// Refusal nazywa powod, dla ktorego zmiana nie wejdzie na ten host:
	// zrodla nie ma, filesystem jest innego typu niz zadany, cel jest juz
	// zajety przez inne urzadzenie. Plan z odmowa jest odpowiedzia, ktora
	// operator ma zobaczyc przed zgoda.
	Refusal string `json:"refusal,omitempty"`

	PlanHash string `json:"plan_hash"`
}

// Nazwy dzialan planu.
const (
	PlanTworzy      = "create"
	PlanZmienia     = "update"
	PlanBezZmian    = "no_change"
	PlanUsuwa       = "remove"
	PlanJuzUsuniety = "remove_absent"
)

// ZaplanujMontowanie liczy roznice dla zapewnienia montowania.
func ZaplanujMontowanie(stan Snapshot, source, target, fsType, options string,
	persist bool) MountPlan {
	plan := MountPlan{
		Target: target, RequestedSource: source, DesiredFSType: fsType,
		DesiredOptions: options, DesiredPersist: persist,
	}

	urzadzenie := stan.UrzadzenieZrodla(source)
	if urzadzenie == nil {
		plan.Refusal = "host nie widzi zrodla " + source
		plan.PlanHash = odciskPlanuMontowania(plan)
		return plan
	}
	kopia := *urzadzenie
	plan.Device = &kopia
	switch {
	case urzadzenie.UUID == "":
		// Bez UUID nie ma czego zwiazac ze zmiana: sciezka /dev/sdX po
		// restarcie wskaze co innego, a zamowienie po sciezce montowaloby
		// wtedy cudzy dysk.
		plan.Refusal = "filesystem na " + source + " nie ma UUID; nie da sie go zwiazac ze zmiana"
	case fsType != "" && urzadzenie.FSType != "" && urzadzenie.FSType != fsType:
		plan.Refusal = "zrodlo ma filesystem " + urzadzenie.FSType + ", a zamowienie zada " + fsType
	}
	if plan.Refusal != "" {
		plan.PlanHash = odciskPlanuMontowania(plan)
		return plan
	}
	plan.ResolvedSource = "UUID=" + urzadzenie.UUID

	obecne := stan.Montowanie(target)
	switch {
	case obecne == nil:
		plan.Action = PlanTworzy
		plan.Changes = []string{"montowanie powstanie"}
		if persist {
			plan.Changes = append(plan.Changes, "wpis w fstab powstanie")
		}
	case !toSamoZrodlo(obecne.Source, urzadzenie):
		// Cel jest juz zajety przez inny filesystem. Zamontowanie na nim
		// drugiego przykryloby pierwszy - to nie jest zmiana, ktora wolno
		// zrobic po cichu w kampanii.
		zastane := *obecne
		plan.Current = &zastane
		plan.Refusal = "cel " + target + " jest zajety przez " + obecne.Source
	default:
		zastane := *obecne
		plan.Current = &zastane
		plan.Changes = roznicemontowania(*obecne, options, persist)
		plan.Action = PlanZmienia
		if len(plan.Changes) == 0 {
			plan.Action = PlanBezZmian
		}
	}
	plan.PlanHash = odciskPlanuMontowania(plan)
	return plan
}

// ZaplanujOdmontowanie liczy roznice dla usuniecia montowania.
func ZaplanujOdmontowanie(stan Snapshot, target string) MountPlan {
	plan := MountPlan{Target: target}
	obecne := stan.Montowanie(target)
	if obecne == nil {
		plan.Action = PlanJuzUsuniety
	} else {
		zastane := *obecne
		plan.Current = &zastane
		plan.Action = PlanUsuwa
		if obecne.Mounted {
			plan.Changes = append(plan.Changes, "filesystem zostanie odmontowany")
		}
		if obecne.InFstab {
			plan.Changes = append(plan.Changes, "wpis w fstab zniknie")
		}
	}
	plan.PlanHash = odciskPlanuMontowania(plan)
	return plan
}

// Odmow wpisuje do planu powod odmowy poznany juz po policzeniu roznic -
// na przyklad procesy trzymajace filesystem - i liczy odcisk na nowo, bo
// plan z odmowa jest inna odpowiedzia niz plan bez niej.
func (p *MountPlan) Odmow(powod string) {
	p.Refusal = powod
	p.PlanHash = odciskPlanuMontowania(*p)
}

// UrzadzenieZrodla rozwiazuje zrodlo zamowienia do urzadzenia hosta.
//
// Zrodlo moze byc sciezka, UUID= albo LABEL=. Kazde z nich wskazuje
// urzadzenie inaczej, a plan potrzebuje jednego: tego, ktore host ma.
func (s Snapshot) UrzadzenieZrodla(source string) *Device {
	switch {
	case strings.HasPrefix(source, "UUID="):
		uuid := strings.TrimPrefix(source, "UUID=")
		for i := range s.Devices {
			if s.Devices[i].UUID == uuid {
				return &s.Devices[i]
			}
		}
	case strings.HasPrefix(source, "LABEL="):
		label := strings.TrimPrefix(source, "LABEL=")
		for i := range s.Devices {
			if s.Devices[i].Label != "" && s.Devices[i].Label == label {
				return &s.Devices[i]
			}
		}
	default:
		return s.Urzadzenie(source)
	}
	return nil
}

// toSamoZrodlo mowi, czy montowanie zastane wskazuje to samo urzadzenie.
func toSamoZrodlo(zastane string, urzadzenie *Device) bool {
	switch {
	case zastane == urzadzenie.Path:
		return true
	case strings.HasPrefix(zastane, "UUID="):
		return strings.TrimPrefix(zastane, "UUID=") == urzadzenie.UUID
	case strings.HasPrefix(zastane, "LABEL="):
		return urzadzenie.Label != "" && strings.TrimPrefix(zastane, "LABEL=") == urzadzenie.Label
	}
	return false
}

// roznicemontowania wylicza zmiany widoczne dla czlowieka.
func roznicemontowania(obecne Mount, options string, persist bool) []string {
	var zmiany []string
	if !obecne.Mounted {
		zmiany = append(zmiany, "filesystem zostanie zamontowany")
	}
	if persist && !obecne.InFstab {
		zmiany = append(zmiany, "wpis w fstab powstanie")
	}
	if persist && obecne.InFstab && !teSameOpcje(obecne.FstabOptions, options) {
		zmiany = append(zmiany, "opcje w fstab z "+lubDomyslne(obecne.FstabOptions)+
			" na "+lubDomyslne(options))
	}
	sort.Strings(zmiany)
	return zmiany
}

// teSameOpcje porownuje opcje montowania jako zbior: kolejnosc nie jest
// decyzja operatora.
func teSameOpcje(a, b string) bool {
	return strings.Join(zbiorOpcji(a), ",") == strings.Join(zbiorOpcji(b), ",")
}

func zbiorOpcji(opcje string) []string {
	czesci := []string{}
	for _, czesc := range strings.Split(opcje, ",") {
		czesc = strings.TrimSpace(czesc)
		if czesc != "" && czesc != "defaults" {
			czesci = append(czesci, czesc)
		}
	}
	sort.Strings(czesci)
	return czesci
}

func lubDomyslne(opcje string) string {
	if strings.TrimSpace(opcje) == "" {
		return "defaults"
	}
	return opcje
}

// odciskPlanuMontowania liczy odcisk planu poza samym odciskiem.
func odciskPlanuMontowania(plan MountPlan) string {
	bezOdcisku := plan
	bezOdcisku.PlanHash = ""
	zakodowany, err := json.Marshal(bezOdcisku)
	if err != nil {
		return ""
	}
	suma := sha256.Sum256(zakodowany)
	return hex.EncodeToString(suma[:])
}
