package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// DevicePlan opisuje, co sprawdzenie, rozszerzenie filesystemu albo
// wolumenu zrobi na jednym hoscie.
//
// "Rozszerz /dev/vg0/dane o 10G" na jednym hoscie ma pokrycie w wolnym
// miejscu grupy, na drugim nie ma; "sprawdz /dev/sdb1" na jednym jest
// odmontowany, na drugim trzyma dane produkcyjne. Plan mowi to przed zgoda,
// a nie na polowie floty.
type DevicePlan struct {
	// Operation nazywa, co planowano: check, resize albo lvm_extend.
	Operation string `json:"operation"`
	Device    string `json:"device"`
	// Action nazywa to, co by sie stalo: run (operacja sie wykona) albo
	// no_change, gdy nie ma czego robic.
	Action string `json:"action"`

	// Stan zastany: urzadzenie, ktore host ma pod sciezka, i to, czy jest
	// zamontowane.
	Found      bool     `json:"found"`
	FSType     string   `json:"fs_type,omitempty"`
	UUID       string   `json:"uuid,omitempty"`
	SizeBytes  uint64   `json:"size_bytes,omitempty"`
	Mountpoint string   `json:"mountpoint,omitempty"`
	Group      string   `json:"group,omitempty"`
	FreeBytes  uint64   `json:"group_free_bytes,omitempty"`
	Size       string   `json:"size,omitempty"`
	Changes    []string `json:"changes,omitempty"`

	Refusal  string `json:"refusal,omitempty"`
	PlanHash string `json:"plan_hash"`
}

// Nazwy operacji i dzialan planu urzadzenia.
const (
	PlanSprawdzenie    = "check"
	PlanRozszerzenieFS = "resize"
	PlanRozszerzenieLV = "lvm_extend"

	PlanWykona = "run"
)

// ZaplanujSprawdzenie liczy plan fsck.
func ZaplanujSprawdzenie(stan Snapshot, device string, naprawa bool) DevicePlan {
	plan := DevicePlan{Operation: PlanSprawdzenie, Device: device}
	if err := WalidujZrodlo(device); err != nil {
		return plan.zOdmowa(err.Error())
	}
	if stan.UnavailableReason != "" {
		return plan.zOdmowa(stan.UnavailableReason)
	}
	urzadzenie := stan.Urzadzenie(device)
	if urzadzenie == nil {
		return plan.zOdmowa("host nie widzi urzadzenia " + device)
	}
	plan.opisz(urzadzenie)
	if urzadzenie.FSType == "" {
		return plan.zOdmowa("na " + device + " nie ma filesystemu do sprawdzenia")
	}
	// fsck na zamontowanym filesystemie potrafi go uszkodzic: to nie jest
	// ostrzezenie, tylko odmowa - i lepiej w planie niz przy wykonaniu.
	if plan.Mountpoint != "" {
		return plan.zOdmowa("filesystem jest zamontowany w " + plan.Mountpoint +
			"; sprawdzenie wymaga odmontowania")
	}
	plan.Action = PlanWykona
	tryb := "bez naprawy (fsck -n)"
	if naprawa {
		tryb = "z naprawa (fsck -y)"
	}
	plan.Changes = []string{"filesystem " + urzadzenie.FSType + " na " + device +
		" zostanie sprawdzony " + tryb}
	plan.PlanHash = odciskPlanuUrzadzenia(plan)
	return plan
}

// ZaplanujRozszerzenieFS liczy plan rozszerzenia filesystemu do rozmiaru
// urzadzenia.
func ZaplanujRozszerzenieFS(stan Snapshot, device string) DevicePlan {
	plan := DevicePlan{Operation: PlanRozszerzenieFS, Device: device}
	if err := WalidujZrodlo(device); err != nil {
		return plan.zOdmowa(err.Error())
	}
	if stan.UnavailableReason != "" {
		return plan.zOdmowa(stan.UnavailableReason)
	}
	urzadzenie := stan.Urzadzenie(device)
	if urzadzenie == nil {
		return plan.zOdmowa("host nie widzi urzadzenia " + device)
	}
	plan.opisz(urzadzenie)
	argumenty, err := ArgumentyRozszerzeniaFS(device, urzadzenie.FSType, plan.Mountpoint)
	if err != nil {
		return plan.zOdmowa(err.Error())
	}
	plan.Action = PlanWykona
	plan.Changes = []string{"filesystem " + urzadzenie.FSType + " na " + device +
		" zostanie rozszerzony do rozmiaru urzadzenia (" + strings.Join(argumenty, " ") + ")"}
	plan.PlanHash = odciskPlanuUrzadzenia(plan)
	return plan
}

// ZaplanujRozszerzenieLV liczy plan rozszerzenia wolumenu logicznego.
func ZaplanujRozszerzenieLV(stan Snapshot, device, size string) DevicePlan {
	plan := DevicePlan{Operation: PlanRozszerzenieLV, Device: device, Size: size}
	if _, err := ArgumentyRozszerzeniaLV(device, size, true); err != nil {
		return plan.zOdmowa(err.Error())
	}
	if stan.LVMUnavailableReason != "" {
		return plan.zOdmowa(stan.LVMUnavailableReason)
	}
	var wolumen *LogicalVolume
	for i := range stan.Volumes {
		if PasujeWolumen(stan.Volumes[i], device) {
			wolumen = &stan.Volumes[i]
			break
		}
	}
	if wolumen == nil {
		return plan.zOdmowa("host nie ma wolumenu logicznego " + device)
	}
	plan.Found = true
	plan.Group = wolumen.Group
	plan.SizeBytes = wolumen.SizeBytes
	if urzadzenie := stan.Urzadzenie(wolumen.Path); urzadzenie != nil {
		plan.opisz(urzadzenie)
	}
	for _, grupa := range stan.Groups {
		if grupa.Name == wolumen.Group {
			plan.FreeBytes = grupa.FreeBytes
		}
	}
	// Grupa bez wolnego miejsca nie powiekszy zadnego wolumenu; to jest
	// najczestsza roznica miedzy hostami i ma stanac w planie.
	if plan.FreeBytes == 0 {
		return plan.zOdmowa("grupa " + wolumen.Group + " nie ma wolnego miejsca; " +
			"wolumen nie da sie rozszerzyc bez dolozenia dysku")
	}
	plan.Action = PlanWykona
	plan.Changes = []string{fmt.Sprintf("wolumen %s zostanie rozszerzony o %s z grupy %s (wolne %d MiB)",
		device, size, wolumen.Group, plan.FreeBytes>>20)}
	if plan.FSType != "" {
		plan.Changes = append(plan.Changes, "filesystem "+plan.FSType+" zostanie rozszerzony razem z wolumenem")
	}
	plan.PlanHash = odciskPlanuUrzadzenia(plan)
	return plan
}

// Odmow wpisuje powod odmowy i liczy odcisk na nowo.
func (p *DevicePlan) Odmow(powod string) {
	p.Refusal = powod
	p.PlanHash = odciskPlanuUrzadzenia(*p)
}

func (p DevicePlan) zOdmowa(powod string) DevicePlan {
	p.Refusal = powod
	p.PlanHash = odciskPlanuUrzadzenia(p)
	return p
}

func (p *DevicePlan) opisz(urzadzenie *Device) {
	p.Found = true
	p.FSType = urzadzenie.FSType
	p.UUID = urzadzenie.UUID
	if p.SizeBytes == 0 {
		p.SizeBytes = urzadzenie.SizeBytes
	}
	if len(urzadzenie.Mountpoints) > 0 {
		p.Mountpoint = urzadzenie.Mountpoints[0]
	}
}

// odciskPlanuUrzadzenia liczy odcisk planu poza samym odciskiem.
func odciskPlanuUrzadzenia(plan DevicePlan) string {
	bezOdcisku := plan
	bezOdcisku.PlanHash = ""
	zakodowany, err := json.Marshal(bezOdcisku)
	if err != nil {
		return ""
	}
	suma := sha256.Sum256(zakodowany)
	return hex.EncodeToString(suma[:])
}
