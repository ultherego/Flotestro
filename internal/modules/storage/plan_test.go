package storage

import (
	"strings"
	"testing"
)

func migawkaZDyskiem(uuid string, montowania ...Mount) Snapshot {
	return Snapshot{
		Devices: []Device{
			{Name: "sdb", Path: "/dev/sdb", Type: "disk", FSType: "ext4", UUID: uuid, SizeBytes: 2 << 30},
		},
		Mounts: montowania,
	}
}

// TestPlanRozwiazujeZrodloDoUUIDHosta pilnuje sedna planu per host: ta sama
// sciezka na dwoch hostach to dwa rozne filesystemy, a w zmianie ma jechac
// ten, ktory host naprawde ma.
func TestPlanRozwiazujeZrodloDoUUIDHosta(t *testing.T) {
	pierwszy := ZaplanujMontowanie(migawkaZDyskiem("aaaa-1111"), "/dev/sdb", "/mnt/dane", "ext4", "", true)
	drugi := ZaplanujMontowanie(migawkaZDyskiem("bbbb-2222"), "/dev/sdb", "/mnt/dane", "ext4", "", true)

	if pierwszy.ResolvedSource != "UUID=aaaa-1111" || drugi.ResolvedSource != "UUID=bbbb-2222" {
		t.Fatalf("zrodla rozwiazane do %q i %q", pierwszy.ResolvedSource, drugi.ResolvedSource)
	}
	if pierwszy.Action != PlanTworzy || drugi.Action != PlanTworzy {
		t.Errorf("plany: %q, %q", pierwszy.Action, drugi.Action)
	}
	if pierwszy.PlanHash == drugi.PlanHash {
		t.Error("dwa rozne filesystemy daly ten sam odcisk planu")
	}
}

// TestPlanOdmawiaZrodlaBezUUID pilnuje, ze zmiana bez czego zwiazac jest
// odmowa, a nie montowaniem po sciezce, ktora po restarcie wskaze inny dysk.
func TestPlanOdmawiaZrodlaBezUUID(t *testing.T) {
	plan := ZaplanujMontowanie(migawkaZDyskiem(""), "/dev/sdb", "/mnt/dane", "ext4", "", true)
	if plan.Refusal == "" || !strings.Contains(plan.Refusal, "UUID") {
		t.Errorf("filesystem bez UUID nie dal odmowy: %+v", plan)
	}
	brak := ZaplanujMontowanie(Snapshot{}, "/dev/sdb", "/mnt/dane", "ext4", "", true)
	if brak.Refusal == "" {
		t.Error("nieistniejace zrodlo nie dalo odmowy")
	}
}

// TestPlanOdmawiaCeluZajetegoPrzezInnyFilesystem pilnuje, ze kampania nie
// przykryje po cichu cudzego montowania.
func TestPlanOdmawiaCeluZajetegoPrzezInnyFilesystem(t *testing.T) {
	stan := migawkaZDyskiem("aaaa-1111", Mount{
		Target: "/mnt/dane", Source: "/dev/sdc", FSType: "xfs", Mounted: true,
	})
	plan := ZaplanujMontowanie(stan, "/dev/sdb", "/mnt/dane", "ext4", "", true)
	if plan.Refusal == "" || !strings.Contains(plan.Refusal, "zajety") {
		t.Errorf("zajety cel nie dal odmowy: %+v", plan)
	}
}

// TestPlanWidziBrakWpisuWFstab pilnuje roznicy, po ktora operator tu
// przychodzi: zamontowane teraz i zamontowane po restarcie to dwa pytania.
func TestPlanWidziBrakWpisuWFstab(t *testing.T) {
	stan := migawkaZDyskiem("aaaa-1111", Mount{
		Target: "/mnt/dane", Source: "UUID=aaaa-1111", FSType: "ext4", Mounted: true, InFstab: false,
	})
	plan := ZaplanujMontowanie(stan, "/dev/sdb", "/mnt/dane", "ext4", "", true)
	if plan.Action != PlanZmienia {
		t.Fatalf("montowanie bez wpisu ma plan %q", plan.Action)
	}
	if !zawieraZmiane(plan.Changes, "fstab") {
		t.Errorf("plan nie nazywa brakujacego wpisu: %+v", plan.Changes)
	}

	gotowe := migawkaZDyskiem("aaaa-1111", Mount{
		Target: "/mnt/dane", Source: "UUID=aaaa-1111", FSType: "ext4",
		Mounted: true, InFstab: true, FstabOptions: "defaults",
	})
	if plan := ZaplanujMontowanie(gotowe, "/dev/sdb", "/mnt/dane", "ext4", "", true); plan.Action != PlanBezZmian {
		t.Errorf("montowanie w stanie docelowym ma plan %q (%+v)", plan.Action, plan.Changes)
	}
}

// TestPlanOdmontowaniaOdrozniaMontowanieIstniejace pilnuje, ze usuniecie
// czegos, czego nie ma, jest widoczne przed zatwierdzeniem.
func TestPlanOdmontowaniaOdrozniaMontowanieIstniejace(t *testing.T) {
	jest := ZaplanujOdmontowanie(migawkaZDyskiem("a", Mount{Target: "/mnt/dane", Mounted: true, InFstab: true}), "/mnt/dane")
	if jest.Action != PlanUsuwa || len(jest.Changes) != 2 {
		t.Errorf("odmontowanie ma plan %q (%+v)", jest.Action, jest.Changes)
	}
	niema := ZaplanujOdmontowanie(migawkaZDyskiem("a"), "/mnt/dane")
	if niema.Action != PlanJuzUsuniety {
		t.Errorf("odmontowanie nieistniejacego ma plan %q", niema.Action)
	}
}

func zawieraZmiane(lista []string, fragment string) bool {
	for _, wpis := range lista {
		if strings.Contains(wpis, fragment) {
			return true
		}
	}
	return false
}

func TestOdmowaZmieniaOdciskPlanu(t *testing.T) {
	stan := Snapshot{Devices: []Device{{Path: "/dev/sdb", FSType: "ext4", UUID: "abc"}}}
	plan := ZaplanujMontowanie(stan, "/dev/sdb", "/mnt/dane", "ext4", "", true)
	przed := plan.PlanHash
	plan.Odmow("filesystem jest w uzyciu przez: PID 1")
	if plan.Refusal == "" || plan.PlanHash == przed || plan.PlanHash == "" {
		t.Errorf("odmowa nie zmienila odcisku: przed=%s po=%s", przed, plan.PlanHash)
	}
}
