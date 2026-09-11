package storage

import (
	"strings"
	"testing"
)

func stanUrzadzen() Snapshot {
	return Snapshot{
		Devices: []Device{
			{Path: "/dev/sdb", FSType: "ext4", UUID: "abc", SizeBytes: 2 << 30},
			{Path: "/dev/sda1", FSType: "ext4", UUID: "root", Mountpoints: []string{"/"}},
			{Path: "/dev/mapper/vg0-dane", FSType: "xfs", UUID: "lv", Mountpoints: []string{"/dane"}},
			{Path: "/dev/sdc"},
		},
		Groups: []VolumeGroup{{Name: "vg0", FreeBytes: 1 << 30}, {Name: "vg1", FreeBytes: 0}},
		Volumes: []LogicalVolume{{Name: "dane", Group: "vg0", Path: "/dev/mapper/vg0-dane", SizeBytes: 4 << 30},
			{Name: "pelny", Group: "vg1", Path: "/dev/mapper/vg1-pelny"}},
	}
}

func TestPlanSprawdzeniaOdmawiaZamontowanego(t *testing.T) {
	ok := ZaplanujSprawdzenie(stanUrzadzen(), "/dev/sdb", false)
	if ok.Action != PlanWykona || ok.Refusal != "" || ok.UUID != "abc" {
		t.Errorf("sprawdzenie odmontowanego: %+v", ok)
	}
	zamontowany := ZaplanujSprawdzenie(stanUrzadzen(), "/dev/sda1", false)
	if !strings.Contains(zamontowany.Refusal, "odmontowania") {
		t.Errorf("sprawdzenie zamontowanego bez odmowy: %+v", zamontowany)
	}
	bezFS := ZaplanujSprawdzenie(stanUrzadzen(), "/dev/sdc", false)
	if !strings.Contains(bezFS.Refusal, "nie ma filesystemu") {
		t.Errorf("urzadzenie bez filesystemu: %+v", bezFS)
	}
	if brak := ZaplanujSprawdzenie(stanUrzadzen(), "/dev/sdz", false); brak.Refusal == "" || brak.Found {
		t.Errorf("urzadzenie, ktorego nie ma: %+v", brak)
	}
}

func TestPlanRozszerzeniaFSZaleznyOdTypu(t *testing.T) {
	ext := ZaplanujRozszerzenieFS(stanUrzadzen(), "/dev/sdb")
	if ext.Action != PlanWykona || !strings.Contains(ext.Changes[0], "resize2fs") {
		t.Errorf("ext4: %+v", ext)
	}
	xfs := ZaplanujRozszerzenieFS(stanUrzadzen(), "/dev/mapper/vg0-dane")
	if xfs.Action != PlanWykona || !strings.Contains(xfs.Changes[0], "/dane") {
		t.Errorf("xfs zamontowany: %+v", xfs)
	}
	if bez := ZaplanujRozszerzenieFS(stanUrzadzen(), "/dev/sdc"); bez.Refusal == "" {
		t.Errorf("urzadzenie bez filesystemu bez odmowy: %+v", bez)
	}
}

func TestPlanRozszerzeniaLVLiczyWolneMiejsce(t *testing.T) {
	ok := ZaplanujRozszerzenieLV(stanUrzadzen(), "/dev/vg0/dane", "+512M")
	if ok.Action != PlanWykona || ok.Group != "vg0" || ok.FreeBytes != 1<<30 || len(ok.Changes) != 2 {
		t.Errorf("rozszerzenie z wolnym miejscem: %+v", ok)
	}
	pelna := ZaplanujRozszerzenieLV(stanUrzadzen(), "/dev/vg1/pelny", "+512M")
	if !strings.Contains(pelna.Refusal, "wolnego miejsca") {
		t.Errorf("grupa bez miejsca bez odmowy: %+v", pelna)
	}
	if brak := ZaplanujRozszerzenieLV(stanUrzadzen(), "/dev/vg9/x", "+1G"); brak.Refusal == "" {
		t.Errorf("wolumen, ktorego nie ma: %+v", brak)
	}
	bezLVM := ZaplanujRozszerzenieLV(Snapshot{LVMUnavailableReason: "brak lvm"}, "/dev/vg0/dane", "+1G")
	if bezLVM.Refusal != "brak lvm" {
		t.Errorf("host bez LVM: %+v", bezLVM)
	}
	if ok.PlanHash == pelna.PlanHash || ok.PlanHash == "" {
		t.Error("odciski planow nie roznia sie")
	}
}
