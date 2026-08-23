package agent

import (
	"context"
	"os"
	"time"

	"github.com/ultherego/flotestro/internal/modules/storage"
)

// lvmProbe czyta stan LVM przez helpera: narzedzia LVM wymagaja roota.
var lvmProbe func(context.Context) (storage.Snapshot, error)

// SetLVMProbe wskazuje funkcje odczytujaca grupy i wolumeny.
func SetLVMProbe(probe func(context.Context) (storage.Snapshot, error)) {
	lvmProbe = probe
}

// ZbierzPrzestrzen czyta topologie dyskow i punkty montowania.
//
// Odczyt urzadzen i montowan nie wymaga roota. LVM juz tak, wiec idzie przez
// helpera - a host bez LVM dostaje powod, nie pusta liste.
func ZbierzPrzestrzen(ctx context.Context) storage.Snapshot {
	snapshot := storage.Snapshot{ObservedAt: time.Now().UTC()}

	if !exists(storage.SciezkaLsblk) {
		snapshot.UnavailableReason = "this host has no lsblk binary"
		return snapshot
	}
	wyjscie, err := wyjsciePolecenia(ctx, storage.SciezkaLsblk, "-J", "-b", "-o",
		kolumny(storage.KolumnyLsblk))
	if err != nil {
		snapshot.UnavailableReason = "lsblk: " + err.Error()
		return snapshot
	}
	urzadzenia, err := storage.ParsujUrzadzenia(wyjscie)
	if err != nil {
		snapshot.UnavailableReason = err.Error()
		return snapshot
	}
	snapshot.Devices = urzadzenia

	mountinfo, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		snapshot.UnavailableReason = "mountinfo: " + err.Error()
		return snapshot
	}
	fstab, _ := os.ReadFile("/etc/fstab")
	snapshot.Mounts = storage.PolaczMontowania(
		storage.ParsujMountinfo(string(mountinfo)), storage.ParsujFstab(string(fstab)))
	uzupelnijZajetosc(snapshot.Mounts)

	if lvmProbe != nil {
		lvm, err := lvmProbe(ctx)
		if err != nil {
			snapshot.LVMUnavailableReason = "helper: " + err.Error()
		} else {
			snapshot.Groups = lvm.Groups
			snapshot.Volumes = lvm.Volumes
			snapshot.LVMUnavailableReason = lvm.LVMUnavailableReason
		}
	}
	// Macierze programowe czytamy z /proc/mdstat: brak pliku oznacza jadro
	// bez modulu md, a nie host bez macierzy.
	if _, err := os.Stat("/proc/mdstat"); err != nil {
		snapshot.RAIDUnavailableReason = "this kernel has no software RAID support (/proc/mdstat)"
	}
	return snapshot
}

// kolumny sklada liste kolumn dla lsblk.
func kolumny(nazwy []string) string {
	wynik := ""
	for i, nazwa := range nazwy {
		if i > 0 {
			wynik += ","
		}
		wynik += nazwa
	}
	return wynik
}
