// Package storage opisuje dyski, filesystemy i punkty montowania hosta.
//
// Modul czyta stan jadra i menedzera wolumenow, a nie sam /etc/fstab: plik
// mowi, co ma byc zamontowane po restarcie, a nie co jest zamontowane teraz.
// Roznica miedzy jednym a drugim jest zwykle powodem, dla ktorego ktos w
// ogole otwiera te zakladke.
package storage

import "time"

// Rodzaje urzadzen blokowych, ktore modul rozroznia.
const (
	TypDysk       = "disk"
	TypPartycja   = "part"
	TypLVM        = "lvm"
	TypRAID       = "raid"
	TypSzyfrowany = "crypt"
)

// Device to jedno urzadzenie blokowe.
//
// Identyfikacja idzie po WWN, serialu i UUID, a nie po /dev/sdX: nazwa
// urzadzenia zalezy od kolejnosci wykrywania i po restarcie potrafi wskazac
// zupelnie inny dysk. Przy operacji niszczacej to jest roznica miedzy
// wyczyszczeniem wlasciwego dysku a wyczyszczeniem cudzych danych.
type Device struct {
	Name string `json:"name"`
	Path string `json:"path"`
	Type string `json:"type"`
	// SizeBytes jest rozmiarem urzadzenia. Zero oznacza urzadzenie puste
	// albo nieodczytane - i wtedy niesie je powod przy migawce.
	SizeBytes uint64 `json:"size_bytes"`
	FSType    string `json:"fs_type,omitempty"`
	Label     string `json:"label,omitempty"`
	UUID      string `json:"uuid,omitempty"`
	PartUUID  string `json:"part_uuid,omitempty"`
	Model     string `json:"model,omitempty"`
	Serial    string `json:"serial,omitempty"`
	WWN       string `json:"wwn,omitempty"`
	// Parent wskazuje urzadzenie nadrzedne: partycja ma dysk, wolumen
	// logiczny ma grupe. Puste dla urzadzen najwyzszego poziomu.
	Parent string `json:"parent,omitempty"`
	// Rotational odroznia talerz od SSD. Brak wartosci oznacza, ze jadro
	// tego nie podalo, a nie ze urzadzenie sie nie kreci.
	Rotational *bool `json:"rotational,omitempty"`
	ReadOnly   bool  `json:"read_only"`
	// Mountpoints wylicza miejsca, w ktorych urzadzenie jest zamontowane.
	// Jedno urzadzenie moze byc zamontowane w kilku miejscach.
	Mountpoints []string `json:"mountpoints,omitempty"`
	// FSSizeBytes i FSUsedBytes opisuja filesystem, a nie urzadzenie:
	// filesystem bywa mniejszy niz partycja, ktora go trzyma.
	FSSizeBytes  *uint64 `json:"fs_size_bytes,omitempty"`
	FSUsedBytes  *uint64 `json:"fs_used_bytes,omitempty"`
	FSAvailBytes *uint64 `json:"fs_avail_bytes,omitempty"`
}

// Mount to jeden punkt montowania.
type Mount struct {
	Target string `json:"target"`
	Source string `json:"source"`
	FSType string `json:"fs_type"`
	// Options sa opcjami, z ktorymi filesystem jest zamontowany teraz.
	Options string `json:"options,omitempty"`
	// FstabOptions sa opcjami zapisanymi w /etc/fstab. Roznica miedzy nimi
	// a Options oznacza montowanie, ktore po restarcie zachowa sie inaczej.
	FstabOptions string `json:"fstab_options,omitempty"`
	// InFstab i Mounted rozdzielaja dwa pytania: czy wpis istnieje i czy
	// filesystem jest zamontowany. Cztery kombinacje znacza cztery rozne
	// rzeczy, a operator patrzy na te zakladke wlasnie przez nie.
	InFstab bool `json:"in_fstab"`
	Mounted bool `json:"mounted"`
	// Managed oznacza wpis zalozony przez panel.
	Managed bool `json:"managed"`
	// UsedPercent i InodesUsedPercent sa zajetoscia. Brak wartosci oznacza
	// filesystem, ktorego nie dalo sie odpytac - nie filesystem pusty.
	UsedPercent       *uint32 `json:"used_percent,omitempty"`
	InodesUsedPercent *uint32 `json:"inodes_used_percent,omitempty"`
	SizeBytes         *uint64 `json:"size_bytes,omitempty"`
	AvailBytes        *uint64 `json:"avail_bytes,omitempty"`
}

// VolumeGroup to grupa wolumenow LVM.
type VolumeGroup struct {
	Name      string `json:"name"`
	SizeBytes uint64 `json:"size_bytes"`
	FreeBytes uint64 `json:"free_bytes"`
	PVCount   int    `json:"pv_count"`
	LVCount   int    `json:"lv_count"`
}

// LogicalVolume to wolumen logiczny LVM.
type LogicalVolume struct {
	Name      string `json:"name"`
	Group     string `json:"group"`
	Path      string `json:"path"`
	SizeBytes uint64 `json:"size_bytes"`
}

// Snapshot to obraz przestrzeni dyskowej hosta.
type Snapshot struct {
	Devices []Device `json:"devices,omitempty"`
	Mounts  []Mount  `json:"mounts,omitempty"`
	// Groups i Volumes sa puste na hoscie bez LVM. Powod niedostepnosci
	// niesie LVMUnavailableReason: brak grup i brak LVM to dwie rozne
	// odpowiedzi.
	Groups                []VolumeGroup   `json:"groups,omitempty"`
	Volumes               []LogicalVolume `json:"volumes,omitempty"`
	LVMUnavailableReason  string          `json:"lvm_unavailable_reason,omitempty"`
	RAIDUnavailableReason string          `json:"raid_unavailable_reason,omitempty"`
	ObservedAt            time.Time       `json:"observed_at"`
	UnavailableReason     string          `json:"unavailable_reason,omitempty"`
}

// Urzadzenie zwraca urzadzenie o podanej sciezce albo nil.
func (s Snapshot) Urzadzenie(sciezka string) *Device {
	for i := range s.Devices {
		if s.Devices[i].Path == sciezka {
			return &s.Devices[i]
		}
	}
	return nil
}

// Montowanie zwraca punkt montowania o podanym celu albo nil.
func (s Snapshot) Montowanie(cel string) *Mount {
	for i := range s.Mounts {
		if s.Mounts[i].Target == cel {
			return &s.Mounts[i]
		}
	}
	return nil
}
