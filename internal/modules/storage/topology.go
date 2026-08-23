package storage

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Sciezki narzedzi. Stale, a nie szukane w PATH: agent i helper uruchamiaja
// wylacznie znane binaria.
const (
	SciezkaLsblk = "/usr/bin/lsblk"
	SciezkaVGS   = "/usr/sbin/vgs"
	SciezkaLVS   = "/usr/sbin/lvs"
)

// KolumnyLsblk wylicza pola, o ktore pytamy lsblk. Pelne "-O" zwraca
// kilkadziesiat kolumn na urzadzenie i wieksza czesc z nich to szczegoly
// sterownika, ktorych panel nigdy nie pokaze.
var KolumnyLsblk = []string{
	"NAME", "PATH", "TYPE", "SIZE", "FSTYPE", "LABEL", "UUID", "PARTUUID",
	"MOUNTPOINTS", "MODEL", "SERIAL", "WWN", "ROTA", "RO", "PKNAME",
	"FSSIZE", "FSUSED", "FSAVAIL",
}

// surowyBlok odwzorowuje jeden wpis z "lsblk -J -b".
type surowyBlok struct {
	Name        string       `json:"name"`
	Path        string       `json:"path"`
	Type        string       `json:"type"`
	Size        *uint64      `json:"size"`
	FSType      *string      `json:"fstype"`
	Label       *string      `json:"label"`
	UUID        *string      `json:"uuid"`
	PartUUID    *string      `json:"partuuid"`
	Mountpoints []*string    `json:"mountpoints"`
	Model       *string      `json:"model"`
	Serial      *string      `json:"serial"`
	WWN         *string      `json:"wwn"`
	Rota        *bool        `json:"rota"`
	RO          *bool        `json:"ro"`
	PKName      *string      `json:"pkname"`
	FSSize      *uint64      `json:"fssize"`
	FSUsed      *uint64      `json:"fsused"`
	FSAvail     *uint64      `json:"fsavail"`
	Children    []surowyBlok `json:"children"`
}

// ParsujUrzadzenia czyta wyjscie "lsblk -J -b".
//
// Drzewo splaszczamy do listy z odsylaczem do rodzica: operator patrzy na
// topologie dysk -> partycja -> wolumen, ale panel musi umiec wskazac kazde
// urzadzenie z osobna, takze w planie operacji.
func ParsujUrzadzenia(wyjscie string) ([]Device, error) {
	var wynik struct {
		Blockdevices []surowyBlok `json:"blockdevices"`
	}
	if err := json.Unmarshal([]byte(wyjscie), &wynik); err != nil {
		return nil, fmt.Errorf("odczyt urzadzen blokowych: %w", err)
	}
	var urzadzenia []Device
	var splaszcz func(blok surowyBlok, rodzic string)
	splaszcz = func(blok surowyBlok, rodzic string) {
		urzadzenia = append(urzadzenia, urzadzenieZBloku(blok, rodzic))
		for _, dziecko := range blok.Children {
			splaszcz(dziecko, blok.Path)
		}
	}
	for _, blok := range wynik.Blockdevices {
		splaszcz(blok, "")
	}
	return urzadzenia, nil
}

func urzadzenieZBloku(blok surowyBlok, rodzic string) Device {
	urzadzenie := Device{
		Name:       blok.Name,
		Path:       blok.Path,
		Type:       blok.Type,
		FSType:     wartosc(blok.FSType),
		Label:      wartosc(blok.Label),
		UUID:       wartosc(blok.UUID),
		PartUUID:   wartosc(blok.PartUUID),
		Model:      strings.TrimSpace(wartosc(blok.Model)),
		Serial:     wartosc(blok.Serial),
		WWN:        wartosc(blok.WWN),
		Parent:     rodzic,
		Rotational: blok.Rota,
	}
	if blok.Size != nil {
		urzadzenie.SizeBytes = *blok.Size
	}
	if blok.RO != nil {
		urzadzenie.ReadOnly = *blok.RO
	}
	// lsblk podaje rodzica jako nazwe jadra; sciezka jest wygodniejsza
	// w planie, wiec zostawiamy te, ktora znamy z drzewa.
	if rodzic == "" && blok.PKName != nil && *blok.PKName != "" {
		urzadzenie.Parent = "/dev/" + *blok.PKName
	}
	for _, punkt := range blok.Mountpoints {
		if punkt != nil && *punkt != "" {
			urzadzenie.Mountpoints = append(urzadzenie.Mountpoints, *punkt)
		}
	}
	// Rozmiar filesystemu bywa mniejszy niz partycja, ktora go trzyma -
	// i to jest dokladnie ta roznica, ktora widac przed resize.
	urzadzenie.FSSizeBytes = blok.FSSize
	urzadzenie.FSUsedBytes = blok.FSUsed
	urzadzenie.FSAvailBytes = blok.FSAvail
	return urzadzenie
}

func wartosc(wskaznik *string) string {
	if wskaznik == nil {
		return ""
	}
	return *wskaznik
}

// raportLVM odwzorowuje wyjscie narzedzi LVM w formacie JSON.
type raportLVM struct {
	Report []struct {
		VG []struct {
			Name    string `json:"vg_name"`
			Size    string `json:"vg_size"`
			Free    string `json:"vg_free"`
			PVCount string `json:"pv_count"`
			LVCount string `json:"lv_count"`
		} `json:"vg"`
		LV []struct {
			Name  string `json:"lv_name"`
			Group string `json:"vg_name"`
			Size  string `json:"lv_size"`
			Path  string `json:"lv_path"`
		} `json:"lv"`
	} `json:"report"`
}

// ParsujGrupy czyta wyjscie "vgs --reportformat json --units b".
func ParsujGrupy(wyjscie string) ([]VolumeGroup, error) {
	var raport raportLVM
	if err := json.Unmarshal([]byte(wyjscie), &raport); err != nil {
		return nil, fmt.Errorf("odczyt grup wolumenow: %w", err)
	}
	var grupy []VolumeGroup
	for _, sekcja := range raport.Report {
		for _, wpis := range sekcja.VG {
			grupy = append(grupy, VolumeGroup{
				Name:      wpis.Name,
				SizeBytes: bajty(wpis.Size),
				FreeBytes: bajty(wpis.Free),
				PVCount:   liczba(wpis.PVCount),
				LVCount:   liczba(wpis.LVCount),
			})
		}
	}
	return grupy, nil
}

// ParsujWolumeny czyta wyjscie "lvs --reportformat json --units b".
func ParsujWolumeny(wyjscie string) ([]LogicalVolume, error) {
	var raport raportLVM
	if err := json.Unmarshal([]byte(wyjscie), &raport); err != nil {
		return nil, fmt.Errorf("odczyt wolumenow: %w", err)
	}
	var wolumeny []LogicalVolume
	for _, sekcja := range raport.Report {
		for _, wpis := range sekcja.LV {
			wolumeny = append(wolumeny, LogicalVolume{
				Name:      wpis.Name,
				Group:     wpis.Group,
				Path:      wpis.Path,
				SizeBytes: bajty(wpis.Size),
			})
		}
	}
	return wolumeny, nil
}

// bajty czyta wartosc LVM zapisana z sufiksem "B".
func bajty(wartosc string) uint64 {
	wartosc = strings.TrimSuffix(strings.TrimSpace(wartosc), "B")
	liczba, err := strconv.ParseUint(wartosc, 10, 64)
	if err != nil {
		return 0
	}
	return liczba
}

func liczba(wartosc string) int {
	numer, err := strconv.Atoi(strings.TrimSpace(wartosc))
	if err != nil {
		return 0
	}
	return numer
}
