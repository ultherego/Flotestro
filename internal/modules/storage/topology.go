package storage

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Tool paths. Fixed, not searched in PATH: the agent and the helper run
// only known binaries.
const (
	LsblkPath = "/usr/bin/lsblk"
	VGSPath   = "/usr/sbin/vgs"
	LVSPath   = "/usr/sbin/lvs"
)

// LsblkColumns lists the fields lsblk is asked for. A full "-O" returns
// dozens of columns per device and most of them are driver details the
// panel never shows.
var LsblkColumns = []string{
	"NAME", "PATH", "TYPE", "SIZE", "FSTYPE", "LABEL", "UUID", "PARTUUID",
	"MOUNTPOINTS", "MODEL", "SERIAL", "WWN", "ROTA", "RO", "PKNAME",
	"FSSIZE", "FSUSED", "FSAVAIL",
}

// rawBlock maps one entry of "lsblk -J -b".
type rawBlock struct {
	Name        string     `json:"name"`
	Path        string     `json:"path"`
	Type        string     `json:"type"`
	Size        *uint64    `json:"size"`
	FSType      *string    `json:"fstype"`
	Label       *string    `json:"label"`
	UUID        *string    `json:"uuid"`
	PartUUID    *string    `json:"partuuid"`
	Mountpoints []*string  `json:"mountpoints"`
	Model       *string    `json:"model"`
	Serial      *string    `json:"serial"`
	WWN         *string    `json:"wwn"`
	Rota        *bool      `json:"rota"`
	RO          *bool      `json:"ro"`
	PKName      *string    `json:"pkname"`
	FSSize      *uint64    `json:"fssize"`
	FSUsed      *uint64    `json:"fsused"`
	FSAvail     *uint64    `json:"fsavail"`
	Children    []rawBlock `json:"children"`
}

// ParseDevices reads the output of "lsblk -J -b".
//
// The tree is flattened into a list with a reference to the parent: the
// operator looks at the topology disk -> partition -> volume, but the panel
// must be able to point at every device separately, also in an operation
// plan.
func ParseDevices(output string) ([]Device, error) {
	var result struct {
		Blockdevices []rawBlock `json:"blockdevices"`
	}
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		return nil, fmt.Errorf("reading the block devices: %w", err)
	}
	var devices []Device
	var flatten func(block rawBlock, parent string)
	flatten = func(block rawBlock, parent string) {
		devices = append(devices, deviceFromBlock(block, parent))
		for _, child := range block.Children {
			flatten(child, block.Path)
		}
	}
	for _, block := range result.Blockdevices {
		flatten(block, "")
	}
	return devices, nil
}

func deviceFromBlock(block rawBlock, parent string) Device {
	device := Device{
		Name:       block.Name,
		Path:       block.Path,
		Type:       block.Type,
		FSType:     value(block.FSType),
		Label:      value(block.Label),
		UUID:       value(block.UUID),
		PartUUID:   value(block.PartUUID),
		Model:      strings.TrimSpace(value(block.Model)),
		Serial:     value(block.Serial),
		WWN:        value(block.WWN),
		Parent:     parent,
		Rotational: block.Rota,
	}
	if block.Size != nil {
		device.SizeBytes = *block.Size
	}
	if block.RO != nil {
		device.ReadOnly = *block.RO
	}
	// lsblk reports the parent as a kernel name; a path is more convenient
	// in a plan, so the one known from the tree is kept.
	if parent == "" && block.PKName != nil && *block.PKName != "" {
		device.Parent = "/dev/" + *block.PKName
	}
	for _, point := range block.Mountpoints {
		if point != nil && *point != "" {
			device.Mountpoints = append(device.Mountpoints, *point)
		}
	}
	// The filesystem size is at times smaller than the partition holding
	// it - and that is exactly the difference visible before a resize.
	device.FSSizeBytes = block.FSSize
	device.FSUsedBytes = block.FSUsed
	device.FSAvailBytes = block.FSAvail
	return device
}

func value(pointer *string) string {
	if pointer == nil {
		return ""
	}
	return *pointer
}

// lvmReport maps the output of the LVM tools in JSON format.
type lvmReport struct {
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

// ParseGroups reads the output of "vgs --reportformat json --units b".
func ParseGroups(output string) ([]VolumeGroup, error) {
	var report lvmReport
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		return nil, fmt.Errorf("reading the volume groups: %w", err)
	}
	var groups []VolumeGroup
	for _, section := range report.Report {
		for _, entry := range section.VG {
			groups = append(groups, VolumeGroup{
				Name:      entry.Name,
				SizeBytes: bytes(entry.Size),
				FreeBytes: bytes(entry.Free),
				PVCount:   number(entry.PVCount),
				LVCount:   number(entry.LVCount),
			})
		}
	}
	return groups, nil
}

// ParseVolumes reads the output of "lvs --reportformat json --units b".
func ParseVolumes(output string) ([]LogicalVolume, error) {
	var report lvmReport
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		return nil, fmt.Errorf("reading the volumes: %w", err)
	}
	var volumes []LogicalVolume
	for _, section := range report.Report {
		for _, entry := range section.LV {
			volumes = append(volumes, LogicalVolume{
				Name:      entry.Name,
				Group:     entry.Group,
				Path:      entry.Path,
				SizeBytes: bytes(entry.Size),
			})
		}
	}
	return volumes, nil
}

// bytes reads an LVM value written with the suffix "B".
func bytes(value string) uint64 {
	value = strings.TrimSuffix(strings.TrimSpace(value), "B")
	n, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0
	}
	return n
}

func number(value string) int {
	n, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return 0
	}
	return n
}
