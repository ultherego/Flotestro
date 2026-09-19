package storage

import (
	"regexp"
	"strings"
)

// PanelMarker marks the fstab entries created by the panel.
const PanelMarker = "# flotestro"

// systemTypes lists the kernel mounts that are not the host disk space.
var systemTypes = map[string]bool{
	"sysfs": true, "proc": true, "devtmpfs": true, "devpts": true, "tmpfs": true,
	"securityfs": true, "cgroup": true, "cgroup2": true, "pstore": true,
	"efivarfs": true, "bpf": true, "autofs": true, "hugetlbfs": true,
	"mqueue": true, "debugfs": true, "tracefs": true, "fusectl": true,
	"configfs": true, "ramfs": true, "binfmt_misc": true, "rpc_pipefs": true,
	"nsfs": true, "squashfs": true, "overlay": true,
}

// ParseMountinfo reads /proc/self/mountinfo.
func ParseMountinfo(content string) []Mount {
	var mounts []Mount
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		// Format: id parent major:minor root target options [optional fields] - type source options
		separator := -1
		for i, field := range fields {
			if field == "-" {
				separator = i
				break
			}
		}
		if separator < 0 || separator+2 >= len(fields) {
			continue
		}
		mount := Mount{
			Target:  decode(fields[4]),
			Options: fields[5],
			FSType:  fields[separator+1],
			Source:  decode(fields[separator+2]),
			Mounted: true,
		}
		if systemTypes[mount.FSType] {
			continue
		}
		mounts = append(mounts, mount)
	}
	return mounts
}

// decode replaces the octal sequences the kernel writes special characters in
// paths with.
var sequence = regexp.MustCompile(`\\([0-7]{3})`)

func decode(path string) string {
	return sequence.ReplaceAllStringFunc(path, func(match string) string {
		var value int
		for _, digit := range match[1:] {
			value = value*8 + int(digit-'0')
		}
		return string(rune(value))
	})
}

// FstabEntry is one row of /etc/fstab.
type FstabEntry struct {
	Source  string
	Target  string
	FSType  string
	Options string
	Dump    string
	Pass    string
	// Managed marks an entry created by the panel.
	Managed bool
	Line    int
}

// ParseFstab reads /etc/fstab.
func ParseFstab(content string) []FstabEntry {
	var entries []FstabEntry
	managed := false
	number := 0
	for _, line := range strings.Split(content, "\n") {
		number++
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			managed = false
			continue
		}
		if strings.HasPrefix(trimmed, "#") {
			// The panel marker stands above the entry the panel created.
			managed = strings.HasPrefix(trimmed, PanelMarker)
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 3 {
			managed = false
			continue
		}
		// fstab writes special characters the same way the kernel does in mountinfo:
		// in octal.
		entry := FstabEntry{
			Source: decode(fields[0]), Target: decode(fields[1]), FSType: fields[2],
			Managed: managed, Line: number,
		}
		if len(fields) > 3 {
			entry.Options = fields[3]
		}
		if len(fields) > 4 {
			entry.Dump = fields[4]
		}
		if len(fields) > 5 {
			entry.Pass = fields[5]
		}
		entries = append(entries, entry)
		managed = false
	}
	return entries
}

// MergeMounts joins the kernel state with the fstab content.
func MergeMounts(fromKernel []Mount, fromFstab []FstabEntry) []Mount {
	result := make([]Mount, 0, len(fromKernel)+len(fromFstab))
	used := map[string]bool{}

	for _, mount := range fromKernel {
		for _, entry := range fromFstab {
			if entry.Target != mount.Target {
				continue
			}
			mount.InFstab = true
			mount.FstabOptions = entry.Options
			mount.Managed = entry.Managed
			used[entry.Target] = true
			break
		}
		result = append(result, mount)
	}

	for _, entry := range fromFstab {
		if used[entry.Target] || entry.Target == "none" || entry.Target == "swap" {
			continue
		}
		// An entry nobody mounted.
		result = append(result, Mount{
			Target: entry.Target, Source: entry.Source, FSType: entry.FSType,
			FstabOptions: entry.Options, InFstab: true, Managed: entry.Managed,
		})
	}
	return result
}
