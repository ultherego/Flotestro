package kernel

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var moduleName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// ParseModules reads /proc/modules.
//
// The kernel file is read, not the lsmod output: lsmod is only a formatting
// of it, and the panel needs fields lsmod does not show anyway.
func ParseModules(content string) []Module {
	var modules []Module
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		module := Module{Name: fields[0]}
		if size, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
			module.SizeBytes = size
		}
		// The fourth field lists the dependent modules, comma-separated.
		// A dash means no dependencies - and is not a module name.
		if fields[3] != "-" {
			for _, dependent := range strings.Split(strings.TrimSuffix(fields[3], ","), ",") {
				if dependent != "" {
					module.UsedBy = append(module.UsedBy, dependent)
				}
			}
		}
		modules = append(modules, module)
	}
	return modules
}

// ParseBlacklist reads a modprobe blacklist file.
func ParseBlacklist(content string) []string {
	var names []string
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) != 2 || fields[0] != "blacklist" {
			continue
		}
		names = append(names, fields[1])
	}
	return names
}

// ComposeBlacklist composes the content of the blacklist file.
//
// A blacklist entry in modprobe.d works for modules loaded on demand. A
// module pulled in by the initramfs is loaded before this file even exists
// in the filesystem - that is why a complete block needs the initramfs
// rebuilt, and the panel says so directly instead of pretending the entry
// is enough.
func ComposeBlacklist(names []string) (string, error) {
	if len(names) == 0 {
		return FileHeader + "\n", nil
	}
	lines := []string{FileHeader}
	for _, name := range names {
		if err := ValidateModule(name); err != nil {
			return "", err
		}
		// The blacklist alone is not enough when the module is a dependency
		// of another: "install ... /bin/false" stops indirect loading too.
		lines = append(lines, "blacklist "+name, "install "+name+" /bin/false")
	}
	return strings.Join(lines, "\n") + "\n", nil
}

// ValidateModule checks a module name.
func ValidateModule(name string) error {
	if !moduleName.MatchString(name) {
		return fmt.Errorf("invalid module name %q", name)
	}
	if reason, protected := protectedModules[name]; protected {
		return fmt.Errorf("the panel does not block the module %s: %s", name, reason)
	}
	return nil
}

// protectedModules lists the modules whose blocking stops the host or cuts
// it off from the panel.
var protectedModules = map[string]string{
	"ext4":       "without it the host cannot mount its own root",
	"xfs":        "without it the host cannot mount its own root",
	"dm_mod":     "without it the LVM volumes, including the root, do not come up",
	"dm-mod":     "without it the LVM volumes, including the root, do not come up",
	"virtio_net": "without it the virtual machine loses its network",
	"virtio_blk": "without it the virtual machine loses its disk",
	"e1000":      "without it the host may lose its only network card",
	"nf_tables":  "without it the host firewall stops working",
}

// InitramfsRequired says whether the block needs the initramfs rebuilt.
//
// A reason is returned, not a flag: the operator is meant to read why the
// entry in modprobe.d alone is not enough.
func InitramfsRequired(name string, loaded bool) string {
	if !loaded {
		return ""
	}
	return "the module " + name + " is loaded; the block takes effect only after a reboot, " +
		"and for modules pulled in by the initramfs also after it is rebuilt"
}
