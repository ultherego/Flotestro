package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// FstabPath points at the host mount file.
const FstabPath = "/etc/fstab"

var (
	// The mount source allows what can be checked and what does not depend
	// on the disk detection order: durable identifiers and paths in /dev. A
	// network name is a separate form here, because it is not a path.
	durableIdentifier = regexp.MustCompile(`^(UUID|PARTUUID|LABEL|PARTLABEL)=[A-Za-z0-9._:-]{1,64}$`)
	devicePath        = regexp.MustCompile(`^/dev/[A-Za-z0-9/._-]{1,120}$`)
	mountOptions      = regexp.MustCompile(`^[A-Za-z0-9=,._:/@%+-]{0,256}$`)
	filesystemType    = regexp.MustCompile(`^[a-z0-9]{1,16}$`)
)

// ValidateSource checks a mount source.
//
// The panel prefers a durable identifier to /dev/sdX: the device name
// depends on the detection order and after a reboot can point at a
// different disk. A path in /dev is allowed, because LVM volumes and arrays
// have stable names in /dev/mapper and /dev/md.
func ValidateSource(source string) error {
	if durableIdentifier.MatchString(source) || devicePath.MatchString(source) {
		return nil
	}
	return fmt.Errorf("the source %q must be a durable identifier (UUID=, LABEL=) or a path in /dev", source)
}

// ValidateTarget checks a mount point.
func ValidateTarget(target string) error {
	if !strings.HasPrefix(target, "/") {
		return fmt.Errorf("the mount point %q is not an absolute path", target)
	}
	if target != filepath.Clean(target) || strings.Contains(target, "..") {
		return fmt.Errorf("the mount point %q is not a normalised path", target)
	}
	// Directories whose shadowing cuts the host off from itself. Mounting
	// anything on them is a separate decision, not a wizard operation.
	for _, protected := range []string{"/", "/boot", "/dev", "/etc", "/proc", "/run",
		"/sys", "/usr", "/var", "/var/lib", "/var/log", "/bin", "/sbin", "/lib"} {
		if target == protected {
			return fmt.Errorf("the panel does not mount anything on %s", protected)
		}
	}
	if strings.ContainsAny(target, "\n\t") {
		return fmt.Errorf("the mount point contains a newline")
	}
	return nil
}

// ValidateOptions checks mount options.
func ValidateOptions(options, fsType string) error {
	if !filesystemType.MatchString(fsType) {
		return fmt.Errorf("invalid filesystem type %q", fsType)
	}
	if !mountOptions.MatchString(options) {
		return fmt.Errorf("the mount options contain a disallowed character")
	}
	return nil
}

// FstabLine composes an entry for /etc/fstab.
//
// Special characters are written in octal, the way fstab itself does it: a
// path with a space written directly would fall apart into two fields and
// the entry would point at an entirely different place.
func FstabLine(source, target, fsType, options string) string {
	if options == "" {
		options = "defaults"
	}
	return fmt.Sprintf("%s %s %s %s 0 0", encode(source), encode(target), fsType, options)
}

func encode(path string) string {
	var result strings.Builder
	for _, r := range path {
		switch r {
		case ' ', '\t', '\\':
			fmt.Fprintf(&result, `\%03o`, r)
		default:
			result.WriteRune(r)
		}
	}
	return result.String()
}

// WriteFstabEntry adds or replaces the panel entry.
//
// The write is atomic: the file is created next to the target and replaces
// the previous one only when complete. An fstab read half-way by systemd
// at a reboot would mean a host that does not come up.
func WriteFstabEntry(path, source, target, fsType, options string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(string(content), "\n")
	result := make([]string, 0, len(lines)+2)

	skip := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if skip {
			skip = false
			// The row after the panel marker belongs to the panel: it is
			// replaced.
			if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
				continue
			}
		}
		if strings.HasPrefix(trimmed, PanelMarker) {
			// The marker of our own entry with the same target is removed
			// together with it.
			if strings.Contains(trimmed, target) {
				skip = true
				continue
			}
		}
		result = append(result, line)
	}

	// Empty rows are removed from the end so the file does not grow at
	// every change.
	for len(result) > 0 && strings.TrimSpace(result[len(result)-1]) == "" {
		result = result[:len(result)-1]
	}
	result = append(result, PanelMarker+": "+target, FstabLine(source, target, fsType, options), "")

	return writeAtomically(path, strings.Join(result, "\n"))
}

// RemoveFstabEntry deletes the panel entry with the given target.
func RemoveFstabEntry(path, target string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(string(content), "\n")
	result := make([]string, 0, len(lines))
	skip := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if skip {
			skip = false
			if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
				continue
			}
		}
		if strings.HasPrefix(trimmed, PanelMarker) && strings.Contains(trimmed, target) {
			skip = true
			continue
		}
		result = append(result, line)
	}
	return writeAtomically(path, strings.Join(result, "\n"))
}

func writeAtomically(path, content string) error {
	temporary := path + ".flotestro-new"
	if err := os.WriteFile(temporary, []byte(content), 0o644); err != nil {
		return err
	}
	// fsync of the file and the directory: without it the change may not
	// survive a power failure, and fstab is a file read precisely after
	// such an event.
	file, err := os.Open(temporary)
	if err == nil {
		_ = file.Sync()
		_ = file.Close()
	}
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return nil
	}
	defer dir.Close()
	return dir.Sync()
}
