package ctl

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"
)

// Rounded shortens a duration into a form a person can read.
func Rounded(duration time.Duration) string {
	if duration < 0 {
		duration = -duration
	}
	days := int(duration.Hours()) / 24
	hours := int(duration.Hours()) % 24
	if days > 0 {
		return fmt.Sprintf("%dd %02dh", days, hours)
	}
	return duration.Round(time.Second).String()
}

// Shortened trims a digest to a form that can be compared by eye.
func Shortened(value string) string {
	if len(value) > 12 {
		return value[:12]
	}
	return value
}

// Bytes prints a size the way an operator reads it: in the largest unit
// that keeps a whole number in front of the point.
func Bytes(value int64) string {
	const unit = 1024
	if value < unit {
		return fmt.Sprintf("%d B", value)
	}
	scaled := float64(value)
	suffixes := []string{"KiB", "MiB", "GiB", "TiB"}
	index := -1
	for scaled >= unit && index < len(suffixes)-1 {
		scaled /= unit
		index++
	}
	return fmt.Sprintf("%.1f %s", scaled, suffixes[index])
}

// CodeOf takes the stable code out of an error of the configuration.
//
// The errors of the parsers start with their code ("config_decode: ..."),
// so the text up to the first colon is the code - as long as it looks like
// one.
func CodeOf(err error, fallback string) string {
	text := err.Error()
	code, _, _ := strings.Cut(text, ":")
	code = strings.TrimSpace(code)
	if code == "" || strings.ContainsAny(code, " \t/") {
		return fallback
	}
	return code
}

// FilePermissions makes sure that not just anybody can swap the
// configuration out.
//
// The file names the address of the panel and the CA bundle, so the right
// to write to it is the right to redirect the component to somebody else's
// panel.
func FilePermissions(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s is writable by the group or by others (%04o)",
			path, info.Mode().Perm())
	}
	return nil
}

// SameOwner refuses to write the identity as somebody other than its owner.
//
// The store writes the new generation as the calling user. Run as root, it
// would leave a key the daemon cannot read - and the component would drop
// out of the fleet at the next restart, not now, when the operator is
// looking. The command is named in the hint so that the operator can repeat
// it as the right user. A directory that does not exist yet has no owner to
// compare with: the caller creates it as itself.
func SameOwner(stateDir, user, tool, command string) error {
	info, err := os.Stat(stateDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("the state directory: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("%s belongs to uid %d and this process runs as uid %d; run the command as the service: sudo -u %s %s %s",
			stateDir, stat.Uid, os.Geteuid(), user, tool, command)
	}
	return nil
}

// FreeSpace returns the bytes available on the filesystem of a path to an
// unprivileged process.
func FreeSpace(path string) (int64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, err
	}
	return int64(stat.Bavail) * int64(stat.Bsize), nil
}

// Writable says whether the process can create a file in the directory.
// The probe is removed at once: the check is about the right, not about
// leaving a trace.
func Writable(dir string) error {
	probe, err := os.CreateTemp(dir, ".probe-*")
	if err != nil {
		return err
	}
	name := probe.Name()
	_ = probe.Close()
	return os.Remove(name)
}
