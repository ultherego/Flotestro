package files

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// AllowlistPath points at the file with the scope set by the host
// administrator. One pattern per line; empty lines and lines starting with
// # are skipped.
const AllowlistPath = "/etc/flotestro/files.allow"

// defaultPatterns apply when the administrator has not set their own.
//
// The list is narrow and deliberately avoids the directories where secrets
// are kept. Extending it is the host administrator's decision and requires
// a write in /etc, not a change in the panel.
var defaultPatterns = []string{
	"/etc/*.conf",
	"/etc/sysctl.d/*.conf",
	"/etc/security/limits.d/*.conf",
	"/etc/logrotate.d/*",
	"/etc/systemd/system/*.conf",
	"/etc/systemd/system/*.d/*.conf",
	"/etc/nginx/conf.d/*.conf",
	"/etc/nginx/sites-available/*",
	"/etc/chrony/*.conf",
	"/etc/chrony.d/*.conf",
	"/etc/motd",
	"/etc/issue",
	"/etc/hosts",
	"/etc/resolv.conf.flotestro",
	"/opt/flotestro/etc/*",
}

// forbiddenPatterns list the paths the panel never touches - even when the
// host administrator adds them to the allowlist.
//
// This is not caution just in case: the file with password hashes, a
// private key or a sudo rule let anyone who can replace them into the
// system. Changing each of these has its own module with its own
// safeguards, not a text editor.
var forbiddenPatterns = []string{
	"/etc/shadow*",
	"/etc/gshadow*",
	"/etc/passwd",
	"/etc/group",
	"/etc/sudoers",
	"/etc/sudoers.d/*",
	"/etc/ssh/*_key",
	"/etc/ssh/sshd_config",
	"/etc/ssh/sshd_config.d/*",
	"/etc/pam.d/*",
	"/etc/krb5.keytab",
	"*.key",
	"*.pem",
	"/root/*",
	"/home/*",
	"/proc/*",
	"/sys/*",
	"/dev/*",
}

var (
	// ErrOutsideAllowlist means a path outside the allowed scope.
	ErrOutsideAllowlist = errors.New("path outside the allowlist")
	// ErrForbidden means a path the panel never touches.
	ErrForbidden = errors.New("the path belongs to another module and is not editable")
	// ErrSymlink means a path leading through a symlink.
	ErrSymlink = errors.New("the path leads through a symbolic link")
)

// Allowlist describes the allowed write scope.
type Allowlist struct {
	Patterns []string
	// Source says where the scope comes from. The operator needs to know
	// what limits them before asking why they cannot change something.
	Source string
}

// LoadAllowlist reads the scope from a file or returns the default.
func LoadAllowlist(path string) Allowlist {
	data, err := os.ReadFile(path)
	if err != nil {
		return Allowlist{Patterns: defaultPatterns, Source: "built-in default list"}
	}
	var patterns []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		patterns = append(patterns, line)
	}
	if len(patterns) == 0 {
		return Allowlist{Patterns: defaultPatterns, Source: "built-in default list"}
	}
	return Allowlist{Patterns: patterns, Source: path}
}

// Forbidden says whether the path belongs to another module and is not
// editable.
//
// The check is separate from the allowlist, because it binds the panel
// too: a task with such a path must not be created, even if the host
// would refuse it anyway.
func Forbidden(path string) error {
	for _, pattern := range forbiddenPatterns {
		if matches(pattern, path) {
			return fmt.Errorf("%w: %s", ErrForbidden, path)
		}
	}
	return nil
}

// Allows checks whether the path lies within the scope.
func (a Allowlist) Allows(path string) error {
	if !strings.HasPrefix(path, "/") {
		return fmt.Errorf("%w: the path must be absolute", ErrOutsideAllowlist)
	}
	if path != filepath.Clean(path) {
		return fmt.Errorf("%w: the path is not normalised", ErrOutsideAllowlist)
	}
	// The ban is checked first and cannot be bypassed by an allowlist
	// entry: the file with password hashes or a private key has its own
	// module, not a text editor.
	if err := Forbidden(path); err != nil {
		return err
	}
	for _, pattern := range a.Patterns {
		if matches(pattern, path) {
			return nil
		}
	}
	return fmt.Errorf("%w: %s (scope: %s)", ErrOutsideAllowlist, path, a.Source)
}

// matches compares a path with a pattern.
//
// A pattern without a trailing slash also matches files in subdirectories
// when it ends with an asterisk covering the whole tail - otherwise
// "/root/*" would not cover "/root/.ssh/id_rsa", and that is exactly the
// case it is meant to cover.
func matches(pattern, path string) bool {
	if ok, _ := filepath.Match(pattern, path); ok {
		return true
	}
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(path, prefix)
	}
	return false
}

// OpenWithoutSymlinks opens a file, refusing to pass through a symlink.
//
// A symlink in the configuration directory would allow overwriting any root
// file despite a correct allowlist: the pattern describes the path, not
// where it really leads.
func OpenWithoutSymlinks(path string, flags int, mode uint32) (*os.File, error) {
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{
		Flags:   uint64(flags) | unix.O_CLOEXEC,
		Mode:    uint64(mode),
		Resolve: unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.EXDEV) {
			return nil, fmt.Errorf("%w: %s", ErrSymlink, path)
		}
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}
