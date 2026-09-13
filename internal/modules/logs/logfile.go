// Package logs reads the logs of the host: the system journal and the files
// from the allowlist.
//
// Reading a file is not a general "read this path" operation. A panel that can
// read any file of root can read private keys and /etc/shadow - which is why
// the scope is enumerated by the administrator of the host and not given in the
// task.
package logs

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

// AllowlistPath points at the file with the allowed patterns. One pattern per
// line; empty lines and lines starting with # are skipped.
const AllowlistPath = "/etc/flotestro/logfiles.allow"

// defaultPatterns apply when the administrator named none of their own.
//
// The list is deliberately narrow: it covers the places where distributions
// keep their logs and nothing beyond them. Extending it is a decision of the
// administrator of the host and needs a write in /etc, not a change in the
// panel.
var defaultPatterns = []string{
	"/var/log/*.log",
	"/var/log/syslog",
	"/var/log/messages",
	"/var/log/auth.log",
	"/var/log/secure",
	"/var/log/kern.log",
	"/var/log/dpkg.log",
	"/var/log/apt/*.log",
	"/var/log/nginx/*.log",
	"/var/log/apache2/*.log",
	"/var/log/httpd/*.log",
}

var (
	// ErrOutsideAllowlist marks a path outside the allowed scope.
	ErrOutsideAllowlist = errors.New("the path is outside the allowlist")
	// ErrSymlink marks a path leading through a symbolic link.
	ErrSymlink = errors.New("the path leads through a symbolic link")
)

// Allowlist describes the allowed read scope.
type Allowlist struct {
	Patterns []string
	// Source says where the scope comes from: the file of the administrator or
	// the built-in default list. The operator is to know what limits them.
	Source string
}

// LoadAllowlist reads the scope from the file or returns the default one.
func LoadAllowlist(path string) Allowlist {
	file, err := os.Open(path)
	if err != nil {
		return Allowlist{Patterns: defaultPatterns, Source: "the built-in default list"}
	}
	defer file.Close()

	var patterns []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// A relative pattern cannot be evaluated, so it is skipped instead of
		// being matched against anything.
		if !strings.HasPrefix(line, "/") {
			continue
		}
		patterns = append(patterns, line)
	}
	if len(patterns) == 0 {
		return Allowlist{Patterns: defaultPatterns, Source: "the built-in default list"}
	}
	sort.Strings(patterns)
	return Allowlist{Patterns: patterns, Source: path}
}

// Allows checks whether the path fits within the scope.
//
// The path is cleaned first: a ".." inside would allow leaving the directory
// the pattern describes even though the text matches the pattern.
func (a Allowlist) Allows(path string) bool {
	if !strings.HasPrefix(path, "/") {
		return false
	}
	clean := filepath.Clean(path)
	if clean != path {
		return false
	}
	for _, pattern := range a.Patterns {
		if matches, err := filepath.Match(pattern, clean); err == nil && matches {
			return true
		}
	}
	return false
}

// Fragment is a piece of a file that was read.
type Fragment struct {
	Path string `json:"path"`
	// Lines is the tail of the file. The beginning is skipped, because the cause
	// of a failure is usually near the end of the log.
	Lines []string `json:"lines"`
	// Truncated says the file is longer than the returned fragment.
	Truncated bool  `json:"truncated"`
	SizeBytes int64 `json:"size_bytes"`
	// Allowlist says what limits the read.
	Allowlist string `json:"allowlist,omitempty"`
}

// maxLines limits a single read.
const maxLines = 2000

// maxBytes limits the size of the tail that is read.
const maxBytes = 1 << 20

// Read returns the tail of a file from the allowlist.
func Read(allowlist Allowlist, path string, lines uint32) (Fragment, error) {
	if !allowlist.Allows(path) {
		return Fragment{}, fmt.Errorf("%w: %s", ErrOutsideAllowlist, path)
	}
	if lines == 0 || lines > maxLines {
		lines = 200
	}

	file, err := openWithoutSymlinks(path)
	if err != nil {
		return Fragment{}, err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return Fragment{}, err
	}
	// A directory and a device are not a log; a read from a socket or a pipe
	// would hang forever.
	if !info.Mode().IsRegular() {
		return Fragment{}, fmt.Errorf("%s is not a regular file", path)
	}

	fragment := Fragment{Path: path, SizeBytes: info.Size(), Allowlist: allowlist.Source}
	start := int64(0)
	if info.Size() > maxBytes {
		start = info.Size() - maxBytes
		fragment.Truncated = true
	}
	if _, err := file.Seek(start, 0); err != nil {
		return fragment, err
	}

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64<<10), 1<<20)
	var collected []string
	for scanner.Scan() {
		collected = append(collected, scanner.Text())
		if len(collected) > int(lines) {
			collected = collected[1:]
			fragment.Truncated = true
		}
	}
	fragment.Lines = collected
	return fragment, scanner.Err()
}

// openWithoutSymlinks opens a file while refusing to follow symbolic links at
// any level of the path.
//
// A symlink in the log directory would allow any file of root to be read despite
// a correct allowlist: a pattern describes the path, not where it really leads.
func openWithoutSymlinks(path string) (*os.File, error) {
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC,
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
