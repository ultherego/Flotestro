package packages

import (
	"strings"
)

// Protected packages are the ones whose removal cuts the host off from
// management or makes booting it impossible.
const AgentPackage = "flotestro-agent"

var protectedNames = []string{
	AgentPackage,
	"openssh-server",
	"systemd",
	"sudo",
	// The base set of Arch: the meta package of the system, the kernel, the
	// manager, the C library and the one ssh package the distribution has.
	"base",
	"linux",
	"pacman",
	"glibc",
	"openssh",
}

// protectedPrefixes cover the families of packages whose removal leaves the
// host without something to boot or upgrade it with.
var protectedPrefixes = []string{
	"linux-image",
	"kernel",
	"grub",
	"apt",
	"dpkg",
	"dnf",
	"rpm",
	"systemd-",
}

// Protected says whether a package belongs to the set that must not be
// removed without a deliberate override.
func Protected(name string) bool {
	name = strings.TrimSpace(strings.ToLower(name))
	if name == "" {
		return false
	}
	// A name with an architecture, e.g. "systemd:amd64", describes the same
	// package.
	if index := strings.IndexByte(name, ':'); index > 0 {
		name = name[:index]
	}
	for _, protectedName := range protectedNames {
		if name == protectedName {
			return true
		}
	}
	for _, prefix := range protectedPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// ProtectedInSet returns the ones of the given packages that are protected.
func ProtectedInSet(pkgs []string) []string {
	var result []string
	for _, pkg := range pkgs {
		if Protected(pkg) {
			result = append(result, pkg)
		}
	}
	return result
}
