package packages

import (
	"strings"
)

// Protected packages are the ones whose removal cuts the host off from
// management or makes booting it impossible.
//
// The list is not complete and is not meant to be: what settles the matter is
// the Essential flag from the package database, which the distribution
// maintains better than we do. These names cover the things the distribution
// does not consider essential and which are no less important in a managed
// fleet: the agent that will carry a repair out, and the access one can come
// in through when the panel fails.
// AgentPackage is the name of the package that carries this agent. An ordinary
// package upgrade deliberately skips it.
const AgentPackage = "flotestro-agent"

var protectedNames = []string{
	AgentPackage,
	"openssh-server",
	"systemd",
	"sudo",
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
// We return a list rather than a plain "yes/no": the operator is to know which
// package blocks the operation rather than only that something blocks it.
func ProtectedInSet(pkgs []string) []string {
	var result []string
	for _, pkg := range pkgs {
		if Protected(pkg) {
			result = append(result, pkg)
		}
	}
	return result
}
