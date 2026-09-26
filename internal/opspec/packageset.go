package opspec

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// PackageSetDigest names the set of packages an order was given, or the empty
// string when it names none. The set is a set: the same names in another order,
// or a name repeated, give the same digest, because the host is told the same
// thing either way.
//
// It exists for the trail. One patch of one vulnerability becomes an order per
// package set - a host is sent what it is affected in and no more - so the set is
// what tells two orders of the same campaign apart afterwards.
func PackageSetDigest(payload Payload) string {
	var names []string
	if payload.PackageChange != nil {
		names = append(names, payload.PackageChange.Packages...)
	}
	if payload.PackageUpgrade != nil {
		names = append(names, payload.PackageUpgrade.Packages...)
	}
	seen := make(map[string]bool, len(names))
	unique := make([]string, 0, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		unique = append(unique, name)
	}
	if len(unique) == 0 {
		return ""
	}
	sort.Strings(unique)
	// The separator cannot appear in a package name, so no two sets can spell
	// the same joined string.
	sum := sha256.Sum256([]byte(strings.Join(unique, "\n")))
	return hex.EncodeToString(sum[:])
}
