package opspec

import (
	"crypto/sha256"
	"encoding/binary"
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
	// Length-prefixed, not joined. The comment here used to say "the separator
	// cannot appear in a package name, so no two sets can spell the same joined
	// string" - and nothing enforced that. A name carrying the separator made
	// two different sets share one digest, so the trail could say two orders
	// were given the same set when they were not. The same ambiguity in the
	// capability binding of a package order was the finding of 06.10; this is
	// its neighbour, and the trail is a place where a thing has to be true.
	var out []byte
	out = append(out, "flotestro-package-set/2\n"...)
	var word [8]byte
	binary.BigEndian.PutUint64(word[:], uint64(len(unique)))
	out = append(out, word[:]...)
	for _, name := range unique {
		binary.BigEndian.PutUint64(word[:], uint64(len(name)))
		out = append(out, word[:]...)
		out = append(out, name...)
	}
	sum := sha256.Sum256(out)
	return hex.EncodeToString(sum[:])
}
