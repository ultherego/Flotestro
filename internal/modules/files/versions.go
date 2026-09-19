package files

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// VersionDir is where the host keeps the content a write displaced.
const VersionDir = "/var/lib/flotestro-helper/files"

// The bounds of the store when the host administrator set none.
const (
	DefaultVersionsPerPath = 10
	DefaultVersionBytes    = 32 << 20
)

var (
	// ErrNoSuchVersion means the host keeps no copy with that digest.
	ErrNoSuchVersion = errors.New("the host keeps no version of this file with that digest")
	// ErrVersionCorrupted means a copy whose content no longer hashes to the
	// digest it is filed under.
	ErrVersionCorrupted = errors.New("the kept version does not match its digest")
)

// KeptVersion describes one copy of a file the host kept before a write took
// its place.
type KeptVersion struct {
	// SHA256 addresses the version and is how an order names it.
	SHA256    string `json:"sha256,omitempty"`
	SizeBytes int64  `json:"size_bytes"`
	Mode      string `json:"mode,omitempty"`
	Owner     string `json:"owner,omitempty"`
	Group     string `json:"group,omitempty"`
	// KeptAt is when the copy was made, that is when the write that
	// displaced this content ran.
	KeptAt time.Time `json:"kept_at"`
	// OrderedBy names the task whose write displaced this content. The
	// panel turns it into a job and a person; the host knows the task.
	OrderedBy string `json:"ordered_by,omitempty"`
	// FromSecret marks content that came from the secret store.
	FromSecret bool `json:"from_secret,omitempty"`
	// Entry is the name of the copy inside the store.
	Entry string `json:"-"`
}

// VersionStore keeps the content a write displaced, so a rollback has
// something exact to put back.
type VersionStore struct {
	// Root is the directory of the store.
	Root string
	// KeepPerPath bounds the number of copies of one file.
	KeepPerPath int
	// MaxBytes bounds the whole store.
	MaxBytes int64
}

// metadataSuffix names the file describing a copy.
const metadataSuffix = ".meta"

// directory returns the place of one path in the store.
func (s VersionStore) directory(path string) string {
	sum := sha256.Sum256([]byte(path))
	return filepath.Join(s.Root, hex.EncodeToString(sum[:]))
}

// Keep copies the current content of a file into the store before it is
// overwritten.
func (s VersionStore) Keep(path string, current File, content []byte, orderedBy string) (KeptVersion, error) {
	digest := Fingerprint(content)
	directory := s.directory(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return KeptVersion{}, err
	}
	// The digest of the path is not the path: a directory of the store says
	// nothing about which file it belongs to unless the file itself is written
	// down next to the copies.
	if err := writePrivately(filepath.Join(directory, "path"), []byte(path+"\n")); err != nil {
		return KeptVersion{}, err
	}

	kept := KeptVersion{
		SHA256: digest, SizeBytes: int64(len(content)),
		Mode: current.Mode, Owner: current.Owner, Group: current.Group,
		KeptAt: time.Now().UTC(), OrderedBy: orderedBy, FromSecret: current.FromSecret,
	}
	kept.Entry = kept.KeptAt.Format("20060102T150405.000000000") + "-" + digest

	for _, existing := range s.list(directory) {
		if existing.SHA256 == digest {
			s.remove(directory, existing)
		}
	}
	if err := writePrivately(filepath.Join(directory, kept.Entry), content); err != nil {
		return KeptVersion{}, err
	}
	metadata, err := json.Marshal(kept)
	if err != nil {
		return KeptVersion{}, err
	}
	if err := writePrivately(filepath.Join(directory, kept.Entry+metadataSuffix), metadata); err != nil {
		_ = os.Remove(filepath.Join(directory, kept.Entry))
		return KeptVersion{}, err
	}

	s.pruneDirectory(directory)
	s.pruneTotal()
	return kept, nil
}

// List returns the versions kept for a path, newest first.
func (s VersionStore) List(path string) []KeptVersion {
	return s.list(s.directory(path))
}

// Reported returns the versions as the host reports them to the panel.
func (s VersionStore) Reported(path string) []KeptVersion {
	versions := s.List(path)
	for i := range versions {
		versions[i].Entry = ""
		if versions[i].FromSecret {
			versions[i].SHA256 = ""
		}
	}
	return versions
}

// Lookup returns the version with the given digest together with its
// content.
func (s VersionStore) Lookup(path, digest string) (KeptVersion, []byte, error) {
	directory := s.directory(path)
	for _, version := range s.list(directory) {
		if version.SHA256 != digest {
			continue
		}
		content, err := os.ReadFile(filepath.Join(directory, version.Entry))
		if err != nil {
			return KeptVersion{}, nil, err
		}
		// The copy is read back and checked against the name it is filed under: a
		// bit flip on the disk holding the store must not become a write of content
		// nobody approved.
		if Fingerprint(content) != digest {
			return KeptVersion{}, nil, fmt.Errorf("%w: %s", ErrVersionCorrupted, digest)
		}
		return version, content, nil
	}
	return KeptVersion{}, nil, fmt.Errorf("%w: %s", ErrNoSuchVersion, digest)
}

// list reads the versions of one directory, newest first.
func (s VersionStore) list(directory string) []KeptVersion {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil
	}
	var versions []KeptVersion
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || filepath.Ext(name) != metadataSuffix {
			continue
		}
		data, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			continue
		}
		var version KeptVersion
		if err := json.Unmarshal(data, &version); err != nil {
			continue
		}
		version.Entry = name[:len(name)-len(metadataSuffix)]
		// A description without its content is not a version: the copy is what a
		// rollback needs, and a half-written pair must not look like something that
		// can be restored.
		if _, err := os.Stat(filepath.Join(directory, version.Entry)); err != nil {
			continue
		}
		versions = append(versions, version)
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i].KeptAt.After(versions[j].KeptAt) })
	return versions
}

// pruneDirectory drops the oldest copies of one file above the count
// bound.
func (s VersionStore) pruneDirectory(directory string) {
	limit := s.KeepPerPath
	if limit <= 0 {
		limit = DefaultVersionsPerPath
	}
	versions := s.list(directory)
	for i := limit; i < len(versions); i++ {
		s.remove(directory, versions[i])
	}
}

// pruneTotal drops the oldest copies in the whole store above the byte bound.
func (s VersionStore) pruneTotal() {
	limit := s.MaxBytes
	if limit <= 0 {
		limit = DefaultVersionBytes
	}
	type entry struct {
		directory string
		version   KeptVersion
	}
	directories, err := os.ReadDir(s.Root)
	if err != nil {
		return
	}
	var all []entry
	var total int64
	for _, item := range directories {
		if !item.IsDir() {
			continue
		}
		directory := filepath.Join(s.Root, item.Name())
		for _, version := range s.list(directory) {
			all = append(all, entry{directory: directory, version: version})
			total += version.SizeBytes
		}
	}
	if total <= limit {
		return
	}
	sort.Slice(all, func(i, j int) bool { return all[i].version.KeptAt.Before(all[j].version.KeptAt) })
	for _, item := range all {
		if total <= limit {
			return
		}
		s.remove(item.directory, item.version)
		total -= item.version.SizeBytes
	}
}

// remove deletes one copy together with its description.
func (s VersionStore) remove(directory string, version KeptVersion) {
	if version.Entry == "" {
		return
	}
	_ = os.Remove(filepath.Join(directory, version.Entry+metadataSuffix))
	_ = os.Remove(filepath.Join(directory, version.Entry))
}

// writePrivately writes a file of the store so that only root reads it.
func writePrivately(path string, content []byte) error {
	if err := os.WriteFile(path, content, 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}
