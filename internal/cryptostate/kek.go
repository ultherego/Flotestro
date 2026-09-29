package cryptostate

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/ultherego/flotestro/internal/secrets"
)

// DefaultKEKFile is where a deployment mounts the key encryption key: a secret
// of the runtime, read-only, outside the database and outside the image.
const DefaultKEKFile = "/run/secrets/flotestro-kek"

// The stable codes of a key encryption key that cannot be used. Each says
// which of the three things is wrong, because the three are fixed differently:
// the file is not there, somebody else could rewrite it, or its content is not
// a key.
const (
	// CodeKEKFileMissing: no file at the path the deployment names.
	CodeKEKFileMissing = "kek_file_missing"
	// CodeKEKFileUnsafe: a file somebody other than its owner could replace -
	// a link, a directory, a file of another account, one the group or the world
	// may write.
	CodeKEKFileUnsafe = "kek_file_unsafe"
	// CodeKEKFileMalformed: the content is not 64 hexadecimal characters.
	CodeKEKFileMalformed = "kek_file_malformed"
	// CodeKEKMismatch: the key in the file is not the one this installation's
	// records were sealed with.
	CodeKEKMismatch = "kek_mismatch"
)

// kekHexLength is the length of the key as it is written down: 32 bytes as
// hexadecimal. One format and no other - two would mean a reader has to guess,
// and a guess about key material is how a deployment ends up with a key nobody
// can reproduce.
const kekHexLength = 2 * secrets.KeyLength

// kekIDLabel separates the identifier from every other use of the key.
const kekIDLabel = "flotestro-kek-id"

// KEK is the key encryption key of an installation, with the name it is known
// by in the records it seals.
type KEK struct {
	key []byte
	id  string
}

// ReadKEKFile reads the key encryption key from a mounted secret.
//
// The file is opened without following a link and judged on the descriptor, so
// what was checked is what was read: a regular file, owned by this process or
// by root, and not writable by the group or by anybody else. Whoever can
// rewrite this file decides what the installation's records are sealed with.
func ReadKEKFile(path string) (*KEK, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	switch {
	case errors.Is(err, unix.ENOENT):
		return nil, fatal(CodeKEKFileMissing, "no key encryption key at "+path, nil)
	case errors.Is(err, unix.ELOOP):
		// O_NOFOLLOW answers a symbolic link with ELOOP: the path is a link, and a
		// link moves the decision about the key somewhere nobody looked.
		return nil, fatal(CodeKEKFileUnsafe, path+" is a symbolic link", nil)
	case err != nil:
		return nil, fatal(CodeKEKFileUnsafe, "the key encryption key "+path+" could not be opened", err)
	}
	defer unix.Close(fd)

	if err := kekFileIsSafe(fd, path); err != nil {
		return nil, err
	}
	content := make([]byte, kekHexLength+2)
	read, err := unix.Read(fd, content)
	if err != nil {
		return nil, fatal(CodeKEKFileUnsafe, "the key encryption key "+path+" could not be read", err)
	}
	return ParseKEK(string(content[:read]), path)
}

// ParseKEK reads the content of a key file. It is separate from the reading so
// that the shape can be tested without a file, and so that the rule lives in
// one place: 64 hexadecimal characters, with at most the one line break the
// command that writes a secret leaves behind.
//
// The trailing newline is taken off by itself rather than by trimming space
// around the value: trimming would also swallow a key that arrived with spaces
// or a second line in it, and content that is not what it should be must be
// refused rather than tidied up.
func ParseKEK(content, path string) (*KEK, error) {
	value := strings.TrimSuffix(content, "\n")
	switch {
	case value == "":
		return nil, fatal(CodeKEKFileMalformed, path+" is empty", nil)
	case len(value) != kekHexLength:
		return nil, fatal(CodeKEKFileMalformed, fmt.Sprintf(
			"%s holds %d characters; a key encryption key is %d hexadecimal characters "+
				"(openssl rand -hex %d)", path, len(value), kekHexLength, secrets.KeyLength), nil)
	}
	key, err := hex.DecodeString(value)
	if err != nil {
		return nil, fatal(CodeKEKFileMalformed,
			path+" holds something that is not hexadecimal", nil)
	}
	if allZero(key) {
		return nil, fatal(CodeKEKFileMalformed, path+" holds a key of zeros", nil)
	}
	return &KEK{key: key, id: kekID(key)}, nil
}

// kekFileIsSafe judges the open file: what was checked is what will be read.
func kekFileIsSafe(fd int, path string) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fatal(CodeKEKFileUnsafe, "the key encryption key "+path+" could not be read", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return fatal(CodeKEKFileUnsafe, path+" is not a regular file", nil)
	}
	if stat.Uid != 0 && uint64(stat.Uid) != uint64(os.Geteuid()) {
		return fatal(CodeKEKFileUnsafe, fmt.Sprintf(
			"%s is owned by uid %d, which is neither root nor this process (%d)",
			path, stat.Uid, os.Geteuid()), nil)
	}
	if stat.Mode&0o077 != 0 {
		return fatal(CodeKEKFileUnsafe, fmt.Sprintf(
			"%s is readable or writable by others (mode %04o); a key encryption key is 0400",
			path, stat.Mode&0o7777), nil)
	}
	return nil
}

// ID is the name this key is known by. It is a digest keyed with the key
// itself, not a digest of it: the identifier travels in the database and in the
// log, and neither is a place for anything derived from key material by a
// digest anybody could repeat.
func (k *KEK) ID() string { return k.id }

// Cipher is the key as the envelope uses it.
func (k *KEK) Cipher() (*secrets.Cipher, error) { return secrets.NewCipher(k.key) }

// Is says whether this is the key the given identifier names.
func (k *KEK) Is(id string) bool { return k != nil && hmac.Equal([]byte(k.id), []byte(id)) }

func kekID(key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(kekIDLabel))
	return "kek-" + hex.EncodeToString(mac.Sum(nil))[:16]
}

func allZero(key []byte) bool {
	for _, b := range key {
		if b != 0 {
			return false
		}
	}
	return true
}

// InstallationKEK is the key encryption key together with the installation
// whose rows it may seal and open.
//
// Sealing lives here and not on KEK so that the binding cannot be forgotten:
// a key read from a file opens nothing until somebody has said which
// installation it belongs to, and the compiler asks at every call site.
type InstallationKEK struct {
	*KEK
	installation string
}

// For binds the key to an installation. It is the only way to a key that
// seals, and the identifier it is given is meant to come from the
// installation record, never from a flag or a guess.
func (k *KEK) For(installationID string) *InstallationKEK {
	return &InstallationKEK{KEK: k, installation: installationID}
}

// Installation names the installation this key seals for.
func (k *InstallationKEK) Installation() string { return k.installation }
