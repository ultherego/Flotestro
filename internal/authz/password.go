package authz

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode"

	"golang.org/x/crypto/argon2"
)

// The password of an identity that signs in without an identity provider.
//
// Hashed with argon2id, which is what a password store should use when it
// has no hardware to lean on: memory-hard, so the attacker's graphics card
// is worth less than it looks. The parameters are written into the encoded
// hash, so raising the cost later does not strand the rows written under the
// old one - a verification reads the parameters of the row it is checking.

const (
	// The cost. 64 MiB and three passes is the middle of the OWASP guidance
	// and costs a panel about 50 ms per sign-in, which is the right order:
	// slow enough to matter in bulk, fast enough that nobody notices once.
	argonMemory  = 64 * 1024
	argonTime    = 3
	argonThreads = 4
	argonKeyLen  = 32
	argonSaltLen = 16

	// MinPasswordLength is the one rule worth having. Length beats a
	// character-class rule that teaches people to write Password1!.
	MinPasswordLength = 12
)

// ErrWeakPassword is a password the installation will not store, with the
// reason in the message: a refusal that does not say what is wrong is a
// refusal somebody works around by adding an exclamation mark.
var ErrWeakPassword = errors.New("the password is too easy to guess")

// HashPassword returns the encoded argon2id hash of a password.
func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword says whether the password matches the encoded hash.
//
// It answers false for a hash it cannot read rather than an error the caller
// might log and continue past: a row that cannot be parsed authenticates
// nobody.
func VerifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	// ["", "argon2id", "v=19", "m=...,t=...,p=...", salt, key]
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false
	}
	var memory uint32
	var times uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &times, &threads); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, times, memory, threads, uint32(len(want)))
	// Constant time: a comparison that stops at the first wrong byte tells
	// an attacker how much of the hash they have.
	return subtle.ConstantTimeCompare(got, want) == 1
}

// CheckPasswordPolicy refuses what should not be stored, and says why.
//
// Length, and the two shapes that defeat any length: the person's own name,
// and the handful of words every list starts with. There is no
// character-class rule on purpose - it teaches Password1! and nothing else.
func CheckPasswordPolicy(password, subject string) error {
	runes := []rune(password)
	if len(runes) < MinPasswordLength {
		return fmt.Errorf("%w: it needs at least %d characters and has %d",
			ErrWeakPassword, MinPasswordLength, len(runes))
	}
	if strings.TrimSpace(password) == "" {
		return fmt.Errorf("%w: it is only spaces", ErrWeakPassword)
	}
	lower := strings.ToLower(password)
	if subject != "" && strings.Contains(lower, strings.ToLower(subject)) {
		return fmt.Errorf("%w: it contains the name it signs in with", ErrWeakPassword)
	}
	for _, common := range commonPasswords {
		if strings.Contains(lower, common) {
			return fmt.Errorf("%w: it contains %q, which is on every list an attacker starts with",
				ErrWeakPassword, common)
		}
	}
	// One long run of the same character is length that costs nothing.
	if onlyRepeats(runes) {
		return fmt.Errorf("%w: it is one character repeated", ErrWeakPassword)
	}
	return nil
}

func onlyRepeats(runes []rune) bool {
	if len(runes) == 0 {
		return true
	}
	first := unicode.ToLower(runes[0])
	for _, one := range runes {
		if unicode.ToLower(one) != first {
			return false
		}
	}
	return true
}

// The words that make a long password a short one. Deliberately short: a
// list of ten thousand belongs in a file somebody maintains, and this is
// here to catch the handful that would otherwise pass the length rule.
var commonPasswords = []string{
	"password", "passw0rd", "123456789", "qwerty", "letmein", "welcome",
	"admin123", "administrator", "flotestro", "changeme", "iloveyou",
}
