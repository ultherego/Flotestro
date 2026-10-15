package authz

import (
	"errors"
	"strings"
	"testing"
)

// A password store is worth exactly what its verification is worth, so both
// sides are checked here: that the right password opens the door, and the
// four shapes of wrong one that a careless implementation lets through.
func TestAPasswordOpensOnlyItsOwnHash(t *testing.T) {
	hash, err := HashPassword("a long enough passphrase")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Fatalf("the hash does not say what made it: %s", hash)
	}
	if strings.Contains(hash, "a long enough passphrase") {
		t.Fatal("the hash carries the password")
	}
	if !VerifyPassword(hash, "a long enough passphrase") {
		t.Error("the password does not open its own hash")
	}
	for _, wrong := range []string{
		"", " ", "a long enough passphras", "a long enough passphrase ",
		"A long enough passphrase", "another long passphrase",
	} {
		if VerifyPassword(hash, wrong) {
			t.Errorf("the hash opened for %q", wrong)
		}
	}

	// Two hashes of one password differ: a store whose rows repeat has no
	// salt, and an attacker who cracks one row cracks every copy of it.
	second, err := HashPassword("a long enough passphrase")
	if err != nil {
		t.Fatal(err)
	}
	if second == hash {
		t.Error("two hashes of the same password are identical, so there is no salt")
	}
	if !VerifyPassword(second, "a long enough passphrase") {
		t.Error("the second hash does not open")
	}
}

// A row that cannot be read authenticates nobody. The opposite - treating an
// unreadable hash as a match, or as an error the caller logs and walks past -
// is how a corrupted row becomes a way in.
func TestAHashThatCannotBeReadOpensForNothing(t *testing.T) {
	for _, broken := range []string{
		"", "$", "not a hash", "$argon2id$", "$bcrypt$v=19$m=1,t=1,p=1$c2FsdA$aGFzaA",
		"$argon2id$v=18$m=65536,t=3,p=4$c2FsdA$aGFzaA",
		"$argon2id$v=19$m=65536,t=3,p=4$!!!$aGFzaA",
		"$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$!!!",
		"$argon2id$v=19$this is not parameters$c2FsdA$aGFzaA",
	} {
		if VerifyPassword(broken, "anything at all") {
			t.Errorf("a hash of %q opened", broken)
		}
		if VerifyPassword(broken, "") {
			t.Errorf("a hash of %q opened for an empty password", broken)
		}
	}
}

// The policy says what it refuses. A refusal that does not name the reason
// is one somebody answers by adding an exclamation mark.
func TestThePolicyRefusesWhatWouldNotSurviveAList(t *testing.T) {
	for _, one := range []struct {
		name     string
		password string
		subject  string
		says     string
	}{
		{"too short", "short", "ada", "at least 12"},
		{"the subject itself", "tszymanski-2026", "tszymanski", "the name it signs in with"},
		{"a word from every list", "my password is here", "ada", "password"},
		{"the product's own name", "flotestro-rules-ok", "ada", "flotestro"},
		{"one character", "aaaaaaaaaaaaaaa", "ada", "one character repeated"},
		{"only spaces", "              ", "ada", "only spaces"},
	} {
		t.Run(one.name, func(t *testing.T) {
			err := CheckPasswordPolicy(one.password, one.subject)
			if err == nil {
				t.Fatalf("%q was accepted", one.password)
			}
			if !errors.Is(err, ErrWeakPassword) {
				t.Errorf("the refusal is not a weak-password refusal: %v", err)
			}
			if !strings.Contains(err.Error(), one.says) {
				t.Errorf("the refusal does not say %q: %v", one.says, err)
			}
		})
	}

	// And what it accepts, so the rule is not simply "no".
	for _, good := range []string{
		"correct horse battery staple", "ZimnaHerbata2026!", "a passphrase of some length",
	} {
		if err := CheckPasswordPolicy(good, "tszymanski"); err != nil {
			t.Errorf("%q was refused: %v", good, err)
		}
	}
}
