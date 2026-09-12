package secrets

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testCipher(t *testing.T) *Cipher {
	t.Helper()
	path := filepath.Join(t.TempDir(), "key")
	cipher, created, err := OpenCipher(path)
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("the key existed before the first open")
	}
	return cipher
}

// The key lies in a file outside the database: it, and not a column, decides
// whether anything can be read out of the ciphertext.
func TestTheKeyLivesInAFileAndComesBackTheSame(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	first, created, err := OpenCipher(path)
	if err != nil || !created {
		t.Fatalf("first open: %v, created=%v", err, created)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// A key readable by everyone is not a key.
	if info.Mode().Perm() != 0o600 {
		t.Errorf("permissions of the key file = %v", info.Mode().Perm())
	}

	nonce, ciphertext, err := first.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	second, created, err := OpenCipher(path)
	if err != nil || created {
		t.Fatalf("second open: %v, created=%v", err, created)
	}
	value, err := second.Decrypt(nonce, ciphertext)
	if err != nil || string(value) != "secret" {
		t.Fatalf("decryption: %q, %v", value, err)
	}
}

// A ciphertext without the key is useless - and that is the point of the
// whole store.
func TestACiphertextDoesNotOpenWithAnotherKey(t *testing.T) {
	first := testCipher(t)
	second := testCipher(t)

	nonce, ciphertext, err := first.Encrypt([]byte("private key"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := second.Decrypt(nonce, ciphertext); err == nil {
		t.Fatal("somebody else's key decrypted the value")
	}
	// The same text encrypted twice gives different ciphertexts: otherwise it
	// would be possible to tell that two secrets have the same value.
	_, secondCiphertext, err := first.Encrypt([]byte("private key"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(ciphertext, secondCiphertext) {
		t.Error("encrypting the same value twice gave the same ciphertext")
	}
}

func TestTheNameAndTheValueHaveBoundaries(t *testing.T) {
	valid := []string{"repo.token", "backup-password", "ca_key1"}
	for _, name := range valid {
		if err := ValidateName(name); err != nil {
			t.Errorf("the name %q was rejected: %v", name, err)
		}
	}
	invalid := []string{"", "A", "big.LETTERS", "with a space", "path/in/the/name", "-leading"}
	for _, name := range invalid {
		if err := ValidateName(name); err == nil {
			t.Errorf("the name %q passed validation", name)
		}
	}

	if err := ValidateValue(nil); err == nil {
		t.Error("a secret without a value passed validation")
	}
	if err := ValidateValue(make([]byte, MaxValue+1)); err == nil {
		t.Error("a value above the limit passed validation")
	}
	if err := ValidateValue([]byte("x")); err != nil {
		t.Errorf("a one-byte value was rejected: %v", err)
	}
}

// A lease is single-use and short: it, rather than the host's identity alone,
// entitles a fetch of the value.
func TestALeaseIsSingleUseAndShort(t *testing.T) {
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	lease := Lease{IssuedAt: now, ExpiresAt: now.Add(LeaseWindow)}

	if !lease.Valid(now.Add(time.Minute)) {
		t.Error("a fresh lease was treated as invalid")
	}
	if lease.Valid(now.Add(LeaseWindow + time.Second)) {
		t.Error("an expired lease was treated as valid")
	}

	used := lease
	moment := now.Add(time.Minute)
	used.RedeemedAt = &moment
	if used.Valid(now.Add(2 * time.Minute)) {
		t.Error("a used lease was treated as valid")
	}

	revoked := lease
	revoked.RevokedAt = &moment
	if revoked.Valid(now.Add(2 * time.Minute)) {
		t.Error("a revoked lease was treated as valid")
	}
}

// A secret without a version or a retired one is not a secret to issue.
func TestWhetherASecretIsIssuable(t *testing.T) {
	if (Secret{CurrentVersion: 0}).Issuable() {
		t.Error("a secret without a version was treated as issuable")
	}
	moment := time.Now()
	if (Secret{CurrentVersion: 2, RetiredAt: &moment}).Issuable() {
		t.Error("a retired secret was treated as issuable")
	}
	if !(Secret{CurrentVersion: 2}).Issuable() {
		t.Error("a secret with a version was treated as not issuable")
	}
}
