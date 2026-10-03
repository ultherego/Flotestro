package secrets

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

// GCM panics on a nonce whose length is not its own, instead of refusing it.
// The nonce is a column of a table, so one damaged row would otherwise take
// the process down - and the rewrap that reads every row runs on a timer, so
// it would take it down again after every restart.
func TestANonceOfTheWrongLengthIsRefusedAndDoesNotPanic(t *testing.T) {
	cipher, err := NewCipher(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	nonce, ciphertext, err := cipher.Encrypt([]byte("value"), "db-root", 1)
	if err != nil {
		t.Fatal(err)
	}

	for _, damaged := range []struct {
		name  string
		nonce []byte
	}{
		{"empty", nil},
		{"one byte short", nonce[:len(nonce)-1]},
		{"one byte long", append(append([]byte(nil), nonce...), 0)},
		{"twice as long", append(append([]byte(nil), nonce...), nonce...)},
	} {
		t.Run(damaged.name, func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("a damaged nonce panicked instead of being refused: %v", recovered)
				}
			}()
			_, err := cipher.Decrypt(damaged.nonce, ciphertext, "db-root", 1)
			if !errors.Is(err, ErrCorruptedVersion) {
				t.Fatalf("err = %v, want ErrCorruptedVersion", err)
			}
		})
	}
}

// A ciphertext shorter than its own tag cannot be opened either, and that is
// a damaged row as much as a short nonce is.
func TestACiphertextShorterThanItsTagIsRefused(t *testing.T) {
	cipher, err := NewCipher(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	nonce, _, err := cipher.Encrypt([]byte("value"), "db-root", 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cipher.Decrypt(nonce, []byte{1, 2, 3}, "db-root", 1); !errors.Is(err, ErrCorruptedVersion) {
		t.Fatalf("err = %v, want ErrCorruptedVersion", err)
	}
}

// What is not damaged still opens: a check that refuses everything would pass
// the tests above and take the product with it.
func TestAVersionThatIsWholeStillOpens(t *testing.T) {
	cipher, err := NewCipher(bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	nonce, ciphertext, err := cipher.Encrypt([]byte("value"), "db-root", 4)
	if err != nil {
		t.Fatal(err)
	}
	value, err := cipher.Decrypt(nonce, ciphertext, "db-root", 4)
	if err != nil {
		t.Fatal(err)
	}
	if string(value) != "value" {
		t.Fatalf("value = %q, want %q", value, "value")
	}
}

// The envelope of the second form reads its nonce from the same column, so it
// needs the same answer.
func TestAnEnvelopeWithADamagedNonceIsRefused(t *testing.T) {
	keys := staticKeys{id: "k1", key: bytes.Repeat([]byte{5}, 32)}
	envelope, err := SealWith(context.Background(), keys, "k1", []byte("value"), []byte("db-root|1"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("a damaged envelope panicked instead of being refused: %v", recovered)
		}
	}()
	envelope.Nonce = envelope.Nonce[:len(envelope.Nonce)-1]
	if _, err := envelope.Open(context.Background(), keys, []byte("db-root|1")); !errors.Is(err, ErrCorruptedVersion) {
		t.Fatalf("err = %v, want ErrCorruptedVersion", err)
	}
}

// staticKeys is one key encryption key, enough to seal an envelope and open
// it again. The wrapping is the key itself over the data key: this test is
// about the shape of what is stored, not about the wrapping.
type staticKeys struct {
	id  string
	key []byte
}

func (s staticKeys) ActiveKeyID(context.Context) (string, error) { return s.id, nil }

func (s staticKeys) Wrap(_ context.Context, keyID string, dek []byte) ([]byte, error) {
	if keyID != s.id {
		return nil, ErrKeyUnavailable
	}
	return append([]byte(nil), dek...), nil
}

func (s staticKeys) Unwrap(_ context.Context, keyID string, wrapped []byte) ([]byte, error) {
	if keyID != s.id {
		return nil, ErrKeyUnavailable
	}
	return append([]byte(nil), wrapped...), nil
}

func (s staticKeys) Health(context.Context) error { return nil }
