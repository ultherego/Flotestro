package secrets

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"testing"
)

// memoryKeys is a provider that keeps its keys in memory: enough to test
// the envelope, which never sees a key encryption key anyway.
type memoryKeys struct {
	active string
	keys   map[string]*Cipher
}

func newMemoryKeys(t *testing.T, ids ...string) *memoryKeys {
	t.Helper()
	m := &memoryKeys{keys: map[string]*Cipher{}}
	for _, id := range ids {
		m.add(t, id)
	}
	m.active = ids[0]
	return m
}

func (m *memoryKeys) add(t *testing.T, id string) {
	t.Helper()
	key := make([]byte, KeyLength)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatal(err)
	}
	cipher, err := NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	m.keys[id] = cipher
}

func (m *memoryKeys) ActiveKeyID(context.Context) (string, error) { return m.active, nil }

func (m *memoryKeys) Wrap(_ context.Context, keyID string, dek []byte) ([]byte, error) {
	cipher, ok := m.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrKeyUnavailable, keyID)
	}
	nonce, ciphertext, err := cipher.Encrypt(dek, keyID, 0)
	if err != nil {
		return nil, err
	}
	return append(nonce, ciphertext...), nil
}

func (m *memoryKeys) Unwrap(_ context.Context, keyID string, wrapped []byte) ([]byte, error) {
	cipher, ok := m.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrKeyUnavailable, keyID)
	}
	size := cipher.aead.NonceSize()
	if len(wrapped) < size {
		return nil, errors.New("wrapped key too short")
	}
	return cipher.Decrypt(wrapped[:size], wrapped[size:], keyID, 0)
}

func (m *memoryKeys) Health(context.Context) error { return nil }

func (m *memoryKeys) LegacyCipher() (*Cipher, bool) {
	cipher, ok := m.keys[LegacyKeyID]
	return cipher, ok
}

// An envelope opens only in the row it was written for, and only with the
// key that wrapped its data key.
func TestAnEnvelopeIsBoundToItsRowAndItsKey(t *testing.T) {
	ctx := context.Background()
	keys := newMemoryKeys(t, "k-one", "k-two")
	associated := AssociatedData("secret-a", 3, "secret", EnvelopeVersion)

	envelope, err := Seal(ctx, keys, []byte("value"), associated)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.KeyID != "k-one" || envelope.Version != EnvelopeVersion {
		t.Fatalf("envelope = %+v", envelope)
	}
	if bytes.Contains(envelope.Ciphertext, []byte("value")) {
		t.Fatal("the value is in the clear")
	}
	value, err := envelope.Open(ctx, keys, associated)
	if err != nil || string(value) != "value" {
		t.Fatalf("open = %q, %v", value, err)
	}

	if _, err := envelope.Open(ctx, keys, AssociatedData("secret-b", 3, "secret", EnvelopeVersion)); err == nil {
		t.Error("the envelope opened under another secret")
	}
	if _, err := envelope.Open(ctx, keys, AssociatedData("secret-a", 4, "secret", EnvelopeVersion)); err == nil {
		t.Error("the envelope opened as another version")
	}
	if _, err := envelope.Open(ctx, keys, AssociatedData("secret-a", 3, "sentinel", EnvelopeVersion)); err == nil {
		t.Error("the envelope opened as another kind")
	}
	if _, err := envelope.Open(ctx, keys, AssociatedData("secret-a", 3, "secret", 1)); err == nil {
		t.Error("the envelope opened re-labelled as another form")
	}

	// A data key wrapped under one key does not unwrap under another,
	// even when the envelope claims so.
	forged := envelope
	forged.KeyID = "k-two"
	if _, err := forged.Open(ctx, keys, associated); err == nil {
		t.Error("the data key unwrapped under a key that did not wrap it")
	}
	// A key the provider does not hold is the key's error, not a
	// decryption failure: the operator has to look for the key, not for
	// a corrupted row.
	gone := envelope
	gone.KeyID = "k-gone"
	if _, err := gone.Open(ctx, keys, associated); !errors.Is(err, ErrKeyUnavailable) {
		t.Errorf("a missing key gave %v, want %v", err, ErrKeyUnavailable)
	}
}

// Every version gets a data key of its own: two seals of the same value
// share neither ciphertext nor wrapped key.
func TestEveryEnvelopeHasItsOwnDataKey(t *testing.T) {
	ctx := context.Background()
	keys := newMemoryKeys(t, "k-one")
	associated := AssociatedData("secret-a", 1, "secret", EnvelopeVersion)
	first, err := Seal(ctx, keys, []byte("same"), associated)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Seal(ctx, keys, []byte("same"), associated)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first.WrappedDEK, second.WrappedDEK) {
		t.Error("two envelopes share a data key")
	}
	if bytes.Equal(first.Ciphertext, second.Ciphertext) {
		t.Error("two envelopes of the same value share a ciphertext")
	}
}

// A rotation rewraps the data key alone: the value stays as sealed, opens
// under the new key and no longer under the old one once that is gone.
func TestARewrapMovesTheEnvelopeToAnotherKey(t *testing.T) {
	ctx := context.Background()
	keys := newMemoryKeys(t, "k-old", "k-new")
	associated := AssociatedData("secret-a", 1, "secret", EnvelopeVersion)
	sealed, err := Seal(ctx, keys, []byte("value"), associated)
	if err != nil {
		t.Fatal(err)
	}
	moved, err := sealed.Rewrap(ctx, keys, "k-new")
	if err != nil {
		t.Fatal(err)
	}
	if moved.KeyID != "k-new" {
		t.Fatalf("key after the rewrap = %s", moved.KeyID)
	}
	if !bytes.Equal(moved.Ciphertext, sealed.Ciphertext) || !bytes.Equal(moved.Nonce, sealed.Nonce) {
		t.Error("the rewrap touched the value")
	}
	// The old key goes; the moved envelope still opens.
	delete(keys.keys, "k-old")
	keys.active = "k-new"
	if value, err := moved.Open(ctx, keys, associated); err != nil || string(value) != "value" {
		t.Fatalf("after the rotation: %q, %v", value, err)
	}
	if _, err := sealed.Open(ctx, keys, associated); !errors.Is(err, ErrKeyUnavailable) {
		t.Errorf("the envelope on the removed key gave %v", err)
	}
}
