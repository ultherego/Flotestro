package cryptostate

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"

	"github.com/ultherego/flotestro/internal/secrets"
)

// DBProviderName is what the installation record calls the provider that keeps
// its keys in the database.
const DBProviderName = "db-sealed"

// DBSealedProvider serves the key encryption keys of the secret store from the
// database, each row wrapped with the key encryption key the deployment
// mounts.
//
// What it serves is what the local provider served from files, byte for byte:
// the same material under the same names, wrapped for the store the same way.
// A panel that moved its keys into the database opens the envelopes it wrote
// before it moved them, and a second replica of the same deployment opens them
// too - which is the whole point of the move.
type DBSealedProvider struct {
	store KeyStore
	kek   *KEK

	mu      sync.RWMutex
	active  string
	keys    map[string]*secrets.Cipher
	raw     map[string][]byte
	retired map[string]bool
}

// NewDBProvider reads the keys of the installation out of the database and
// opens them with the mounted key encryption key.
//
// Every row has to open. A provider that quietly served the keys it could read
// would look healthy until the one secret sealed under the unreadable key was
// asked for, which is exactly the moment nobody wants to learn it.
func NewDBProvider(ctx context.Context, store KeyStore, kek *KEK) (*DBSealedProvider, error) {
	if kek == nil {
		return nil, fatal(CodeKEKFileMissing, "the panel was given no key encryption key", nil)
	}
	p := &DBSealedProvider{store: store, kek: kek}
	p.keys = map[string]*secrets.Cipher{}
	p.raw = map[string][]byte{}
	p.retired = map[string]bool{}
	if err := p.Reload(ctx); err != nil {
		return nil, err
	}
	return p, nil
}

// Reload reads the keys again. Another replica of the same installation may
// have made a key since this one started, and a key that exists elsewhere is
// not a key that is missing.
func (p *DBSealedProvider) Reload(ctx context.Context) error {
	rows, err := p.store.WrappedKeys(ctx, PurposeSecrets)
	if err != nil {
		return fmt.Errorf("the keys of the installation: %w", err)
	}
	keys := map[string]*secrets.Cipher{}
	raw := map[string][]byte{}
	retired := map[string]bool{}
	for _, row := range rows {
		material, err := p.kek.Open(row)
		if err != nil {
			return err
		}
		cipher, err := secrets.NewCipher(material)
		if err != nil {
			return fatal(CodeWrappedKeyUnreadable, "the key "+row.KeyID+" opened into something that is not a key", err)
		}
		keys[row.KeyID] = cipher
		raw[row.KeyID] = material
		retired[row.KeyID] = row.Retired()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.keys, p.raw, p.retired = keys, raw, retired
	return nil
}

// Name implements Provider.
func (p *DBSealedProvider) Name() string { return DBProviderName }

// KEKID names the key encryption key the rows are wrapped with.
func (p *DBSealedProvider) KEKID() string { return p.kek.ID() }

// KeyIDs implements Provider.
func (p *DBSealedProvider) KeyIDs() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	ids := make([]string, 0, len(p.keys))
	for id := range p.keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// HasMaterial implements Provider.
func (p *DBSealedProvider) HasMaterial() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.keys) > 0
}

// RequireKey implements Provider. A key this instance has not seen is looked
// for once more before it is called missing: the row may have been written by
// another replica after this one read the table.
func (p *DBSealedProvider) RequireKey(ctx context.Context, id string) error {
	if p.holds(id) {
		return nil
	}
	if err := p.Reload(ctx); err != nil {
		return err
	}
	if p.holds(id) {
		return nil
	}
	return fmt.Errorf("%w: the key %s is not among the keys of this installation", secrets.ErrKeyUnavailable, id)
}

func (p *DBSealedProvider) holds(id string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	_, ok := p.keys[id]
	return ok
}

// SetActive implements Provider.
func (p *DBSealedProvider) SetActive(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.active = id
}

// ActiveKeyID implements secrets.KeyProvider. A retired key is refused here
// rather than at SetActive, which cannot answer: new material is not to be
// sealed under a key the installation has put out of use.
func (p *DBSealedProvider) ActiveKeyID(context.Context) (string, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.active == "" {
		return "", fmt.Errorf("%w: no active key", secrets.ErrKeyUnavailable)
	}
	if _, ok := p.keys[p.active]; !ok {
		return "", fmt.Errorf("%w: the active key %s is not loaded", secrets.ErrKeyUnavailable, p.active)
	}
	if p.retired[p.active] {
		return "", fmt.Errorf("%w: the active key %s is retired", secrets.ErrKeyUnavailable, p.active)
	}
	return p.active, nil
}

// Wrap implements secrets.KeyProvider. The wrapping is the local provider's,
// down to the label: the envelopes an installation wrote before it moved its
// keys into the database have to keep opening afterwards.
func (p *DBSealedProvider) Wrap(_ context.Context, id string, dek []byte) ([]byte, error) {
	cipher, ok := p.cipher(id)
	if !ok {
		return nil, fmt.Errorf("%w: %s", secrets.ErrKeyUnavailable, id)
	}
	nonce, ciphertext, err := cipher.Encrypt(dek, "kek:"+id, 0)
	if err != nil {
		return nil, err
	}
	return append(nonce, ciphertext...), nil
}

// Unwrap implements secrets.KeyProvider.
func (p *DBSealedProvider) Unwrap(_ context.Context, id string, wrapped []byte) ([]byte, error) {
	cipher, ok := p.cipher(id)
	if !ok {
		return nil, fmt.Errorf("%w: %s", secrets.ErrKeyUnavailable, id)
	}
	nonceSize := cipher.NonceSize()
	if len(wrapped) <= nonceSize {
		return nil, fmt.Errorf("the wrapped key under %s is too short", id)
	}
	dek, err := cipher.Decrypt(wrapped[:nonceSize], wrapped[nonceSize:], "kek:"+id, 0)
	if err != nil {
		return nil, fmt.Errorf("the wrapped key does not open under %s: %w", id, err)
	}
	return dek, nil
}

func (p *DBSealedProvider) cipher(id string) (*secrets.Cipher, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	cipher, ok := p.keys[id]
	return cipher, ok
}

// Health implements secrets.KeyProvider: the row of the active key is still
// there and still holds what this instance loaded.
//
// The local provider reads the file again at this point; here the row is read
// again, which also says that the database is answering. A key that changed
// under a running panel is the same accident in either place, and it is found
// here rather than at the next fetch.
func (p *DBSealedProvider) Health(ctx context.Context) error {
	id, err := p.ActiveKeyID(ctx)
	if err != nil {
		return err
	}
	row, err := p.store.WrappedKey(ctx, id)
	if errors.Is(err, ErrWrappedKeyMissing) {
		return fmt.Errorf("%w: the active key %s is no longer in the database", secrets.ErrKeyUnavailable, id)
	}
	if err != nil {
		return fmt.Errorf("%w: the active key %s: %v", secrets.ErrKeyUnavailable, id, err)
	}
	material, err := p.kek.Open(row)
	if err != nil {
		return fmt.Errorf("%w: the active key %s: %v", secrets.ErrKeyUnavailable, id, err)
	}
	p.mu.RLock()
	loaded := p.raw[id]
	p.mu.RUnlock()
	if subtle.ConstantTimeCompare(material, loaded) != 1 {
		return fmt.Errorf("%w: the row of the active key %s changed since it was loaded", secrets.ErrKeyUnavailable, id)
	}
	return nil
}

// LegacyCipher implements secrets.LegacyOpener.
func (p *DBSealedProvider) LegacyCipher() (*secrets.Cipher, bool) {
	return p.cipher(secrets.LegacyKeyID)
}

// Generate implements Provider.
func (p *DBSealedProvider) Generate(ctx context.Context) (string, error) {
	suffix := make([]byte, 6)
	if _, err := io.ReadFull(rand.Reader, suffix); err != nil {
		return "", err
	}
	id := "k-" + hex.EncodeToString(suffix)
	if err := p.GenerateNamed(ctx, id); err != nil {
		return "", err
	}
	return id, nil
}

// GenerateNamed implements Provider.
func (p *DBSealedProvider) GenerateNamed(ctx context.Context, id string) error {
	if err := ValidateKeyID(id); err != nil {
		return err
	}
	if p.holds(id) {
		return fmt.Errorf("the key %s already exists", id)
	}
	material := make([]byte, secrets.KeyLength)
	if _, err := io.ReadFull(rand.Reader, material); err != nil {
		return err
	}
	return p.write(ctx, id, material, false)
}

// Adopt implements Provider: material made elsewhere lands as a row under the
// given name. This is how the keys of the state directory become keys of the
// database.
func (p *DBSealedProvider) Adopt(ctx context.Context, id string, material []byte) error {
	if err := ValidateKeyID(id); err != nil {
		return err
	}
	return p.write(ctx, id, material, true)
}

// write seals the material and puts it in the database. A name already taken
// is not an error by itself: two replicas of one installation initialising at
// once make the same key under the same name, and a row that holds the same
// material is that, not a collision. Different material under a taken name is
// refused, whoever asked.
func (p *DBSealedProvider) write(ctx context.Context, id string, material []byte, adopting bool) error {
	p.mu.RLock()
	existing, held := p.raw[id]
	p.mu.RUnlock()
	if held {
		if subtle.ConstantTimeCompare(existing, material) != 1 {
			return fmt.Errorf("the key %s already exists with different material", id)
		}
		return nil
	}
	row, err := sealSecretsKey(p.kek, id, material)
	if err != nil {
		return err
	}
	switch err := p.store.PutWrappedKey(ctx, row); {
	case errors.Is(err, ErrKeyExists):
		// Somebody wrote the row between the check and the insert. Whether it is
		// the same key decides whether this is a race that ended well or two
		// different keys under one name.
		found, readErr := p.store.WrappedKey(ctx, id)
		if readErr != nil {
			return fmt.Errorf("the key %s exists and could not be read: %w", id, readErr)
		}
		theirs, openErr := p.kek.Open(found)
		if openErr != nil {
			return openErr
		}
		if subtle.ConstantTimeCompare(theirs, material) != 1 {
			return fmt.Errorf("the key %s already exists with different material", id)
		}
		if found.Purpose != PurposeSecrets {
			return fmt.Errorf("the name %s is taken by a key kept for %s", id, found.Purpose)
		}
		material = theirs
	case err != nil:
		if adopting {
			return fmt.Errorf("the key %s could not be adopted: %w", id, err)
		}
		return fmt.Errorf("the key %s could not be written: %w", id, err)
	}
	return p.remember(id, material, false)
}

// remember puts opened material into the maps.
func (p *DBSealedProvider) remember(id string, material []byte, retired bool) error {
	cipher, err := secrets.NewCipher(material)
	if err != nil {
		return fmt.Errorf("key %s: %w", id, err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.keys[id] = cipher
	p.raw[id] = append([]byte(nil), material...)
	p.retired[id] = retired
	return nil
}

// Retire puts a key out of use for new material without taking away what it
// opens.
func (p *DBSealedProvider) Retire(ctx context.Context, id string) error {
	if err := p.RequireKey(ctx, id); err != nil {
		return err
	}
	if err := p.store.RetireWrappedKey(ctx, id); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.retired[id] = true
	return nil
}

// Remove deletes a key that was made in this process and turned out not to be
// needed: the cleanup of an initialisation that could not record itself.
func (p *DBSealedProvider) Remove(ctx context.Context, id string) error {
	if err := p.store.DeleteWrappedKey(ctx, id); err != nil && !errors.Is(err, ErrWrappedKeyMissing) {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.keys, id)
	delete(p.raw, id)
	delete(p.retired, id)
	if p.active == id {
		p.active = ""
	}
	return nil
}
