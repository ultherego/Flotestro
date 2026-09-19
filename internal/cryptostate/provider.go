// Package cryptostate guards the cryptographic identity of an installation:
// the key encryption keys of the secret store and the fleet CA, and the record
// in the database that says which of them this installation is.
package cryptostate

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/ultherego/flotestro/internal/secrets"
)

// LocalProviderName is what the installation record calls the built-in
// provider.
const LocalProviderName = "local-sealed"

// KeysDir is the directory of the key encryption keys under the state
// directory.
const KeysDir = "keys"

// keyFileSuffix ends the name of every key file: keys/<key-id>.key.
const keyFileSuffix = ".key"

// keyID bounds the names of keys: they go into file names and into the
// database, so they are short and plain.
var keyID = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// ValidateKeyID checks the name of a key.
func ValidateKeyID(id string) error {
	if !keyID.MatchString(id) {
		return fmt.Errorf("key id %q: lowercase letters, digits and dashes are allowed (1-63 characters)", id)
	}
	return nil
}

// Provider is what the startup guard needs from a key provider on top of what
// the store needs: to know what material is there, to create and adopt keys
// during initialisation, and to name itself in the record.
type Provider interface {
	secrets.KeyProvider
	// Name is the provider's name in the installation record.
	Name() string
	// KeyIDs lists the keys the provider holds.
	KeyIDs() []string
	// HasMaterial says whether the provider holds any key at all.
	HasMaterial() bool
	// RequireKey checks that the named key is there and readable.
	RequireKey(ctx context.Context, id string) error
	// Generate creates a new key under a fresh name and returns the name.
	Generate(ctx context.Context) (string, error)
	// GenerateNamed creates a new key under the given name. It refuses a
	// name that exists.
	GenerateNamed(ctx context.Context, id string) error
	// Adopt registers existing material under a name.
	Adopt(ctx context.Context, id string, key []byte) error
	// SetActive names the key new envelopes are wrapped with.
	SetActive(id string)
}

// LocalSealedProvider keeps the key encryption keys as files of the state
// directory: keys/<key-id>.
type LocalSealedProvider struct {
	dir string
	// credential names the systemd credential that holds a key, as
	// "<key-id>": the file $CREDENTIALS_DIRECTORY/<key-id> is the key.
	credential string

	mu     sync.RWMutex
	active string
	keys   map[string]*secrets.Cipher
	raw    map[string][]byte
	// readOnly marks the keys that came from a credential: they are not
	// files of the directory and are not written or removed.
	readOnly map[string]bool
}

// NewLocalProvider reads the keys of the directory and, when named, the
// systemd credential.
func NewLocalProvider(dir, credential string) (*LocalSealedProvider, error) {
	p := &LocalSealedProvider{
		dir: dir, credential: credential,
		keys: map[string]*secrets.Cipher{}, raw: map[string][]byte{}, readOnly: map[string]bool{},
	}
	entries, err := os.ReadDir(dir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("the keys directory: %w", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, keyFileSuffix) {
			continue
		}
		id := strings.TrimSuffix(name, keyFileSuffix)
		if err := ValidateKeyID(id); err != nil {
			// A file with a name that cannot be a key id is not a key of this provider
			// - a temporary file of an interrupted write, or something put there by
			// hand.
			continue
		}
		key, err := secrets.ReadKeyFile(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("key %s: %w", id, err)
		}
		if err := p.register(id, key, false); err != nil {
			return nil, err
		}
	}
	if credential != "" {
		if err := ValidateKeyID(credential); err != nil {
			return nil, fmt.Errorf("FLOTESTRO_SECRETS_KEY_CREDENTIAL: %w", err)
		}
		root := os.Getenv("CREDENTIALS_DIRECTORY")
		if root == "" {
			return nil, fmt.Errorf("FLOTESTRO_SECRETS_KEY_CREDENTIAL names %s, but systemd passed no credentials directory", credential)
		}
		key, err := secrets.ReadKeyFile(filepath.Join(root, credential))
		if err != nil {
			return nil, fmt.Errorf("credential %s: %w", credential, err)
		}
		if err := p.register(credential, key, true); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// register puts a key into the map, refusing different material under a
// name already taken.
func (p *LocalSealedProvider) register(id string, key []byte, readOnly bool) error {
	cipher, err := secrets.NewCipher(key)
	if err != nil {
		return fmt.Errorf("key %s: %w", id, err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if existing, ok := p.raw[id]; ok {
		if string(existing) != string(key) {
			return fmt.Errorf("key %s exists twice with different material", id)
		}
		return nil
	}
	p.keys[id] = cipher
	p.raw[id] = append([]byte(nil), key...)
	if readOnly {
		p.readOnly[id] = true
	}
	return nil
}

// Name implements Provider.
func (p *LocalSealedProvider) Name() string { return LocalProviderName }

// Dir returns the directory the keys live in.
func (p *LocalSealedProvider) Dir() string { return p.dir }

// KeyIDs implements Provider.
func (p *LocalSealedProvider) KeyIDs() []string {
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
func (p *LocalSealedProvider) HasMaterial() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.keys) > 0
}

// RequireKey implements Provider.
func (p *LocalSealedProvider) RequireKey(_ context.Context, id string) error {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if _, ok := p.keys[id]; !ok {
		return fmt.Errorf("%w: the key %s is not in %s and not a credential", secrets.ErrKeyUnavailable, id, p.dir)
	}
	return nil
}

// SetActive implements Provider.
func (p *LocalSealedProvider) SetActive(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.active = id
}

// ActiveKeyID implements secrets.KeyProvider.
func (p *LocalSealedProvider) ActiveKeyID(context.Context) (string, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.active == "" {
		return "", fmt.Errorf("%w: no active key", secrets.ErrKeyUnavailable)
	}
	if _, ok := p.keys[p.active]; !ok {
		return "", fmt.Errorf("%w: the active key %s is not loaded", secrets.ErrKeyUnavailable, p.active)
	}
	return p.active, nil
}

// Wrap implements secrets.
func (p *LocalSealedProvider) Wrap(_ context.Context, id string, dek []byte) ([]byte, error) {
	p.mu.RLock()
	cipher, ok := p.keys[id]
	p.mu.RUnlock()
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
func (p *LocalSealedProvider) Unwrap(_ context.Context, id string, wrapped []byte) ([]byte, error) {
	p.mu.RLock()
	cipher, ok := p.keys[id]
	p.mu.RUnlock()
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

// Health implements secrets. KeyProvider: the active key is named and its file
// is still there and unchanged.
func (p *LocalSealedProvider) Health(ctx context.Context) error {
	id, err := p.ActiveKeyID(ctx)
	if err != nil {
		return err
	}
	p.mu.RLock()
	readOnly := p.readOnly[id]
	loaded := p.raw[id]
	p.mu.RUnlock()
	if readOnly {
		return nil
	}
	onDisk, err := secrets.ReadKeyFile(p.path(id))
	if err != nil {
		return fmt.Errorf("%w: the active key %s: %v", secrets.ErrKeyUnavailable, id, err)
	}
	if string(onDisk) != string(loaded) {
		return fmt.Errorf("%w: the file of the active key %s changed since it was loaded", secrets.ErrKeyUnavailable, id)
	}
	return nil
}

// LegacyCipher implements secrets.LegacyOpener: the key adopted from
// before the envelope opens the rows of the first form directly.
func (p *LocalSealedProvider) LegacyCipher() (*secrets.Cipher, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	cipher, ok := p.keys[secrets.LegacyKeyID]
	return cipher, ok
}

// Generate implements Provider.
func (p *LocalSealedProvider) Generate(ctx context.Context) (string, error) {
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
func (p *LocalSealedProvider) GenerateNamed(_ context.Context, id string) error {
	if err := ValidateKeyID(id); err != nil {
		return err
	}
	if err := p.RequireKey(context.Background(), id); err == nil {
		return fmt.Errorf("the key %s already exists", id)
	}
	// A file that appeared since the directory was read is another panel of the
	// same installation making the same key; it is taken as is rather than
	// replaced.
	if onDisk, err := secrets.ReadKeyFile(p.path(id)); err == nil {
		return p.register(id, onDisk, false)
	} else if !errors.Is(err, secrets.ErrKeyMissing) {
		return err
	}
	key := make([]byte, secrets.KeyLength)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return err
	}
	if err := secrets.WriteKeyFile(p.path(id), key); err != nil {
		return err
	}
	return p.register(id, key, false)
}

// Adopt implements Provider: the material lands as a file of the
// directory under the given name, unless it is already there and the same.
func (p *LocalSealedProvider) Adopt(_ context.Context, id string, key []byte) error {
	if err := ValidateKeyID(id); err != nil {
		return err
	}
	p.mu.RLock()
	existing, ok := p.raw[id]
	p.mu.RUnlock()
	if ok {
		if string(existing) != string(key) {
			return fmt.Errorf("the key %s already exists with different material", id)
		}
		return nil
	}
	// A file that appeared since the directory was read - another panel of the
	// same installation adopting the same key on a shared state directory - is
	// accepted when it holds the same material.
	if onDisk, err := secrets.ReadKeyFile(p.path(id)); err == nil {
		if string(onDisk) != string(key) {
			return fmt.Errorf("the key file %s already exists with different material", p.path(id))
		}
		return p.register(id, key, false)
	} else if !errors.Is(err, secrets.ErrKeyMissing) {
		return err
	}
	if err := secrets.WriteKeyFile(p.path(id), key); err != nil {
		return err
	}
	return p.register(id, key, false)
}

// Remove deletes a key file that was created in this process and turned out
// not to be needed: the cleanup of an initialisation that could not record
// itself.
func (p *LocalSealedProvider) Remove(id string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.readOnly[id] {
		return nil
	}
	delete(p.keys, id)
	delete(p.raw, id)
	if p.active == id {
		p.active = ""
	}
	if err := os.Remove(p.path(id)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (p *LocalSealedProvider) path(id string) string {
	return filepath.Join(p.dir, id+keyFileSuffix)
}
