package helpercap

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
)

// Keyring is the set of public keys whose capabilities the helper honours.
type Keyring struct {
	keys map[string]ed25519.PublicKey
}

// NewKeyring builds a keyring from keys held in memory.
func NewKeyring(keys ...ed25519.PublicKey) *Keyring {
	ring := &Keyring{keys: map[string]ed25519.PublicKey{}}
	for _, key := range keys {
		ring.keys[KeyID(key)] = key
	}
	return ring
}

// Lookup finds a key by its identifier.
func (k *Keyring) Lookup(keyID string) (ed25519.PublicKey, bool) {
	if k == nil {
		return nil, false
	}
	key, ok := k.keys[keyID]
	return key, ok
}

// IDs lists the identifiers, sorted.
func (k *Keyring) IDs() []string {
	if k == nil {
		return nil
	}
	ids := make([]string, 0, len(k.keys))
	for id := range k.keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// Empty says whether the keyring holds no key at all.
func (k *Keyring) Empty() bool { return k == nil || len(k.keys) == 0 }

// The stable codes of a refused trust update.
const (
	ErrorTrustInvalid   = "trust_bundle_invalid"
	ErrorTrustUntrusted = "trust_bundle_untrusted"
)

// TrustStore is the root-owned keyring and host identity on a host.
//
// The keys are files named <key_id>.pub in the directory, PEM public keys.
// The identifier is derived from the key, never read from the name, so a
// file cannot claim another key's identity. The host identifier is one
// line in its own file. Both belong to root; the agent's user cannot write
// them, so a compromised agent cannot make the helper trust a key of its
// own.
type TrustStore struct {
	// Dir holds the key files. A missing directory is an empty keyring.
	Dir string
	// HostIDPath is the file with the host identifier.
	HostIDPath string
	// RequireRoot refuses key files not owned by root or writable by
	// anybody else. Off only in tests, which do not run as root.
	RequireRoot bool
}

// DefaultTrustDir and DefaultHostIDPath are where a packaged helper keeps
// its trust.
const (
	DefaultTrustDir   = "/etc/flotestro/helper-trust.d"
	DefaultHostIDPath = "/var/lib/flotestro-helper/host-id"
)

// Keyring loads the keys. A file that is not a usable root-owned key is
// skipped and named in the second value: an unusable key must not stop
// the helper from honouring the usable ones, and must not be honoured
// either.
func (t TrustStore) Keyring() (*Keyring, []string, error) {
	entries, err := os.ReadDir(t.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return NewKeyring(), nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	// The directory has to be root's as much as the files: a directory
	// another user can write to is a directory that user can empty, and an
	// emptied keyring must not become an opening. Such a directory is an
	// error, not an empty keyring - every capability is refused until the
	// operator fixes the ownership.
	if t.RequireRoot {
		info, err := os.Stat(t.Dir)
		if err != nil {
			return nil, nil, err
		}
		if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Uid != 0 {
			return nil, nil, fmt.Errorf("the trust directory %s is owned by uid %d, not by root", t.Dir, stat.Uid)
		}
		if info.Mode().Perm()&0o022 != 0 {
			return nil, nil, fmt.Errorf("the trust directory %s is writable by others (mode %04o)", t.Dir, info.Mode().Perm())
		}
	}
	ring := NewKeyring()
	var skipped []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".pub") {
			continue
		}
		path := filepath.Join(t.Dir, entry.Name())
		key, err := t.readKey(path)
		if err != nil {
			skipped = append(skipped, fmt.Sprintf("%s: %v", entry.Name(), err))
			continue
		}
		ring.keys[KeyID(key)] = key
	}
	return ring, skipped, nil
}

func (t TrustStore) readKey(path string) (ed25519.PublicKey, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("a symbolic link is not a key")
	}
	if t.RequireRoot {
		if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Uid != 0 {
			return nil, fmt.Errorf("owned by uid %d, not by root", stat.Uid)
		}
		if info.Mode().Perm()&0o022 != 0 {
			return nil, fmt.Errorf("writable by others (mode %04o)", info.Mode().Perm())
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePublicKeyPEM(raw)
}

// ParsePublicKeyPEM reads a PEM "PUBLIC KEY" block holding an Ed25519 key.
func ParsePublicKeyPEM(raw []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("not a PEM public key")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("not an Ed25519 key")
	}
	return key, nil
}

// EncodePublicKeyPEM writes a key as a PEM "PUBLIC KEY" block.
func EncodePublicKeyPEM(key ed25519.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// HostID reads the host identifier. An empty string means the host has
// none yet.
func (t TrustStore) HostID() (string, error) {
	raw, err := os.ReadFile(t.HostIDPath)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

// TrustUpdate is what an applied bundle left behind.
type TrustUpdate struct {
	HostID  string
	KeyIDs  []string
	Changed bool
	// Bootstrap says the bundle was taken on trust because the keyring
	// was empty - the enrollment of the host.
	Bootstrap bool
}

// Apply replaces the keyring and the host identity with a bundle.
//
// The bundle has to be signed by a key the helper already trusts. The one
// exception is a host with neither a keyring nor an identity: at
// enrollment there is nothing to verify against, so the first bundle is
// taken on trust, verified against a key it carries itself so at least a
// damaged bundle is refused. From then on only the panel that signed the
// first bundle can change the keys or the host identity - a rotation lists
// the new key in a bundle signed by the old one. A key missing from the
// bundle is removed: that is how a retired key stops being honoured. A
// host with an identity but no keys is not taken back on trust: its keys
// went away without the panel, and the operator restores them by hand
// (a key file in the trust directory, or the identity file removed).
func (t TrustStore) Apply(bundle *helperv1.HelperTrustBundle) (*TrustUpdate, error) {
	keys, err := checkBundle(bundle)
	if err != nil {
		return nil, err
	}
	current, _, err := t.Keyring()
	if err != nil {
		return nil, err
	}
	currentHost, err := t.HostID()
	if err != nil {
		return nil, err
	}

	bootstrap := current.Empty() && currentHost == ""
	if current.Empty() && currentHost != "" {
		return nil, refusal(ErrorTrustUntrusted,
			fmt.Sprintf("the host %s has an identity but no trusted key; restore the keyring by hand", currentHost))
	}
	signer, trusted := current.Lookup(bundle.GetSignedByKeyId())
	if bootstrap {
		signer, trusted = keys[bundle.GetSignedByKeyId()]
	}
	if !trusted {
		return nil, refusal(ErrorTrustUntrusted,
			fmt.Sprintf("the bundle is signed by %s, which the helper does not trust", bundle.GetSignedByKeyId()))
	}
	if !ed25519.Verify(signer, TrustBundleSigningBytes(bundle), bundle.GetSignature()) {
		return nil, refusal(ErrorTrustUntrusted, "the signature of the bundle does not verify")
	}

	changed := false
	if currentHost != bundle.GetHostId() {
		if err := writeRootFile(t.HostIDPath, []byte(bundle.GetHostId()+"\n"), 0o600); err != nil {
			return nil, err
		}
		changed = true
	}
	if err := os.MkdirAll(t.Dir, 0o755); err != nil {
		return nil, err
	}
	for id, key := range keys {
		encoded, err := EncodePublicKeyPEM(key)
		if err != nil {
			return nil, err
		}
		path := filepath.Join(t.Dir, id+".pub")
		if existing, err := os.ReadFile(path); err == nil && bytes.Equal(existing, encoded) {
			continue
		}
		if err := writeRootFile(path, encoded, 0o644); err != nil {
			return nil, err
		}
		changed = true
	}
	for _, id := range current.IDs() {
		if _, kept := keys[id]; kept {
			continue
		}
		if err := os.Remove(filepath.Join(t.Dir, id+".pub")); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		changed = true
	}
	ids := make([]string, 0, len(keys))
	for id := range keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return &TrustUpdate{HostID: bundle.GetHostId(), KeyIDs: ids, Changed: changed, Bootstrap: bootstrap}, nil
}

// Reset forgets the host identity and every trusted key, so the next
// bundle is taken on trust again. It is the decision a root operator
// takes when the host is enrolled afresh: the agent's identity is gone,
// the panel that signed the old bundle may be gone with it, and what the
// helper trusted belonged to that identity. Nothing but root can do it -
// the files belong to root - and a failure leaves what is there.
func (t TrustStore) Reset() error {
	if err := os.Remove(t.HostIDPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	entries, err := os.ReadDir(t.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Type().IsRegular() && strings.HasSuffix(entry.Name(), ".pub") {
			if err := os.Remove(filepath.Join(t.Dir, entry.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	return nil
}

// checkBundle reads the keys of a bundle and refuses a malformed one.
func checkBundle(bundle *helperv1.HelperTrustBundle) (map[string]ed25519.PublicKey, error) {
	if bundle == nil || bundle.GetHostId() == "" {
		return nil, refusal(ErrorTrustInvalid, "the bundle names no host")
	}
	if len(bundle.GetKeys()) == 0 {
		return nil, refusal(ErrorTrustInvalid, "the bundle carries no key")
	}
	if len(bundle.GetSignature()) != ed25519.SignatureSize {
		return nil, refusal(ErrorTrustInvalid, "the bundle carries no signature")
	}
	keys := map[string]ed25519.PublicKey{}
	for _, key := range bundle.GetKeys() {
		if len(key.GetPublicKey()) != ed25519.PublicKeySize {
			return nil, refusal(ErrorTrustInvalid, "a key of the bundle is not an Ed25519 public key")
		}
		public := ed25519.PublicKey(append([]byte(nil), key.GetPublicKey()...))
		if KeyID(public) != key.GetKeyId() {
			return nil, refusal(ErrorTrustInvalid,
				fmt.Sprintf("the key %s is named after another key", key.GetKeyId()))
		}
		keys[key.GetKeyId()] = public
	}
	return keys, nil
}

// writeRootFile writes a file through a temporary name and a rename, with
// the final mode from the start.
func writeRootFile(path string, content []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	temporary := path + ".new"
	if err := os.WriteFile(temporary, content, mode); err != nil {
		return err
	}
	if err := os.Chmod(temporary, mode); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return os.Rename(temporary, path)
}
