package helpercap

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
)

// NonceSize is the length of a capability nonce.
const NonceSize = 32

// Signer holds the control plane's capability key.
type Signer struct {
	key    ed25519.PrivateKey
	public ed25519.PublicKey
	keyID  string
	// previous is the key retired by a rotation, kept for the overlap: the hosts
	// trust it, so the bundle that introduces the new key is signed with it.
	previous *Signer
}

// LoadOrGenerateSigner reads the signing key from a file, generating one when
// the file is missing.
func LoadOrGenerateSigner(path string) (*Signer, bool, error) {
	signer, err := loadSigner(path)
	created := false
	switch {
	case err == nil:
	case errors.Is(err, os.ErrNotExist):
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, false, err
		}
		if err := writeKey(path, private); err != nil {
			return nil, false, err
		}
		signer = &Signer{key: private, public: public, keyID: KeyID(public)}
		created = true
	default:
		return nil, false, err
	}
	previousPath := previousKeyPath(path)
	previous, err := loadSigner(previousPath)
	switch {
	case err == nil:
		if previous.keyID != signer.keyID {
			signer.previous = previous
		}
	case errors.Is(err, os.ErrNotExist):
	default:
		return nil, false, fmt.Errorf("the retired signing key %s: %w", previousPath, err)
	}
	return signer, created, nil
}

// previousKeyPath names the retired key beside the active one:
// helper-signing.key goes with helper-signing-previous.key.
func previousKeyPath(path string) string {
	ext := filepath.Ext(path)
	return path[:len(path)-len(ext)] + "-previous" + ext
}

func loadSigner(path string) (*Signer, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("%s: not a PEM private key", path)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	private, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: not an Ed25519 key", path)
	}
	public := private.Public().(ed25519.PublicKey)
	return &Signer{key: private, public: public, keyID: KeyID(public)}, nil
}

func writeKey(path string, private ed25519.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	// The file is created with the final mode and never widened: a key readable
	// by another user of the panel host is a key that user can mint root
	// operations with.
	temporary := path + ".new"
	if err := os.WriteFile(temporary, encoded, 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

// NewSignerFromKey wraps a key held in memory; the tests and the simulator
// use it.
func NewSignerFromKey(private ed25519.PrivateKey) *Signer {
	public := private.Public().(ed25519.PublicKey)
	return &Signer{key: private, public: public, keyID: KeyID(public)}
}

// KeyID names the active key.
func (s *Signer) KeyID() string { return s.keyID }

// PublicKey is the active public key.
func (s *Signer) PublicKey() ed25519.PublicKey { return s.public }

// TrustedKeys lists the public keys a host is to trust: the active key
// and, during a rotation, the retired one.
func (s *Signer) TrustedKeys() []*helperv1.HelperTrustKey {
	keys := []*helperv1.HelperTrustKey{{KeyId: s.keyID, PublicKey: append([]byte(nil), s.public...)}}
	if s.previous != nil {
		keys = append(keys, &helperv1.HelperTrustKey{
			KeyId: s.previous.keyID, PublicKey: append([]byte(nil), s.previous.public...)})
	}
	return keys
}

// Mint describes the capability to issue.
type Mint struct {
	HostID     string
	TaskID     string
	ActionType string
	// PayloadSHA256 is the digest of the canonical payload the capability
	// binds - what the helper will compute over the bytes it is handed.
	PayloadSHA256  []byte
	Grants         []string
	PolicyRevision uint64
	Now            time.Time
}

// Issue mints and signs a capability.
func (s *Signer) Issue(mint Mint) (*helperv1.HelperCapability, []byte, error) {
	if mint.HostID == "" || mint.TaskID == "" || mint.ActionType == "" {
		return nil, nil, errors.New("a capability needs a host, a task and an action")
	}
	if len(mint.PayloadSHA256) != 32 {
		return nil, nil, errors.New("a capability binds a 32-byte payload digest")
	}
	now := mint.Now
	if now.IsZero() {
		now = time.Now()
	}
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	capability := &helperv1.HelperCapability{
		SchemaVersion:  SchemaVersion,
		KeyId:          s.keyID,
		CapabilityId:   uuid.NewString(),
		HostId:         mint.HostID,
		TaskId:         mint.TaskID,
		ActionType:     mint.ActionType,
		PayloadSha256:  append([]byte(nil), mint.PayloadSHA256...),
		NotBeforeUnix:  now.Add(-ClockSkew).Unix(),
		ExpiresUnix:    now.Add(TTLOf(mint.ActionType)).Unix(),
		Nonce:          nonce,
		PolicyRevision: mint.PolicyRevision,
		Grants:         append([]string(nil), mint.Grants...),
	}
	return capability, Sign(s.key, capability), nil
}

// Fingerprints are the whole SHA-256 of the keys this panel signs a first
// bundle with: the current one, and the previous one while a rotation is still
// in the air. An operator pins these, not the short identifier.
func (s *Signer) Fingerprints() []string {
	out := []string{KeyFingerprint(s.public)}
	if s.previous != nil {
		out = append(out, KeyFingerprint(s.previous.public))
	}
	return out
}

// TrustBundle is the signed keyring for one host.
func (s *Signer) TrustBundle(hostID string, now time.Time) *helperv1.HelperTrustBundle {
	if now.IsZero() {
		now = time.Now()
	}
	bundle := &helperv1.HelperTrustBundle{
		HostId:     hostID,
		Keys:       s.TrustedKeys(),
		IssuedUnix: now.Unix(),
	}
	signer := s
	if s.previous != nil {
		signer = s.previous
	}
	bundle.SignedByKeyId = signer.keyID
	bundle.Signature = ed25519.Sign(signer.key, TrustBundleSigningBytes(bundle))
	return bundle
}

// trustPrefix separates bundle signatures from capability signatures.
const trustPrefix = "flotestro-helper-trust/1\n"

// TrustBundleSigningBytes is the deterministic byte form of a bundle
// without its signature.
func TrustBundleSigningBytes(bundle *helperv1.HelperTrustBundle) []byte {
	var out []byte
	out = append(out, trustPrefix...)
	out = appendBytes(out, []byte(bundle.GetHostId()))
	out = appendUint(out, uint64(bundle.GetIssuedUnix()))
	out = appendBytes(out, []byte(bundle.GetSignedByKeyId()))
	out = appendUint(out, uint64(len(bundle.GetKeys())))
	for _, key := range bundle.GetKeys() {
		out = appendBytes(out, []byte(key.GetKeyId()))
		out = appendBytes(out, key.GetPublicKey())
	}
	return out
}
