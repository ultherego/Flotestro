package identitystore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
)

// Key is the private key of a fleet identity.
//
// An interface rather than bytes, because a key cannot always be exported.
// Today the agent generates it in software and writes it as PEM; in the
// hardware profile the key comes into being inside a TPM and never leaves it
// - only a handle then goes to disk. The generation store must assume neither
// of those, because such an assumption would travel from here into the
// enrollment and into the renewal.
type Key interface {
	// Public returns the public key. That is enough to build a certificate
	// request and to check that a certificate matches the key.
	Public() crypto.PublicKey
	// Signer signs requests and the TLS handshake without giving out the
	// material.
	Signer() crypto.Signer
	// Save persists the key in a generation directory.
	Save(dir string) error
}

// KeySource creates and loads identity keys.
//
// The source is replaceable: a hardware profile replaces it in full, and the
// rest of the agent does not change at all.
type KeySource interface {
	New() (Key, error)
	Load(dir string) (Key, error)
}

// ErrKeyNotExportable means a key that cannot be exported. It is not an error
// in itself: that is exactly how a hardware key behaves.
var ErrKeyNotExportable = errors.New("key_not_exportable")

// Software returns the source of a key kept in a file.
//
// The default and the only one today. The name says outright that the key is
// in software, so that a hardware profile does not have to be called "the
// other one".
func Software() KeySource { return softwareSource{} }

type softwareSource struct{}

func (softwareSource) New() (Key, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &softwareKey{key: key}, nil
}

func (softwareSource) Load(dir string) (Key, error) {
	content, err := os.ReadFile(filepath.Join(dir, KeyName))
	if err != nil {
		return nil, err
	}
	return KeyFromPEM(content)
}

// KeyFromPEM reads a key written as PEM.
func KeyFromPEM(keyPEM []byte) (Key, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("%w: no PEM block", ErrKeyPair)
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return &softwareKey{key: key, pem: keyPEM}, nil
	}
	private, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyPair, err)
	}
	signer, ok := private.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("%w: the key cannot sign", ErrKeyPair)
	}
	return &softwareKey{key: signer, pem: keyPEM}, nil
}

// softwareKey keeps the key in the process's memory and writes it to a file.
type softwareKey struct {
	key crypto.Signer
	pem []byte
}

func (k *softwareKey) Public() crypto.PublicKey { return k.key.Public() }
func (k *softwareKey) Signer() crypto.Signer    { return k.key }

func (k *softwareKey) Save(dir string) error {
	content, err := k.materialPEM()
	if err != nil {
		return err
	}
	// The key is readable by its owner alone. The certificate and the bundle
	// are not secret, but this file is the host's whole identity.
	return writeWithSync(filepath.Join(dir, KeyName), content, 0o600)
}

func (k *softwareKey) materialPEM() ([]byte, error) {
	if len(k.pem) > 0 {
		return k.pem, nil
	}
	private, ok := k.key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: unsupported kind of key", ErrKeyPair)
	}
	der, err := x509.MarshalECPrivateKey(private)
	if err != nil {
		return nil, err
	}
	k.pem = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	return k.pem, nil
}

// Request builds a CSR signed with the given key.
//
// The subject and the names are a hint: the panel grants the identity on the
// strength of a token or of the current certificate rather than on what the
// host writes about itself. The exception is a relay's network names, which
// the panel takes from the request at the first registration - because they
// are not in the registry yet.
func Request(key Key, name string, dns []string, addresses []net.IP) ([]byte, error) {
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: name},
		DNSNames:    dns,
		IPAddresses: addresses,
	}, key.Signer())
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}
