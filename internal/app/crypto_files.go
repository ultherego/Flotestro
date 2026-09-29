package app

import (
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ultherego/flotestro/internal/cryptostate"
	"github.com/ultherego/flotestro/internal/helpercap"
	"github.com/ultherego/flotestro/internal/pki"
	"github.com/ultherego/flotestro/internal/secrets"
)

// Where the keys of an installation lie while they are still files, and how
// each of them becomes a row and comes back again.
//
// The panel reads these files in four different packages, each with its own
// idea of what a key looks like. Gathering them is therefore done here, in one
// place, so that "everything the replicas need equally" is a list somebody can
// read rather than something spread over the code.

// preparedAtBlock carries the moment an authority was prepared, which is a
// file beside the key and not part of any of the PEM the subsystem writes.
// Keeping it in the bundle is what lets a prepared authority survive the move
// as the thing it is: prepared, and since when.
const preparedAtBlock = "FLOTESTRO PREPARED AT"

// helperKeyPrefix and helperPreviousPrefix name the rows of the helper's
// signer. The two keys are the same kind of thing in two roles, and nothing
// else records which is which, so the name says it.
const (
	helperKeyPrefix      = "helper-"
	helperPreviousPrefix = "helper-previous-"
)

// installationFiles is where the keys of this installation are read from.
type installationFiles struct {
	// StateDir holds the keys directory and the authorities.
	StateDir string
	// LegacyKeyPath is the one key of an installation from before the keys
	// were named. Empty means nowhere to look.
	LegacyKeyPath string
	// HelperKeyPath is the signer of the root helper's capabilities.
	HelperKeyPath string
}

func (f installationFiles) keysDir() string {
	return filepath.Join(f.StateDir, cryptostate.KeysDir)
}

// collect gathers every private key of the installation.
//
// Anything that is there and cannot be read stops the whole collection. A
// migration that quietly left one key behind would produce an installation
// that starts, serves, and then cannot renew a certificate or open one secret
// - the failure arriving weeks later, at the worst possible moment.
func (f installationFiles) collect() ([]cryptostate.Material, error) {
	var found []cryptostate.Material
	secretsKeys, err := f.collectSecretsKeys()
	if err != nil {
		return nil, err
	}
	found = append(found, secretsKeys...)

	authorities, err := f.collectAuthorities()
	if err != nil {
		return nil, err
	}
	found = append(found, authorities...)

	helper, err := f.collectHelperSigning()
	if err != nil {
		return nil, err
	}
	found = append(found, helper...)
	return found, nil
}

// collectSecretsKeys reads the keys the secret store seals its values with.
func (f installationFiles) collectSecretsKeys() ([]cryptostate.Material, error) {
	dir := f.keysDir()
	entries, err := os.ReadDir(dir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("the keys directory: %w", err)
	}
	var found []cryptostate.Material
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".key") {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		id := strings.TrimSuffix(name, ".key")
		if err := cryptostate.ValidateKeyID(id); err != nil {
			// A file whose name cannot be a key id is not a key of the provider
			// either: a temporary file of an interrupted write, or something put
			// there by hand. The provider ignores it, so this does too.
			continue
		}
		path := filepath.Join(dir, name)
		key, err := secrets.ReadKeyFile(path)
		if err != nil {
			return nil, fmt.Errorf("the key %s: %w", id, err)
		}
		found = append(found, cryptostate.Material{
			KeyID: id, Purpose: cryptostate.PurposeSecrets, Source: path, Bytes: key,
		})
	}
	if f.LegacyKeyPath == "" {
		return found, nil
	}
	legacy, err := secrets.ReadKeyFile(f.LegacyKeyPath)
	if errors.Is(err, secrets.ErrKeyMissing) {
		return found, nil
	}
	if err != nil {
		return nil, fmt.Errorf("the key of an installation from before the keys were named: %w", err)
	}
	for _, material := range found {
		if material.KeyID != secrets.LegacyKeyID {
			continue
		}
		// The same key under two paths is the ordinary state of an adopted
		// installation; two different keys under one name is not something a
		// migration may decide about.
		if string(material.Bytes) != string(legacy) {
			return nil, fmt.Errorf(
				"%s and %s both claim to be the key %q and hold different material",
				f.LegacyKeyPath, material.Source, secrets.LegacyKeyID)
		}
		return found, nil
	}
	return append(found, cryptostate.Material{
		KeyID: secrets.LegacyKeyID, Purpose: cryptostate.PurposeSecrets,
		Source: f.LegacyKeyPath, Bytes: legacy,
	}), nil
}

// collectAuthorities reads the private key of the fleet CA, and of the one
// prepared to take over when there is one. The certificate travels with the
// key: a replica that has the key and not the certificate can sign nothing
// anybody would accept.
func (f installationFiles) collectAuthorities() ([]cryptostate.Material, error) {
	var found []cryptostate.Material
	active, err := f.authority(pki.CAKeyFile, pki.CACertFile, "")
	if err != nil {
		return nil, err
	}
	if active == nil {
		return nil, fmt.Errorf("%s holds no fleet CA; there is no installation to move",
			filepath.Join(f.StateDir, pki.CACertFile))
	}
	found = append(found, *active)

	pending, err := f.authority(pki.PendingKeyFile, pki.PendingCertFile, pki.PreparedAtFile)
	if err != nil {
		return nil, err
	}
	if pending != nil {
		found = append(found, *pending)
	}
	return found, nil
}

// authority reads one CA as key, certificate and, for a prepared one, the
// moment it was prepared.
func (f installationFiles) authority(keyFile, certFile, atFile string) (*cryptostate.Material, error) {
	keyPath := filepath.Join(f.StateDir, keyFile)
	certPath := filepath.Join(f.StateDir, certFile)
	keyPEM, keyErr := os.ReadFile(keyPath)
	certPEM, certErr := os.ReadFile(certPath)
	switch {
	case errors.Is(keyErr, os.ErrNotExist) && errors.Is(certErr, os.ErrNotExist):
		return nil, nil
	case keyErr != nil:
		return nil, fmt.Errorf("%s: %w", keyPath, keyErr)
	case certErr != nil:
		return nil, fmt.Errorf("%s: %w", certPath, certErr)
	}
	cert, err := pki.ParseCertificatePEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", certPath, err)
	}
	var preparedAt []byte
	if atFile != "" {
		atPath := filepath.Join(f.StateDir, atFile)
		preparedAt, err = os.ReadFile(atPath)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%s: %w", atPath, err)
		}
	}
	return &cryptostate.Material{
		KeyID:   pki.IssuerIDOf(cert),
		Purpose: cryptostate.PurposeAgentCA,
		Source:  keyPath,
		Bytes:   authorityBundle(keyPEM, certPEM, preparedAt),
	}, nil
}

// collectHelperSigning reads the key that signs the capabilities the root
// helper accepts, and the one it was rotated from when there is one: the hosts
// still trust both during the overlap.
func (f installationFiles) collectHelperSigning() ([]cryptostate.Material, error) {
	if f.HelperKeyPath == "" {
		return nil, nil
	}
	var found []cryptostate.Material
	for _, role := range []struct {
		path   string
		prefix string
	}{
		{f.HelperKeyPath, helperKeyPrefix},
		{helpercap.PreviousKeyPath(f.HelperKeyPath), helperPreviousPrefix},
	} {
		content, err := os.ReadFile(role.path)
		if errors.Is(err, os.ErrNotExist) {
			if role.prefix == helperKeyPrefix {
				return nil, fmt.Errorf(
					"%s holds no helper signing key; the hosts of this fleet trust a key that would be left behind",
					role.path)
			}
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", role.path, err)
		}
		signer, err := helpercap.ReadSigner(role.path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", role.path, err)
		}
		found = append(found, cryptostate.Material{
			KeyID:   role.prefix + signer.KeyID(),
			Purpose: cryptostate.PurposeHelperSigning,
			Source:  role.path,
			Bytes:   content,
		})
	}
	return found, nil
}

// paths names every file the collected material came from, for the operator
// who is about to be told these files can go.
func materialPaths(materials []cryptostate.Material) []string {
	paths := make([]string, 0, len(materials))
	for _, material := range materials {
		paths = append(paths, material.Source)
	}
	return paths
}

// authorityBundle puts a CA into one value: its key, its certificate and, for
// a prepared one, the moment it was prepared.
func authorityBundle(keyPEM, certPEM, preparedAt []byte) []byte {
	bundle := append([]byte(nil), keyPEM...)
	bundle = append(bundle, certPEM...)
	if len(preparedAt) > 0 {
		bundle = append(bundle, pem.EncodeToMemory(&pem.Block{
			Type: preparedAtBlock, Bytes: preparedAt,
		})...)
	}
	return bundle
}

// authorityParts takes a bundle apart again.
func authorityParts(bundle []byte) (keyPEM, certPEM, preparedAt []byte, err error) {
	rest := bundle
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		encoded := pem.EncodeToMemory(block)
		switch {
		case strings.Contains(block.Type, "PRIVATE KEY"):
			keyPEM = append(keyPEM, encoded...)
		case block.Type == "CERTIFICATE":
			certPEM = append(certPEM, encoded...)
		case block.Type == preparedAtBlock:
			preparedAt = block.Bytes
		default:
			return nil, nil, nil, fmt.Errorf("the authority carries a %q, which is not part of one", block.Type)
		}
	}
	if len(keyPEM) == 0 || len(certPEM) == 0 {
		return nil, nil, nil, errors.New("the authority is missing its key or its certificate")
	}
	return keyPEM, certPEM, preparedAt, nil
}
