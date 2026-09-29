package cryptostate

import (
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// A certificate authority of the fleet as one value.
//
// The subsystem that owns it keeps it as three things: a private key, a
// certificate, and for one prepared to take over the moment of preparation. A
// wrapped row holds one value, so the three travel bundled - and they are
// bundled here rather than at either end, because the side that moves the keys
// into the database and the side that reads them back have to agree on the
// bytes exactly.

// PreparedAtBlock carries the moment an authority was prepared, which is not
// part of any PEM the subsystem writes. Keeping it in the bundle is what lets
// a prepared authority survive the move as the thing it is: prepared, and
// since when.
const PreparedAtBlock = "FLOTESTRO PREPARED AT"

// HelperKeyPrefix and HelperPreviousPrefix name the rows of the helper's
// signer. The two keys are the same kind of thing in two roles, and nothing
// else records which is which, so the name says it.
const (
	HelperKeyPrefix      = "helper-"
	HelperPreviousPrefix = "helper-previous-"
)

// AuthorityBundle puts a CA into one value: its key, its certificate and, for
// a prepared one, the moment it was prepared.
func AuthorityBundle(keyPEM, certPEM, preparedAt []byte) []byte {
	bundle := append([]byte(nil), keyPEM...)
	bundle = append(bundle, certPEM...)
	if len(preparedAt) > 0 {
		bundle = append(bundle, pem.EncodeToMemory(&pem.Block{
			Type: PreparedAtBlock, Bytes: preparedAt,
		})...)
	}
	return bundle
}

// AuthorityParts takes a bundle apart again.
func AuthorityParts(bundle []byte) (keyPEM, certPEM, preparedAt []byte, err error) {
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
		case block.Type == PreparedAtBlock:
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
