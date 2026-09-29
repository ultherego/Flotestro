package cryptostate

import (
	"context"
	"errors"
	"fmt"
)

// ProviderSource is what choosing a provider needs of the database: the key
// encryption key the installation recorded, and the rows a sealed provider
// reads.
type ProviderSource interface {
	KeyStore
	// KEKID names the key encryption key this installation's keys are
	// wrapped with; empty means they are still files.
	KEKID(ctx context.Context) (string, error)
	// Load is the installation record. Which installation this is decides
	// which rows the key encryption key may open, so the key is not bound
	// from a flag or a file but from the record itself.
	Load(ctx context.Context) (*Record, error)
}

// SelectProvider says where the keys of this installation come from, and is
// the first thing a start decides: the guard, the secret store and the CA all
// hang off the answer.
//
// An installation that has not moved its keys keeps them in the state
// directory and is not asked for a key encryption key at all - a deployment
// may mount one long before the migration that uses it runs. Once the record
// names one, the keys are rows, and a start without that key, or with another,
// is a refusal rather than a quiet fall back to the files: those files may
// still be lying there and would serve the fleet material the installation has
// stopped sealing with.
func SelectProvider(ctx context.Context, source ProviderSource, kekFile, nextKEKFile string, local Provider) (Provider, error) {
	recorded, err := source.KEKID(ctx)
	switch {
	case errors.Is(err, ErrNoRecord):
		return local, nil
	case err != nil:
		return nil, fmt.Errorf("the recorded key encryption key: %w", err)
	case recorded == "":
		return local, nil
	}
	kek, err := ReadKEKFile(kekFile)
	if err != nil {
		return nil, err
	}
	if !kek.Is(recorded) {
		// A rotation is the one moment an installation has two key encryption
		// keys: the one the rows were wrapped with and the one they are being
		// moved to. Which of the two this panel uses is the record's to say, so
		// there is no order of steps in which a restart brings the panel down.
		// This is not a fallback to whatever opens - a key that the record does
		// not name is refused whichever file it came from.
		next, nextErr := readNextKEK(nextKEKFile, recorded)
		if nextErr != nil {
			return nil, nextErr
		}
		if next == nil {
			return nil, fatal(CodeKEKMismatch, fmt.Sprintf(
				"the keys of this installation are wrapped with %s; %s holds %s",
				recorded, kekFile, kek.ID()), nil)
		}
		kek = next
	}
	// The key is bound to the installation before it opens anything. A record
	// naming a key encryption key is a record, so this read finds one; an
	// installation with no record took the two returns above.
	record, err := source.Load(ctx)
	if err != nil {
		return nil, fmt.Errorf("the installation record: %w", err)
	}
	return NewDBProvider(ctx, source, kek.For(record.InstallationID))
}

// readNextKEK returns the key a rotation is moving to, when there is one and
// it is the one the record names. Anything else is nothing: a missing file is
// the ordinary state, and a key that does not match leaves the refusal to the
// caller, which names the key in use rather than this one.
func readNextKEK(path, recorded string) (*KEK, error) {
	if path == "" {
		return nil, nil
	}
	next, err := ReadKEKFile(path)
	var fatalErr *FatalError
	if errors.As(err, &fatalErr) && fatalErr.Code == CodeKEKFileMissing {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !next.Is(recorded) {
		return nil, nil
	}
	return next, nil
}
