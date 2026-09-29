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
func SelectProvider(ctx context.Context, source ProviderSource, kekFile string, local Provider) (Provider, error) {
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
		return nil, fatal(CodeKEKMismatch, fmt.Sprintf(
			"the keys of this installation are wrapped with %s; %s holds %s",
			recorded, kekFile, kek.ID()), nil)
	}
	return NewDBProvider(ctx, source, kek)
}
