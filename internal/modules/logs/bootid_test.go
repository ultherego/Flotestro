package logs

import (
	"errors"
	"testing"
)

// The kernel and the journal spell one boot identifier two ways; both
// reach journalctl as the bare lowercase form, and nothing else reaches
// it at all - a wrong value would read as "no such boot" or, empty, as
// every boot.
func TestNormalizeBootIDTakesBothSpellingsAndNothingElse(t *testing.T) {
	const bare = "2cd1131243654fe6b49ee4d704ea2c5a"
	for _, raw := range []string{
		bare,
		"2cd11312-4365-4fe6-b49e-e4d704ea2c5a",
		"2CD11312-4365-4FE6-B49E-E4D704EA2C5A",
		" 2cd1131243654fe6b49ee4d704ea2c5a\n",
	} {
		got, err := NormalizeBootID(raw)
		if err != nil {
			t.Errorf("%q: %v", raw, err)
			continue
		}
		if got != bare {
			t.Errorf("%q normalised to %q, want %q", raw, got, bare)
		}
	}
	for _, raw := range []string{
		"",
		"-",
		"2cd1131243654fe6b49ee4d704ea2c5",
		"2cd1131243654fe6b49ee4d704ea2c5a0",
		"2cd1131243654fe6b49ee4d704ea2c5g",
		"--boot=2cd1131243654fe6b49ee4d704ea2c5a",
		"-1",
		"2cd1131243654fe6b49ee4d704ea2c5a; rm -rf /",
	} {
		if got, err := NormalizeBootID(raw); !errors.Is(err, ErrBootID) || got != "" {
			t.Errorf("%q was accepted as %q (%v)", raw, got, err)
		}
	}
}
