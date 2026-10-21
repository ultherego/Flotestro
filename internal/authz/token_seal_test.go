package authz

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ultherego/flotestro/internal/cryptostate"
)

func testSealer(t *testing.T) *TokenSealer {
	t.Helper()
	provider, err := cryptostate.NewLocalProvider(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := provider.GenerateNamed(ctx, "k-one"); err != nil {
		t.Fatal(err)
	}
	provider.SetActive("k-one")
	return NewTokenSealer(provider)
}

// The refresh token of a session is a credential at the identity provider, and the
// database that keeps it is read by more people than the provider's own admins.
func TestAProviderTokenIsNotStoredAsItCame(t *testing.T) {
	sealer := testSealer(t)
	ctx := context.Background()

	stored, err := sealer.Seal(ctx, "session-1", "refresh", "refresh-token-of-the-provider")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stored, "refresh-token-of-the-provider") || !strings.HasPrefix(stored, sealedTokenPrefix) {
		t.Fatalf("the token is stored in the clear or unmarked: %q", stored)
	}
	got, err := sealer.Open(ctx, "session-1", "refresh", stored)
	if err != nil || got != "refresh-token-of-the-provider" {
		t.Fatalf("a token did not come back as it went in: %q, %v", got, err)
	}
}

// Moved to another session, or into the other column, a sealed token does not open.
func TestASealedProviderTokenIsBoundToItsSessionAndItsKind(t *testing.T) {
	sealer := testSealer(t)
	ctx := context.Background()
	stored, err := sealer.Seal(ctx, "session-1", "refresh", "a token")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sealer.Open(ctx, "session-2", "refresh", stored); !errors.Is(err, ErrTokenUnreadable) {
		t.Errorf("a token moved to another session opened: %v", err)
	}
	if _, err := sealer.Open(ctx, "session-1", "id", stored); !errors.Is(err, ErrTokenUnreadable) {
		t.Errorf("a refresh token read as the ID token opened: %v", err)
	}
	damaged := stored[:len(stored)-6] + "AAAAAA"
	if _, err := sealer.Open(ctx, "session-1", "refresh", damaged); !errors.Is(err, ErrTokenUnreadable) {
		t.Errorf("a damaged token opened: %v", err)
	}
}

// A session that wrote its token before the sealing existed still reads it, and an
// empty token stays empty: the sealing is not a reason to sign everybody out.
func TestATokenWrittenBeforeTheSealingIsStillRead(t *testing.T) {
	sealer := testSealer(t)
	ctx := context.Background()
	got, err := sealer.Open(ctx, "session-1", "refresh", "plain-token-from-before")
	if err != nil || got != "plain-token-from-before" {
		t.Errorf("an unsealed token was not passed through: %q, %v", got, err)
	}
	empty, err := sealer.Seal(ctx, "session-1", "refresh", "")
	if err != nil || empty != "" {
		t.Errorf("an empty token became %q, %v", empty, err)
	}
}
