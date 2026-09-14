package identity

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"slices"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/oidc"
)

// fakeProvider answers a refresh from a table rather than from the network.
type fakeProvider struct {
	tokens *oidc.TokenSet
	claims *oidc.Claims
	err    error
	asked  []string
}

func (f *fakeProvider) Refresh(_ context.Context, refreshToken string) (*oidc.TokenSet, *oidc.Claims, error) {
	f.asked = append(f.asked, refreshToken)
	return f.tokens, f.claims, f.err
}

// fakeGroupStore records what the refresher writes.
type fakeGroupStore struct {
	due      []authz.RefreshableSession
	recorded map[string][]string
	tokens   map[string]authz.SessionTokens
	revoked  map[string]string
	writeErr error
}

func (f *fakeGroupStore) StaleGroupSnapshots(context.Context, time.Time, int) ([]authz.RefreshableSession, error) {
	return f.due, nil
}

func (f *fakeGroupStore) RecordGroupRefresh(_ context.Context, sessionID string, groups []string, tokens authz.SessionTokens) error {
	if f.writeErr != nil {
		return f.writeErr
	}
	if f.recorded == nil {
		f.recorded = map[string][]string{}
		f.tokens = map[string]authz.SessionTokens{}
	}
	f.recorded[sessionID] = groups
	f.tokens[sessionID] = tokens
	return nil
}

func (f *fakeGroupStore) RevokeSession(_ context.Context, sessionID, reason string) error {
	if f.revoked == nil {
		f.revoked = map[string]string{}
	}
	f.revoked[sessionID] = reason
	return nil
}

type fakeAudit struct{ events []audit.Event }

func (f *fakeAudit) Record(_ context.Context, event audit.Event) { f.events = append(f.events, event) }

func newTestRefresher(store *fakeGroupStore, provider *fakeProvider, trail *fakeAudit) *SessionGroupRefresher {
	return NewSessionGroupRefresher(store, provider, trail,
		slog.New(slog.NewTextHandler(io.Discard, nil)), 5*time.Minute)
}

var testSession = authz.RefreshableSession{
	ID: "s-1", PrincipalID: "p-alice", Subject: "alice",
	Groups: []string{"ops", "admins"}, RefreshToken: "rt-old",
}

func TestTheRefresherDecidesFromTheProviderAnswer(t *testing.T) {
	invalidGrant := &oauth2.RetrieveError{ErrorCode: "invalid_grant"}
	cases := []struct {
		name     string
		provider *fakeProvider
		outcome  RefreshOutcome
		// groups is the snapshot the session holds afterwards; nil means the
		// session was not written.
		groups  []string
		revoked bool
		action  string
	}{
		{
			name: "the same groups in another order confirm the snapshot",
			provider: &fakeProvider{
				tokens: &oidc.TokenSet{RefreshToken: "rt-new", IDToken: "id-new"},
				claims: &oidc.Claims{Subject: "alice", Groups: []string{"admins", "ops"}},
			},
			outcome: RefreshUnchanged, groups: []string{"ops", "admins"},
		},
		{
			name: "a group taken away changes the snapshot",
			provider: &fakeProvider{
				tokens: &oidc.TokenSet{RefreshToken: "rt-new", IDToken: "id-new"},
				claims: &oidc.Claims{Subject: "alice", Groups: []string{"ops"}},
			},
			outcome: RefreshChanged, groups: []string{"ops"}, action: "auth.groups_changed",
		},
		{
			name: "every group taken away leaves an empty snapshot, not a missing one",
			provider: &fakeProvider{
				tokens: &oidc.TokenSet{RefreshToken: "rt-new", IDToken: "id-new"},
				claims: &oidc.Claims{Subject: "alice", Groups: nil},
			},
			outcome: RefreshChanged, groups: []string{}, action: "auth.groups_changed",
		},
		{
			name: "a renewal without an identity token keeps the snapshot and the new tokens",
			provider: &fakeProvider{
				tokens: &oidc.TokenSet{RefreshToken: "rt-new"},
			},
			outcome: RefreshUnchanged, groups: []string{"ops", "admins"},
		},
		{
			name:     "an invalid grant ends the session",
			provider: &fakeProvider{err: invalidGrant},
			outcome:  RefreshRevoked, revoked: true, action: "auth.session_revoked",
		},
		{
			name:     "a provider outage keeps the session for the next tick",
			provider: &fakeProvider{err: errors.New("dial tcp: connection refused")},
			outcome:  RefreshDeferred,
		},
		{
			name:     "a provider error other than an invalid grant is transient too",
			provider: &fakeProvider{err: &oauth2.RetrieveError{ErrorCode: "temporarily_unavailable"}},
			outcome:  RefreshDeferred,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := &fakeGroupStore{}
			trail := &fakeAudit{}
			refresher := newTestRefresher(store, tc.provider, trail)

			got := refresher.refreshOne(context.Background(), testSession)
			if got != tc.outcome {
				t.Fatalf("outcome = %s, expected %s", got, tc.outcome)
			}
			if tc.provider.asked[0] != "rt-old" {
				t.Fatalf("the provider was asked with %q, expected the stored refresh token", tc.provider.asked[0])
			}

			written, wrote := store.recorded["s-1"]
			if (tc.groups != nil) != wrote {
				t.Fatalf("session written = %v, expected %v", wrote, tc.groups != nil)
			}
			if wrote && !slices.Equal(written, tc.groups) {
				t.Fatalf("groups = %v, expected %v", written, tc.groups)
			}
			if wrote && store.tokens["s-1"].RefreshToken != "rt-new" {
				// A provider that rotates refresh tokens refuses the old one
				// next time; losing the new one would end a live session.
				t.Fatalf("refresh token = %q, expected the rotated one", store.tokens["s-1"].RefreshToken)
			}

			if _, ended := store.revoked["s-1"]; ended != tc.revoked {
				t.Fatalf("revoked = %v, expected %v", ended, tc.revoked)
			}
			if tc.action == "" {
				if len(trail.events) != 0 {
					t.Fatalf("no audit event expected, got %s", trail.events[0].Action)
				}
				return
			}
			if len(trail.events) != 1 || trail.events[0].Action != tc.action {
				t.Fatalf("audit events = %+v, expected one %s", trail.events, tc.action)
			}
			if trail.events[0].TargetID != "p-alice" {
				t.Fatalf("the event targets %q, expected the principal", trail.events[0].TargetID)
			}
		})
	}
}

func TestAChangedSnapshotIsNotedWithBothSides(t *testing.T) {
	store := &fakeGroupStore{}
	trail := &fakeAudit{}
	refresher := newTestRefresher(store, &fakeProvider{
		tokens: &oidc.TokenSet{RefreshToken: "rt-new", IDToken: "id-new"},
		claims: &oidc.Claims{Subject: "alice", Groups: []string{"ops", "auditors"}},
	}, trail)

	refresher.refreshOne(context.Background(), testSession)

	event := trail.events[0]
	before, _ := event.Before.(map[string]any)
	after, _ := event.After.(map[string]any)
	if !slices.Equal(before["groups"].([]string), []string{"ops", "admins"}) {
		t.Fatalf("before = %v", before)
	}
	if !slices.Equal(after["groups"].([]string), []string{"ops", "auditors"}) {
		t.Fatalf("after = %v", after)
	}
	if !slices.Equal(event.Detail["added"].([]string), []string{"auditors"}) ||
		!slices.Equal(event.Detail["removed"].([]string), []string{"admins"}) {
		t.Fatalf("detail = %v", event.Detail)
	}
}

func TestAFailedWriteDefersTheSession(t *testing.T) {
	// The provider answered, the database did not: the snapshot is not
	// changed in memory alone, and the next tick asks again.
	store := &fakeGroupStore{writeErr: errors.New("database gone")}
	trail := &fakeAudit{}
	refresher := newTestRefresher(store, &fakeProvider{
		tokens: &oidc.TokenSet{RefreshToken: "rt-new", IDToken: "id-new"},
		claims: &oidc.Claims{Subject: "alice", Groups: []string{"ops"}},
	}, trail)

	if got := refresher.refreshOne(context.Background(), testSession); got != RefreshDeferred {
		t.Fatalf("outcome = %s, expected deferred", got)
	}
	if len(trail.events) != 0 {
		t.Fatal("a change that was not written must not be on the trail")
	}
}

func TestATickWalksEveryDueSession(t *testing.T) {
	store := &fakeGroupStore{due: []authz.RefreshableSession{
		{ID: "s-1", PrincipalID: "p-1", Subject: "alice", Groups: []string{"ops"}, RefreshToken: "rt-1"},
		{ID: "s-2", PrincipalID: "p-2", Subject: "bob", Groups: []string{"ops"}, RefreshToken: "rt-2"},
	}}
	provider := &fakeProvider{
		tokens: &oidc.TokenSet{RefreshToken: "rt-new", IDToken: "id-new"},
		claims: &oidc.Claims{Subject: "x", Groups: []string{"ops"}},
	}
	refresher := newTestRefresher(store, provider, &fakeAudit{})

	refresher.tick(context.Background())

	if !slices.Equal(provider.asked, []string{"rt-1", "rt-2"}) {
		t.Fatalf("asked = %v", provider.asked)
	}
}

func TestTheRefresherIsIdleWithoutAProviderOrAnInterval(t *testing.T) {
	// A token-only deployment has no provider; a zero interval turns the
	// loop off. Either way Run returns rather than waiting on a ticker that
	// would never do anything.
	store := &fakeGroupStore{due: []authz.RefreshableSession{testSession}}
	done := make(chan struct{})
	go func() {
		NewSessionGroupRefresher(store, nil, &fakeAudit{},
			slog.New(slog.NewTextHandler(io.Discard, nil)), time.Second).Run(context.Background())
		NewSessionGroupRefresher(store, &fakeProvider{}, &fakeAudit{},
			slog.New(slog.NewTextHandler(io.Discard, nil)), 0).Run(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return for a disabled refresher")
	}
}
