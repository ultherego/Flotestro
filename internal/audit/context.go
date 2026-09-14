package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// Actor is what the request knows about the identity behind it beyond its
// name: the session it holds, how the identity provider authenticated that
// session, and the request identifier. It is set once, where the request is
// authenticated, and every event recorded under the request carries it
// without the handler repeating it.
//
// The fields are copies rather than a reference to the session, so the
// audit package needs to know nothing about sessions: a test, a background
// worker or another entry point fills in what it has.
type Actor struct {
	// SessionID is the digest of the session identifier, not the identifier
	// itself: the trail is read by more people than hold sessions, and a
	// digest still ties every event of one session together.
	SessionID string
	// ACR and AMR are what the identity provider reported for the session;
	// AuthTime is when it authenticated it. Empty for an API token.
	ACR      string
	AMR      []string
	AuthTime time.Time
	// RequestID is the identifier the caller attached to the request, so an
	// event can be matched with the client's own log.
	RequestID string
}

// requestContext is what the context carries for the recorder: the actor and
// the host lookups already made under this request, so ten events about one
// host under one request cost one query.
type requestContext struct {
	actor Actor
	mu    sync.Mutex
	hosts map[string]hostSnapshot
}

type hostSnapshot struct {
	hostname string
	address  string
}

type actorContextKey struct{}

// WithActor attaches the actor to the context. Called once per request by
// the authentication layer; the recorder reads it from every event's
// context.
func WithActor(ctx context.Context, actor Actor) context.Context {
	return context.WithValue(ctx, actorContextKey{}, &requestContext{actor: actor})
}

// ActorFromContext returns the actor attached to the context, if any.
func ActorFromContext(ctx context.Context) (Actor, bool) {
	rc, ok := ctx.Value(actorContextKey{}).(*requestContext)
	if !ok {
		return Actor{}, false
	}
	return rc.actor, true
}

// SessionDigest renders a session identifier the way the trail records it.
func SessionDigest(sessionID string) string {
	if sessionID == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(sessionID))
	return hex.EncodeToString(sum[:])
}

func requestFromContext(ctx context.Context) *requestContext {
	rc, _ := ctx.Value(actorContextKey{}).(*requestContext)
	return rc
}

// cachedHost returns the snapshot of a host made earlier under the same
// request.
func (rc *requestContext) cachedHost(hostID string) (hostSnapshot, bool) {
	if rc == nil {
		return hostSnapshot{}, false
	}
	rc.mu.Lock()
	defer rc.mu.Unlock()
	snapshot, ok := rc.hosts[hostID]
	return snapshot, ok
}

func (rc *requestContext) rememberHost(hostID string, snapshot hostSnapshot) {
	if rc == nil {
		return
	}
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if rc.hosts == nil {
		rc.hosts = map[string]hostSnapshot{}
	}
	rc.hosts[hostID] = snapshot
}
