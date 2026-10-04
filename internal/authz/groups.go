package authz

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// GroupConfirmationMaxAge bounds how old a directory's confirmation of
// somebody's group membership may be when it authorizes work nobody is
// watching. It is the delay this product accepts between a membership being
// taken away and the work stopping: a campaign wave lasts minutes, so two
// minutes is noticed inside the wave that is running, while one lookup per
// identity per two minutes stays a handful of calls even for a fleet of
// thousands - the cache is keyed by the identity, not by the host.
const GroupConfirmationMaxAge = 2 * time.Minute

// ErrGroupsUnavailable means nobody can say which groups the identity is in
// now: no source answers for its issuer, the directory did not answer, or the
// only confirmation on hand is older than GroupConfirmationMaxAge. It is not a
// refusal - it is the absence of an answer, and the caller pauses on it.
var ErrGroupsUnavailable = errors.New("the group membership of the identity is not confirmed")

// GroupSource answers which groups one system places an account in now.
type GroupSource interface {
	// Issuer names the system this source speaks for. The groups it returns
	// satisfy the mappings of that issuer and of no other: a Keycloak group
	// and a FreeIPA group of the same name are two different groups.
	Issuer() string
	// GroupsOf names the groups of one account, by the identifier that system
	// knows the account under.
	GroupsOf(ctx context.Context, account string) ([]string, error)
}

// GroupConfirmation is a group set together with the moment a directory
// confirmed it and the system that did.
type GroupConfirmation struct {
	Issuer      string
	Account     string
	Groups      []string
	ConfirmedAt time.Time
}

// Age says how long ago the directory confirmed this group set.
func (c GroupConfirmation) Age(now time.Time) time.Duration { return now.Sub(c.ConfirmedAt) }

// GroupDirectory reads group membership from the directories themselves rather
// than from a session's snapshot, behind a cache whose entries expire at
// maxAge. An entry past that age is not served: the question is asked again,
// and a directory that does not answer leaves the caller without an answer.
type GroupDirectory struct {
	mu sync.Mutex
	// issuers holds one source per issuer, for an identity of that issuer.
	issuers map[string]GroupSource
	// linked is the directory an explicit account link points at.
	linked GroupSource
	cache  map[string]GroupConfirmation
	maxAge time.Duration
	// now is the clock the ages are measured against; the tests move it.
	now func() time.Time
}

// NewGroupDirectory builds the resolver. A maxAge of zero means
// GroupConfirmationMaxAge.
func NewGroupDirectory(maxAge time.Duration) *GroupDirectory {
	if maxAge <= 0 {
		maxAge = GroupConfirmationMaxAge
	}
	return &GroupDirectory{issuers: map[string]GroupSource{},
		cache: map[string]GroupConfirmation{}, maxAge: maxAge, now: time.Now}
}

// AddIssuerSource registers the source that answers for an identity of its own
// issuer.
func (d *GroupDirectory) AddIssuerSource(source GroupSource) {
	if source == nil || source.Issuer() == "" {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.issuers[source.Issuer()] = source
}

// SetLinkedSource names the directory an explicit account link points at.
func (d *GroupDirectory) SetLinkedSource(source GroupSource) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.linked = source
}

// LinkedIssuer names the system an explicit account link resolves against, or
// an empty string where no such directory is configured.
func (d *GroupDirectory) LinkedIssuer() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.linked == nil {
		return ""
	}
	return d.linked.Issuer()
}

// SetClock replaces the clock the ages are measured against.
func (d *GroupDirectory) SetClock(clock func() time.Time) {
	if clock == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.now = clock
}

// ConfirmIssuer resolves the groups an identity's own issuer places it in.
func (d *GroupDirectory) ConfirmIssuer(ctx context.Context, issuer, account string) (GroupConfirmation, error) {
	d.mu.Lock()
	source := d.issuers[issuer]
	d.mu.Unlock()
	if source == nil {
		return GroupConfirmation{}, fmt.Errorf("%w: no source answers for the issuer %s",
			ErrGroupsUnavailable, issuer)
	}
	return d.confirm(ctx, source, account)
}

// ConfirmLinked resolves the groups of an explicitly linked directory account.
func (d *GroupDirectory) ConfirmLinked(ctx context.Context, account string) (GroupConfirmation, error) {
	d.mu.Lock()
	source := d.linked
	d.mu.Unlock()
	if source == nil {
		return GroupConfirmation{}, fmt.Errorf("%w: no directory answers for a linked account",
			ErrGroupsUnavailable)
	}
	return d.confirm(ctx, source, account)
}

// confirm serves a confirmation young enough or asks the source for a new one.
func (d *GroupDirectory) confirm(ctx context.Context, source GroupSource, account string) (GroupConfirmation, error) {
	issuer := source.Issuer()
	if account == "" {
		return GroupConfirmation{}, fmt.Errorf("%w: the identity names no account at %s",
			ErrGroupsUnavailable, issuer)
	}
	key := issuer + "\x00" + account
	d.mu.Lock()
	cached, known := d.cache[key]
	clock := d.now
	d.mu.Unlock()
	now := clock()
	if known && cached.Age(now) <= d.maxAge {
		return cached, nil
	}

	groups, err := source.GroupsOf(ctx, account)
	if err != nil {
		// A confirmation that is too old is no answer either: it is not served
		// alongside the failure, and the caller gets the reason instead.
		return GroupConfirmation{}, fmt.Errorf("%w: %s did not answer about %s: %v",
			ErrGroupsUnavailable, issuer, account, err)
	}
	if groups == nil {
		groups = []string{}
	}
	confirmation := GroupConfirmation{Issuer: issuer, Account: account,
		Groups: groups, ConfirmedAt: clock()}
	d.mu.Lock()
	d.cache[key] = confirmation
	d.mu.Unlock()
	return confirmation, nil
}

// Forget drops what is cached about one account, so the next question goes to
// the directory.
func (d *GroupDirectory) Forget(issuer, account string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.cache, issuer+"\x00"+account)
}
