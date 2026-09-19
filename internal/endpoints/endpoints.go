// Package endpoints chooses the gateway the agent tries to connect to. An
// agent keeps one active session but knows an ordered list of gateways.
package endpoints

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// Class describes the kind of a failure of a connection.
type Class string

const (
	// ClassNetwork is a broken or refused connection. An ordinary failure: it
	// is worth trying the next gateway right away.
	ClassNetwork Class = "network"
	// ClassConfiguration is an unknown CA or a name the certificate does not
	// attest.
	ClassConfiguration Class = "configuration_error"
	// ClassIdentity is a certificate that is unknown or revoked.
	ClassIdentity Class = "identity_rejected"
)

// ErrIdentityRejected ends the work of the manager: no gateway will let in a
// certificate the panel has revoked.
var ErrIdentityRejected = errors.New("the identity of the agent was rejected by the centre")

// The default limits of the backoff.
const (
	MinBackoff = 2 * time.Second
	MaxBackoff = 5 * time.Minute
	// ConfigurationBackoff is longer: a configuration error is fixed by a person
	// rather than by a retry.
	ConfigurationBackoff = 15 * time.Minute
)

// State describes one gateway.
type State struct {
	URL         string
	Errors      int
	Class       Class
	NextAttempt time.Time
	LastSuccess time.Time
}

// Manager drives the choice of a gateway.
type Manager struct {
	gateways   []*State
	minBackoff time.Duration
	maxBackoff time.Duration
	// rejected remembers that the centre refused the identity. Global state
	// rather than per gateway: the identity is one for the whole fleet.
	rejected bool
	// now and sleep are the clock of the manager.
	now   func() time.Time
	sleep func(context.Context, time.Duration) error
}

// New creates a manager for the given list of gateways in order of priority.
func New(addresses []string, minBackoff, maxBackoff time.Duration) *Manager {
	if minBackoff <= 0 {
		minBackoff = MinBackoff
	}
	if maxBackoff < minBackoff {
		maxBackoff = MaxBackoff
	}
	manager := &Manager{
		minBackoff: minBackoff, maxBackoff: maxBackoff,
		now: time.Now, sleep: sleepContext,
	}
	seen := map[string]bool{}
	for _, address := range addresses {
		if address == "" || seen[address] {
			continue
		}
		seen[address] = true
		manager.gateways = append(manager.gateways, &State{URL: address})
	}
	return manager
}

// Gateways returns the state of every gateway in order of priority.
func (m *Manager) Gateways() []State {
	copied := make([]State, 0, len(m.gateways))
	for _, gateway := range m.gateways {
		copied = append(copied, *gateway)
	}
	return copied
}

// Choose returns the first gateway ready for an attempt.
func (m *Manager) Choose(now time.Time) (*State, error) {
	if m.rejected {
		return nil, ErrIdentityRejected
	}
	for _, gateway := range m.gateways {
		if !now.Before(gateway.NextAttempt) {
			return gateway, nil
		}
	}
	return nil, nil
}

// UntilNext says how long to wait before any gateway is ready.
func (m *Manager) UntilNext(now time.Time) time.Duration {
	var soonest time.Duration
	for _, gateway := range m.gateways {
		waiting := gateway.NextAttempt.Sub(now)
		if waiting <= 0 {
			return 0
		}
		if soonest == 0 || waiting < soonest {
			soonest = waiting
		}
	}
	if soonest == 0 {
		return m.minBackoff
	}
	return soonest
}

// Success clears the error history of a gateway. What counts is a session that
// really worked.
func (m *Manager) Success(url string, now time.Time) {
	for _, gateway := range m.gateways {
		if gateway.URL == url {
			gateway.Errors = 0
			gateway.Class = ""
			gateway.LastSuccess = now
			gateway.NextAttempt = time.Time{}
			return
		}
	}
}

// Error records a failed attempt and sets the window of the next one.
func (m *Manager) Error(url string, class_ Class, now time.Time) {
	if class_ == ClassIdentity {
		// A revoked certificate is not a problem of this gateway. Further attempts
		// will not restore access and only bury the log of the centre.
		m.rejected = true
	}
	for _, gateway := range m.gateways {
		if gateway.URL != url {
			continue
		}
		gateway.Errors++
		gateway.Class = class_
		gateway.NextAttempt = now.Add(m.window(gateway))
		return
	}
}

// window computes the time until the next attempt of a given gateway.
func (m *Manager) window(gateway *State) time.Duration {
	upper := m.maxBackoff
	if gateway.Class == ClassConfiguration {
		upper = ConfigurationBackoff
	}
	// The doubling is bounded by the exponent: 1<<n with dozens of errors
	// overflows the counter and gives a negative duration.
	exponent := gateway.Errors
	if exponent > 10 {
		exponent = 10
	}
	window := m.minBackoff * time.Duration(1<<exponent)
	if window > upper || window <= 0 {
		window = upper
	}
	return fullJitter(window)
}

// fullJitter returns a random duration from the range [0, upper).
func fullJitter(upper time.Duration) time.Duration {
	if upper <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(upper)))
	if err != nil {
		return upper / 2
	}
	return time.Duration(n.Int64())
}

// Attempt is one try against one gateway: which one, how it failed and what
// kind of failure it was.
type Attempt struct {
	URL   string
	Class Class
	Err   error
}

// ErrNoGateway means the caller gave no address to try.
var ErrNoGateway = errors.New("no gateway address is configured")

// Failover is the answer when every address refused: what was tried, in order,
// and how each one answered.
type Failover struct {
	Attempts []Attempt
}

func (f *Failover) Error() string {
	if len(f.Attempts) == 0 {
		return ErrNoGateway.Error()
	}
	if len(f.Attempts) == 1 {
		// One address configured: the failure is the gateway's own, and a sentence
		// about a failover nobody asked for would only stand between the operator
		// and the reason.
		return f.Attempts[0].URL + ": " + f.Attempts[0].Err.Error()
	}
	parts := make([]string, 0, len(f.Attempts))
	for _, attempt := range f.Attempts {
		parts = append(parts, fmt.Sprintf("%s: %s (%s)", attempt.URL, attempt.Err, attempt.Class))
	}
	return "every gateway refused: " + strings.Join(parts, "; ")
}

// Unwrap gives the failure of the last gateway tried, so that errors.Is
// against a transport error still works on the whole answer.
func (f *Failover) Unwrap() error {
	if len(f.Attempts) == 0 {
		return ErrNoGateway
	}
	return f.Attempts[len(f.Attempts)-1].Err
}

// Try runs an operation against the gateways in order until one answers, and
// returns the address that did.
func (m *Manager) Try(ctx context.Context,
	operation func(ctx context.Context, url string) error) (string, error) {
	if len(m.gateways) == 0 {
		return "", ErrNoGateway
	}
	if m.rejected {
		return "", ErrIdentityRejected
	}
	failover := &Failover{}
	for index, gateway := range m.gateways {
		if index > 0 {
			if err := m.sleep(ctx, fullJitter(m.minBackoff)); err != nil {
				return "", err
			}
		}
		err := operation(ctx, gateway.URL)
		if err == nil {
			m.Success(gateway.URL, m.now())
			return gateway.URL, nil
		}
		class := Classify(err)
		m.Error(gateway.URL, class, m.now())
		failover.Attempts = append(failover.Attempts, Attempt{URL: gateway.URL, Class: class, Err: err})
		if class == ClassIdentity {
			// The reason the centre gave travels with the verdict: the operator's tool
			// prints the code it matches against the error guide, and "the identity was
			// rejected" alone is not one.
			return "", fmt.Errorf("%w: %w", ErrIdentityRejected, err)
		}
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
	}
	return "", failover
}

// sleepContext waits, or gives up when the caller does.
func sleepContext(ctx context.Context, wait time.Duration) error {
	if wait <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// Classify classifies a connection error.
func Classify(err error) Class {
	if err == nil {
		return ClassNetwork
	}
	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "the certificate was revoked"),
		strings.Contains(text, "the certificate is unknown"),
		strings.Contains(text, "identity_rejected"),
		strings.Contains(text, "tls: certificate required"),
		strings.Contains(text, "bad certificate"),
		strings.Contains(text, "certificate revoked"):
		return ClassIdentity
	case strings.Contains(text, "unknown authority"),
		strings.Contains(text, "certificate signed by unknown"),
		strings.Contains(text, "not valid for any names"),
		strings.Contains(text, "certificate is valid for"),
		strings.Contains(text, "x509: "):
		return ClassConfiguration
	}
	return ClassNetwork
}
