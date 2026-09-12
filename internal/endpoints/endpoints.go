// Package endpoints chooses the gateway the agent tries to connect to.
//
// An agent keeps one active session but knows an ordered list of gateways.
// The choice is not simply "take the next one from the list": the kind of
// error settles whether it is worth trying further at all. A broken TCP
// connection means "try somewhere else in a moment"; an unknown CA means "this
// gateway is misconfigured and switching quickly in circles will not fix
// anything"; a revoked certificate means "stop trying, because the problem is
// not on the side of the network".
//
// The backoff has full jitter, because ten thousand agents must not come back
// in the same second after a failure of the centre - it is that second that
// topples it again.
package endpoints

import (
	"crypto/rand"
	"errors"
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
	// attest. Switching quickly will fix nothing, because the problem is in
	// the configuration rather than in the link.
	ClassConfiguration Class = "configuration_error"
	// ClassIdentity is a certificate that is unknown or revoked. The agent is
	// to stop trying: further attempts are not a failure of the link but
	// knocking with an identity that has been withdrawn.
	ClassIdentity Class = "identity_rejected"
)

// ErrIdentityRejected ends the work of the manager: no gateway will let in a
// certificate the panel has revoked.
var ErrIdentityRejected = errors.New("the identity of the agent was rejected by the centre")

// The default limits of the backoff.
const (
	MinBackoff = 2 * time.Second
	MaxBackoff = 5 * time.Minute
	// ConfigurationBackoff is longer: a configuration error is fixed by a
	// person rather than by a retry. A short backoff would turn it into a loop
	// in the log.
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
}

// New creates a manager for the given list of gateways in order of priority.
func New(addresses []string, minBackoff, maxBackoff time.Duration) *Manager {
	if minBackoff <= 0 {
		minBackoff = MinBackoff
	}
	if maxBackoff < minBackoff {
		maxBackoff = MaxBackoff
	}
	manager := &Manager{minBackoff: minBackoff, maxBackoff: maxBackoff}
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
//
// The order of the list is a priority rather than a suggestion: the agent
// returns to the first gateway as soon as its retry window passes. Without
// that the whole fleet would stay on the backup gateway long after the main
// one came back.
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

// Success clears the error history of a gateway.
//
// What counts is a session that really worked. A connection broken after a
// second is not a success even though it was technically established - which
// is why the caller decides when to call this.
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
		// A revoked certificate is not a problem of this gateway. Further
		// attempts will not restore access and only bury the log of the
		// centre.
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
//
// Full jitter rather than half: the point is spreading the fleet out rather
// than shortening the wait. A halved one leaves the peak in the same place,
// only lower.
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

// Classify classifies a connection error.
//
// The recognition goes by the text of the error, because the TLS libraries
// give no types here that would survive being wrapped in connect and http2. An
// unrecognised error is a network error: that is an assumption which at worst
// asks for another attempt rather than one that stops the agent for good.
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
