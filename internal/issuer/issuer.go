// Package issuer separates the issuing of the certificates of the fleet from
// where the key of the authority lies.
//
// Today the CA key is a file the panel reads at start. One day it may lie in
// an HSM or in a remote signing service - and only the implementation of this
// interface changes then. The protocol of the agent, the contract of the
// enrollment and the rules of scope stay the same, because they do not know
// what the signer is.
//
// The separation is a boundary for the tests as well: a service can be checked
// with an issuer that fails on demand, without building a whole PKI.
package issuer

import (
	"context"
	"time"

	"github.com/ultherego/flotestro/internal/pki"
)

// Certificate is an issued certificate of an identity of the fleet.
//
// The type is our own rather than borrowed from pki: the services are to
// depend on this contract rather than on the structure of the certificate
// authority.
type Certificate struct {
	PEM         []byte
	Serial      string
	Fingerprint []byte
	NotBefore   time.Time
	NotAfter    time.Time
	CommonName  string
	// The issuer allows counting how many hosts the withdrawal of a given CA
	// concerns.
	IssuerSubject string
	IssuerSerial  string
	// The network names issued in the certificate. Empty for hosts: only a
	// relay appears to anyone as a server.
	DNSNames    []string
	IPAddresses []string
}

// Issuer signs the identity requests of the fleet and describes who the panel
// trusts.
//
// The context is in the signature from the start even though today's
// implementation does not need it: a signature in an HSM or in a remote
// service is a network call and has to be interruptible together with the
// request that ordered it.
type Issuer interface {
	// SignHost issues the certificate of a host. The panel grants the
	// identity: everything in the request but the public key is ignored.
	SignHost(ctx context.Context, csrPEM []byte, hostID string) (*Certificate, error)
	// SignRelay issues the certificate of a relay. The network names come
	// from the registry of the panel; empty means "take them from the
	// request", which is allowed at the first registration alone.
	SignRelay(ctx context.Context, csrPEM []byte, relayID string, names []string) (*Certificate, error)
	// Trust returns the CA bundle of the fleet in force now.
	Trust(ctx context.Context) ([]byte, error)
}

// FromTrust builds an issuer over the certificate authority of the panel.
//
// The trust is read at every signature rather than copied at creation: a
// rotation of the CA changes the active authority while the panel works and
// the issuer is to know about it without a restart.
func FromTrust(trust *pki.Trust) Issuer { return &local{trust: trust} }

// local signs with the key the panel keeps itself.
type local struct {
	trust *pki.Trust
}

func (l *local) SignHost(_ context.Context, csrPEM []byte, hostID string) (*Certificate, error) {
	issued, err := l.trust.Active().SignAgentCSR(csrPEM, hostID)
	if err != nil {
		return nil, err
	}
	return fromPKI(issued), nil
}

func (l *local) SignRelay(_ context.Context, csrPEM []byte, relayID string,
	names []string) (*Certificate, error) {
	var issued *pki.IssuedCert
	var err error
	if len(names) == 0 {
		issued, err = l.trust.Active().SignRelayCSR(csrPEM, relayID)
	} else {
		issued, err = l.trust.Active().SignRelayCSRWithNames(csrPEM, relayID, names)
	}
	if err != nil {
		return nil, err
	}
	return fromPKI(issued), nil
}

func (l *local) Trust(context.Context) ([]byte, error) { return l.trust.Bundle(), nil }

func fromPKI(issued *pki.IssuedCert) *Certificate {
	return &Certificate{
		PEM: issued.PEM, Serial: issued.Serial, Fingerprint: issued.Fingerprint,
		NotBefore: issued.NotBefore, NotAfter: issued.NotAfter,
		CommonName:    issued.CommonName,
		IssuerSubject: issued.IssuerSubject, IssuerSerial: issued.IssuerSerial,
		DNSNames: issued.DNSNames, IPAddresses: issued.IPAddresses,
	}
}
