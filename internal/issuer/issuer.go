// Package issuer separates the issuing of the certificates of the fleet from
// where the key of the authority lies.
package issuer

import (
	"context"
	"time"

	"github.com/ultherego/flotestro/internal/pki"
)

// Certificate is an issued certificate of an identity of the fleet.
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
	// IssuerID is the stable identifier of the issuing CA, recorded with the
	// certificate so the installation's cryptographic state can be checked
	// against what the hosts hold.
	IssuerID string
	// The network names issued in the certificate. Empty for hosts: only a
	// relay appears to anyone as a server.
	DNSNames    []string
	IPAddresses []string
}

// Issuer signs the identity requests of the fleet and describes who the panel
// trusts.
type Issuer interface {
	// SignHost issues the certificate of a host. The panel grants the
	// identity: everything in the request but the public key is ignored.
	SignHost(ctx context.Context, csrPEM []byte, hostID string) (*Certificate, error)
	// SignRelay issues the certificate of a relay.
	SignRelay(ctx context.Context, csrPEM []byte, relayID string, names []string) (*Certificate, error)
	// Trust returns the CA bundle of the fleet in force now.
	Trust(ctx context.Context) ([]byte, error)
}

// FromTrust builds an issuer over the certificate authority of the panel.
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
		IssuerSubject: issued.IssuerSubject, IssuerSerial: issued.IssuerSerial, IssuerID: issued.IssuerID,
		DNSNames: issued.DNSNames, IPAddresses: issued.IPAddresses,
	}
}
