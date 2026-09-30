package app

import (
	"crypto/tls"
	"log/slog"
	"net"
	"strings"
	"sync"

	"github.com/ultherego/flotestro/internal/pki"
)

// advertisedNames is the address the panel is reached at, asked at every
// handshake rather than fixed at the start. The generation changes whenever the
// value in force does, which is what tells the certificate to be issued again.
type advertisedNames interface {
	CertificateNames() (dnsNames []string, ips []net.IP, generation uint64)
}

// panelCertificate is the certificate the panel presents to the fleet, kept in
// step with the authority that signs and with the address the fleet is told to
// dial.
//
// It used to be issued once at the start. After a handover of signing - here
// or on another replica, read in by the reload - it was still signed by the
// authority that had stepped down, which works for exactly as long as that
// authority is withdrawn but still recognised, and stops the moment an
// operator takes it out of the trust set. Nothing said so until the fleet went
// quiet, so the certificate follows the authority instead.
//
// The address is the same shape of defect and was not covered by that fix: an
// administrator confirms the name the agents will dial, and a certificate that
// was issued at the start carries the loopback it started with, so the very
// first agent to connect fails the handshake on the name. So the certificate
// follows both, and by the same means - it asks, per handshake, and issues only
// when the answer has changed.
type panelCertificate struct {
	trust *pki.Trust
	names advertisedNames
	log   *slog.Logger

	mu sync.Mutex
	// issuer is the authority the certificate in hand was signed by, and
	// generation the address it was issued for.
	issuer     string
	generation uint64
	current    tls.Certificate
}

// newPanelCertificate issues the first one.
func newPanelCertificate(trust *pki.Trust, names advertisedNames,
	log *slog.Logger) (*panelCertificate, error) {
	panel := &panelCertificate{trust: trust, names: names, log: log}
	active := trust.Active()
	dnsNames, ips, generation := names.CertificateNames()
	certificate, err := issueFor(active, dnsNames, ips)
	if err != nil {
		return nil, err
	}
	panel.issuer, panel.generation, panel.current = active.IssuerID(), generation, certificate
	return panel, nil
}

// get returns the certificate to present, issuing a new one when the authority
// that signs is no longer the one that signed this, or when the address the
// panel is advertised under has changed. It is called per handshake, and does
// the work only when one of the two has actually moved.
//
// An issue that fails keeps the certificate in hand: it is still trusted by
// every host that has not dropped the old authority, and answering no
// handshake at all reaches nobody. Nothing is recorded as done in that case
// either, so the next handshake tries again.
func (p *panelCertificate) get() *tls.Certificate {
	active := p.trust.Active()
	id := active.IssuerID()
	dnsNames, ips, generation := p.names.CertificateNames()
	p.mu.Lock()
	defer p.mu.Unlock()
	if id == p.issuer && generation == p.generation {
		return &p.current
	}
	certificate, err := issueFor(active, dnsNames, ips)
	if err != nil {
		p.log.Error("the panel could not issue its own certificate; it goes on presenting the "+
			"one it holds, which the fleet trusts only while the CA that signed it is still in "+
			"the trust set and only under the names it already carries",
			"err", err, "issuer_id", id, "advertised", strings.Join(dnsNames, ","))
		return &p.current
	}
	p.issuer, p.generation, p.current = id, generation, certificate
	p.log.Warn("the panel issued its own certificate",
		"issuer_id", id, "dns_names", strings.Join(dnsNames, ","), "generation", generation)
	return &p.current
}

// forClient is the tls.Config callback shape.
func (p *panelCertificate) forClient(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return p.get(), nil
}

func issueFor(ca *pki.CA, dnsNames []string, ips []net.IP) (tls.Certificate, error) {
	certPEM, keyPEM, err := ca.IssueServerCert(dnsNames, ips)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}
