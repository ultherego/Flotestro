package app

import (
	"crypto/tls"
	"log/slog"
	"net"
	"sync"

	"github.com/ultherego/flotestro/internal/pki"
)

// panelCertificate is the certificate the panel presents to the fleet, kept in
// step with the authority that signs.
//
// It used to be issued once at the start. After a handover of signing - here
// or on another replica, read in by the reload - it was still signed by the
// authority that had stepped down, which works for exactly as long as that
// authority is withdrawn but still recognised, and stops the moment an
// operator takes it out of the trust set. Nothing said so until the fleet went
// quiet, so the certificate follows the authority instead.
type panelCertificate struct {
	trust    *pki.Trust
	dnsNames []string
	ips      []net.IP
	log      *slog.Logger

	mu sync.Mutex
	// issuer is the authority the certificate in hand was signed by.
	issuer  string
	current tls.Certificate
}

// newPanelCertificate issues the first one.
func newPanelCertificate(trust *pki.Trust, dnsNames []string, ips []net.IP,
	log *slog.Logger) (*panelCertificate, error) {
	panel := &panelCertificate{trust: trust, dnsNames: dnsNames, ips: ips, log: log}
	active := trust.Active()
	certificate, err := issueFor(active, dnsNames, ips)
	if err != nil {
		return nil, err
	}
	panel.issuer, panel.current = active.IssuerID(), certificate
	return panel, nil
}

// get returns the certificate to present, issuing a new one when the authority
// that signs is no longer the one that signed this. It is called per handshake,
// and does the work only when the authority has actually changed.
//
// An issue that fails keeps the certificate in hand: it is still trusted by
// every host that has not dropped the old authority, and answering no
// handshake at all reaches nobody.
func (p *panelCertificate) get() *tls.Certificate {
	active := p.trust.Active()
	id := active.IssuerID()
	p.mu.Lock()
	defer p.mu.Unlock()
	if id == p.issuer {
		return &p.current
	}
	certificate, err := issueFor(active, p.dnsNames, p.ips)
	if err != nil {
		p.log.Error("the fleet CA was exchanged and the panel could not issue its own certificate "+
			"from the new one; it goes on presenting the old one, which the fleet trusts only "+
			"until the previous CA is taken out of the trust set",
			"err", err, "issuer_id", id)
		return &p.current
	}
	p.issuer, p.current = id, certificate
	p.log.Warn("the panel issued its own certificate from the CA that now signs",
		"issuer_id", id)
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
