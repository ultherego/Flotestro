package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// The bounds of the clock check.
//
// Kerberos and the certificates tolerate minutes; a TLS handshake fails when
// the certificate "is not yet valid" by the clock of the host. Half a minute
// is worth a word, five minutes is the point at which the enrollment stops
// working.
const (
	clockWarnAbove = 30 * time.Second
	clockFailAbove = 5 * time.Minute
)

// checkClock compares the clock of the host with the one of the endpoint.
//
// The endpoint answers every request with a Date header, so a HEAD request
// is enough - nothing is sent and nothing is read beyond the headers. When
// the verified handshake fails the header is read without verification: a
// skewed clock is itself the commonest reason a certificate is refused, and
// the offset is the only thing this check is after.
func (d diagnostics) checkClock(ctx context.Context, target endpoint, pool *x509.CertPool) Check {
	start := d.Now()
	header, verified, err := d.fetchHeaders(ctx, target, pool)
	end := d.Now()
	if err != nil {
		return notRun("clock", fmt.Sprintf("%s did not answer: %v; see tls.%s", target.Host, err, target.Name))
	}
	// The remote time was stamped somewhere between the request and the
	// answer; the middle is the closest guess.
	local := start.Add(end.Sub(start) / 2)
	check := clockCheck(local, header.Get("Date"))
	if !verified {
		check.Detail += " (the server was not verified: the offset is informational)"
	}
	return check
}

// clockCheck judges the offset from the Date header alone.
//
// Separate from the request so that a test can hand it a time and a header
// without a network. The header carries whole seconds, so an offset below a
// second is noise rather than a measurement.
func clockCheck(local time.Time, date string) Check {
	if date == "" {
		return warn("clock", "clock_unverified", "the endpoint sent no Date header")
	}
	remote, err := http.ParseTime(date)
	if err != nil {
		return warn("clock", "clock_unverified", fmt.Sprintf("the Date header is unreadable: %q", date))
	}
	offset := local.Sub(remote)
	milliseconds := offset.Milliseconds()
	magnitude := offset
	if magnitude < 0 {
		magnitude = -magnitude
	}
	detail := fmt.Sprintf("the host is %s from the endpoint", describeOffset(offset))
	var check Check
	switch {
	case magnitude > clockFailAbove:
		check = fail("clock", "clock_skew", detail+"; synchronise the time before enrolling")
	case magnitude > clockWarnAbove:
		check = warn("clock", "clock_skew", detail+"; check the time synchronisation")
	default:
		check = pass("clock", detail)
	}
	check.OffsetMS = &milliseconds
	return check
}

// describeOffset says the direction along with the size.
func describeOffset(offset time.Duration) string {
	switch {
	case offset > 0:
		return fmt.Sprintf("%s ahead", offset.Round(time.Millisecond))
	case offset < 0:
		return fmt.Sprintf("%s behind", (-offset).Round(time.Millisecond))
	}
	return "0s"
}

// fetchHeaders sends a HEAD request to the endpoint and returns the headers.
//
// The second value says whether the certificate of the server was verified.
// The first attempt verifies; only when that fails on the certificate does
// the second go without, and the caller marks the result accordingly.
func (d diagnostics) fetchHeaders(ctx context.Context, target endpoint, pool *x509.CertPool) (http.Header, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, d.Timeout)
	defer cancel()

	attempt := func(insecure bool) (http.Header, error) {
		transport := &http.Transport{
			DialContext: d.Dial,
			TLSClientConfig: &tls.Config{
				RootCAs:    pool,
				MinVersion: tls.VersionTLS12,
				// The fallback reads a Date header and nothing else: no
				// secret goes out and no answer is trusted, and the caller
				// marks the result as unverified.
				InsecureSkipVerify: insecure,
			},
		}
		defer transport.CloseIdleConnections()
		request, err := http.NewRequestWithContext(ctx, http.MethodHead, target.URL, nil)
		if err != nil {
			return nil, err
		}
		response, err := (&http.Client{Transport: transport}).Do(request)
		if err != nil {
			return nil, err
		}
		defer response.Body.Close()
		return response.Header, nil
	}

	header, err := attempt(false)
	if err == nil {
		return header, true, nil
	}
	if !certificateProblem(err) {
		return nil, false, err
	}
	header, err = attempt(true)
	if err != nil {
		return nil, false, err
	}
	return header, false, nil
}

// certificateProblem says whether the handshake failed on the certificate
// rather than on the network.
func certificateProblem(err error) bool {
	var unknown x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	var verification *tls.CertificateVerificationError
	return errors.As(err, &unknown) || errors.As(err, &hostname) ||
		errors.As(err, &invalid) || errors.As(err, &verification)
}

// checkDNS resolves the name of the endpoint.
func (d diagnostics) checkDNS(ctx context.Context, target endpoint) Check {
	name := "dns." + target.Name
	if ip := net.ParseIP(target.Host); ip != nil {
		// A literal address needs no resolver, and a resolver that is down
		// would not stop the agent from reaching it.
		check := pass(name, fmt.Sprintf("%s is a literal address", target.Host))
		check.Addresses = []string{ip.String()}
		return check
	}
	ctx, cancel := context.WithTimeout(ctx, d.Timeout)
	defer cancel()
	addresses, err := d.LookupHost(ctx, target.Host)
	if err != nil {
		return fail(name, "dns_resolve_failed", fmt.Sprintf("%s: %v", target.Host, err))
	}
	if len(addresses) == 0 {
		return fail(name, "dns_resolve_failed", fmt.Sprintf("%s resolved to no address", target.Host))
	}
	check := pass(name, fmt.Sprintf("%s -> %s", target.Host, strings.Join(addresses, ", ")))
	check.Addresses = addresses
	return check
}

// checkTLS opens the connection and completes the handshake.
//
// The verification is not turned off even in diagnostics: the check names
// the error of the chain and the expected name, but it does not pretend the
// connection is good.
func (d diagnostics) checkTLS(ctx context.Context, target endpoint, pool *x509.CertPool,
	poolErr error, resolved bool) Check {
	name := "tls." + target.Name
	if poolErr != nil {
		return fail(name, "bootstrap_ca_invalid", poolErr.Error())
	}
	if !resolved {
		return notRun(name, fmt.Sprintf("%s did not resolve; see dns.%s", target.Host, target.Name))
	}
	ctx, cancel := context.WithTimeout(ctx, d.Timeout)
	defer cancel()

	conn, err := d.Dial(ctx, "tcp", net.JoinHostPort(target.Host, target.Port))
	if err != nil {
		return fail(name, "connect_failed", fmt.Sprintf("%s:%s: %v", target.Host, target.Port, err))
	}
	defer conn.Close()

	client := tls.Client(conn, &tls.Config{ServerName: target.Host, RootCAs: pool, MinVersion: tls.VersionTLS12})
	if err := client.HandshakeContext(ctx); err != nil {
		code, detail := tlsError(target.Host, err)
		return fail(name, code, detail)
	}
	state := client.ConnectionState()
	description := "without a server certificate"
	if len(state.PeerCertificates) > 0 {
		server := state.PeerCertificates[0]
		description = fmt.Sprintf("%s, valid until %s", server.Subject.CommonName,
			server.NotAfter.UTC().Format(time.RFC3339))
	}
	return pass(name, fmt.Sprintf("%s (%s)", description, tlsVersion(state.Version)))
}

// tlsError maps a handshake error onto a stable code and a detail that says
// what to fix.
//
// The codes are the ones of the enrollment document: a playbook compares the
// code, a person reads the detail.
func tlsError(host string, err error) (code, detail string) {
	var unknown x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	var timeout net.Error
	switch {
	case errors.As(err, &unknown):
		return "tls_unknown_authority", fmt.Sprintf("%s: the certificate is not signed by the configured CA: check bootstrap_ca_file", host)
	case errors.As(err, &hostname):
		names := "no name"
		if hostname.Certificate != nil && len(hostname.Certificate.DNSNames) > 0 {
			names = strings.Join(hostname.Certificate.DNSNames, ", ")
		}
		return "tls_name_mismatch", fmt.Sprintf("the certificate is valid for %s, not %s", names, host)
	case errors.As(err, &invalid):
		if invalid.Reason == x509.Expired {
			// "Expired" by the clock of the host: a skewed clock gives the
			// same error as a certificate really past its term.
			return "tls_certificate_invalid", fmt.Sprintf("%s: the certificate is expired or not yet valid by the clock of this host; see clock", host)
		}
		return "tls_certificate_invalid", fmt.Sprintf("%s: %v", host, err)
	case errors.As(err, &timeout) && timeout.Timeout():
		return "connect_timeout", fmt.Sprintf("%s: the handshake timed out: %v", host, err)
	}
	return "tls_handshake_failed", fmt.Sprintf("%s: %v", host, err)
}

func tlsVersion(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	}
	return fmt.Sprintf("0x%04x", version)
}
