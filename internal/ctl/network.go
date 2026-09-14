package ctl

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
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
	ClockWarnAbove = 30 * time.Second
	ClockFailAbove = 5 * time.Minute
)

// Endpoint is one address of the panel a component connects to.
type Endpoint struct {
	// Name labels the checks: "enrollment", "gateway", "gateway.2"...
	Name string
	URL  string
	Host string
	Port string
}

// ParseEndpoint turns an address from the configuration into an endpoint.
// An address that does not parse is left out: the configuration parser has
// already refused it, and a check on it would name the wrong problem.
func ParseEndpoint(name, raw string) (Endpoint, bool) {
	address, err := url.Parse(raw)
	if err != nil || address.Host == "" {
		return Endpoint{}, false
	}
	port := address.Port()
	if port == "" {
		port = "443"
	}
	return Endpoint{Name: name, URL: raw, Host: address.Hostname(), Port: port}, true
}

// GatewayEndpoints names the gateways in the order the component uses them.
// The further ones are backups: they get a number rather than a name of
// their own.
func GatewayEndpoints(urls []string) []Endpoint {
	var endpoints []Endpoint
	for i, raw := range urls {
		name := "gateway"
		if i > 0 {
			name = fmt.Sprintf("gateway.%d", i+1)
		}
		if endpoint, ok := ParseEndpoint(name, raw); ok {
			endpoints = append(endpoints, endpoint)
		}
	}
	return endpoints
}

// Network gathers what the network checks touch outside the process.
//
// The clock and the dialers are fields rather than calls to the packages,
// so that a test can run the checks without a network.
type Network struct {
	Now     func() time.Time
	Timeout time.Duration
	// Dial opens the TCP connection for the TLS and clock checks.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)
	// LookupHost resolves a name for the DNS checks.
	LookupHost func(ctx context.Context, host string) ([]string, error)
}

// RealNetwork wires the checks to the network of the host.
func RealNetwork() Network {
	return Network{
		Now:        time.Now,
		Timeout:    15 * time.Second,
		Dial:       (&net.Dialer{}).DialContext,
		LookupHost: net.DefaultResolver.LookupHost,
	}
}

// CheckClock compares the clock of the host with the one of the endpoint.
//
// The endpoint answers every request with a Date header, so a HEAD request
// is enough - nothing is sent and nothing is read beyond the headers. When
// the verified handshake fails the header is read without verification: a
// skewed clock is itself the commonest reason a certificate is refused, and
// the offset is the only thing this check is after.
func (n Network) CheckClock(ctx context.Context, target Endpoint, pool *x509.CertPool) Check {
	start := n.Now()
	header, verified, err := n.FetchHeaders(ctx, target, pool)
	end := n.Now()
	if err != nil {
		return NotRun("clock", fmt.Sprintf("%s did not answer: %v; see tls.%s", target.Host, err, target.Name))
	}
	// The remote time was stamped somewhere between the request and the
	// answer; the middle is the closest guess.
	local := start.Add(end.Sub(start) / 2)
	check := ClockCheck(local, header.Get("Date"))
	if !verified {
		check.Detail += " (the server was not verified: the offset is informational)"
	}
	return check
}

// ClockCheck judges the offset from the Date header alone.
//
// Separate from the request so that a test can hand it a time and a header
// without a network. The header carries whole seconds, so an offset below a
// second is noise rather than a measurement.
func ClockCheck(local time.Time, date string) Check {
	if date == "" {
		return Warn("clock", "clock_unverified", "the endpoint sent no Date header")
	}
	remote, err := http.ParseTime(date)
	if err != nil {
		return Warn("clock", "clock_unverified", fmt.Sprintf("the Date header is unreadable: %q", date))
	}
	offset := local.Sub(remote)
	milliseconds := offset.Milliseconds()
	magnitude := offset
	if magnitude < 0 {
		magnitude = -magnitude
	}
	detail := fmt.Sprintf("the host is %s from the endpoint", DescribeOffset(offset))
	var check Check
	switch {
	case magnitude > ClockFailAbove:
		check = Fail("clock", "clock_skew", detail+"; synchronise the time before enrolling")
	case magnitude > ClockWarnAbove:
		check = Warn("clock", "clock_skew", detail+"; check the time synchronisation")
	default:
		check = Pass("clock", detail)
	}
	check.OffsetMS = &milliseconds
	return check
}

// DescribeOffset says the direction along with the size.
func DescribeOffset(offset time.Duration) string {
	switch {
	case offset > 0:
		return fmt.Sprintf("%s ahead", offset.Round(time.Millisecond))
	case offset < 0:
		return fmt.Sprintf("%s behind", (-offset).Round(time.Millisecond))
	}
	return "0s"
}

// FetchHeaders sends a HEAD request to the endpoint and returns the headers.
//
// The second value says whether the certificate of the server was verified.
// The first attempt verifies; only when that fails on the certificate does
// the second go without, and the caller marks the result accordingly.
func (n Network) FetchHeaders(ctx context.Context, target Endpoint, pool *x509.CertPool) (http.Header, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, n.Timeout)
	defer cancel()

	attempt := func(insecure bool) (http.Header, error) {
		transport := &http.Transport{
			DialContext: n.Dial,
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
	if !CertificateProblem(err) {
		return nil, false, err
	}
	header, err = attempt(true)
	if err != nil {
		return nil, false, err
	}
	return header, false, nil
}

// CertificateProblem says whether the handshake failed on the certificate
// rather than on the network.
func CertificateProblem(err error) bool {
	var unknown x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	var verification *tls.CertificateVerificationError
	return errors.As(err, &unknown) || errors.As(err, &hostname) ||
		errors.As(err, &invalid) || errors.As(err, &verification)
}

// CheckDNS resolves the name of the endpoint.
func (n Network) CheckDNS(ctx context.Context, target Endpoint) Check {
	name := "dns." + target.Name
	if ip := net.ParseIP(target.Host); ip != nil {
		// A literal address needs no resolver, and a resolver that is down
		// would not stop the component from reaching it.
		check := Pass(name, fmt.Sprintf("%s is a literal address", target.Host))
		check.Addresses = []string{ip.String()}
		return check
	}
	ctx, cancel := context.WithTimeout(ctx, n.Timeout)
	defer cancel()
	addresses, err := n.LookupHost(ctx, target.Host)
	if err != nil {
		return Fail(name, "dns_resolve_failed", fmt.Sprintf("%s: %v", target.Host, err))
	}
	if len(addresses) == 0 {
		return Fail(name, "dns_resolve_failed", fmt.Sprintf("%s resolved to no address", target.Host))
	}
	check := Pass(name, fmt.Sprintf("%s -> %s", target.Host, strings.Join(addresses, ", ")))
	check.Addresses = addresses
	return check
}

// CheckTLS opens the connection and completes the handshake.
//
// The verification is not turned off even in diagnostics: the check names
// the error of the chain and the expected name, but it does not pretend the
// connection is good.
func (n Network) CheckTLS(ctx context.Context, target Endpoint, pool *x509.CertPool,
	poolErr error, resolved bool) Check {
	name := "tls." + target.Name
	if poolErr != nil {
		return Fail(name, "bootstrap_ca_invalid", poolErr.Error())
	}
	if !resolved {
		return NotRun(name, fmt.Sprintf("%s did not resolve; see dns.%s", target.Host, target.Name))
	}
	ctx, cancel := context.WithTimeout(ctx, n.Timeout)
	defer cancel()

	conn, err := n.Dial(ctx, "tcp", net.JoinHostPort(target.Host, target.Port))
	if err != nil {
		return Fail(name, "connect_failed", fmt.Sprintf("%s:%s: %v", target.Host, target.Port, err))
	}
	defer conn.Close()

	client := tls.Client(conn, &tls.Config{ServerName: target.Host, RootCAs: pool, MinVersion: tls.VersionTLS12})
	if err := client.HandshakeContext(ctx); err != nil {
		code, detail := TLSError(target.Host, err)
		return Fail(name, code, detail)
	}
	state := client.ConnectionState()
	description := "without a server certificate"
	if len(state.PeerCertificates) > 0 {
		server := state.PeerCertificates[0]
		description = fmt.Sprintf("%s, valid until %s", server.Subject.CommonName,
			server.NotAfter.UTC().Format(time.RFC3339))
	}
	return Pass(name, fmt.Sprintf("%s (%s)", description, TLSVersion(state.Version)))
}

// TLSError maps a handshake error onto a stable code and a detail that says
// what to fix.
//
// The codes are the ones of the enrollment document: a playbook compares the
// code, a person reads the detail.
func TLSError(host string, err error) (code, detail string) {
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

// TLSVersion names the protocol version of a handshake.
func TLSVersion(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	}
	return fmt.Sprintf("0x%04x", version)
}

// TrustPool assembles the trust for checking the connections out of PEM
// files: the trust bundle of the identity when the component has one, and
// the bootstrap CA from the configuration.
//
// Nothing configured means the system roots, which is the public-CA variant
// of the bootstrap. A configured bundle that cannot be read or parsed is an
// error of its own, not a silent fall back to the system roots.
func TrustPool(identityTrust []byte, bootstrapCA string, read func(string) ([]byte, error)) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	added := false
	if len(identityTrust) > 0 && pool.AppendCertsFromPEM(identityTrust) {
		added = true
	}
	if bootstrapCA != "" {
		content, err := read(bootstrapCA)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", bootstrapCA, err)
		}
		if !pool.AppendCertsFromPEM(content) {
			return nil, fmt.Errorf("%s holds no certificate", bootstrapCA)
		}
		added = true
	}
	if !added {
		return nil, nil
	}
	return pool, nil
}
