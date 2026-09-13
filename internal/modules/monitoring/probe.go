// Package monitoring runs probes from the host.
//
// A probe answers the question central monitoring cannot ask: "what does this
// host see". An alert may say a service does not answer while it answers from
// the host - and then the problem is in the network between them, not in the
// service. That is why a probe is a per-host task and not another query to
// Prometheus.
//
// A probe changes nothing and needs no root, so it does not go through the
// helper: every trip through root has to be justified.
package monitoring

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// The kinds of probes.
const (
	ProbeHTTP = "http"
	ProbeTCP  = "tcp"
)

// MaxTimeout limits the wait for an answer.
const MaxTimeout = 60 * time.Second

// DefaultTimeout applies to a probe without a given limit.
const DefaultTimeout = 10 * time.Second

// maxBody limits the amount of the answer that is read. A probe checks whether
// the service answers - it does not fetch data from it.
const maxBody = 64 << 10

// Request describes one probe.
type Request struct {
	Kind string `json:"kind"`
	// Target is the address: a URL for an HTTP probe, host:port for TCP.
	Target string `json:"target"`
	// ExpectStatus is the expected response code. Zero means any code in the
	// 2xx and 3xx range.
	ExpectStatus int `json:"expect_status,omitempty"`
	// ExpectBody is a fragment of the body that is to be found in the answer.
	ExpectBody     string `json:"expect_body,omitempty"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
}

// Result describes what the host saw.
type Result struct {
	Kind   string `json:"kind"`
	Target string `json:"target"`
	// Reachable says whether the connection came about.
	Reachable bool `json:"reachable"`
	// Passed says whether the answer met the expectations of the request. These
	// are two different things: a service can answer and answer wrongly.
	Passed         bool  `json:"passed"`
	StatusCode     *int  `json:"status_code,omitempty"`
	DurationMillis int64 `json:"duration_millis"`
	BodyMatched    *bool `json:"body_matched,omitempty"`
	// TLSExpiry is the deadline of the certificate the service presented. Empty
	// means a connection without TLS or no certificate.
	TLSExpiry  *time.Time `json:"tls_expiry,omitempty"`
	TLSIssuer  string     `json:"tls_issuer,omitempty"`
	Error      string     `json:"error,omitempty"`
	ObservedAt time.Time  `json:"observed_at"`
}

// Validate checks the probe request.
func (r Request) Validate() error {
	if r.TimeoutSeconds < 0 || time.Duration(r.TimeoutSeconds)*time.Second > MaxTimeout {
		return fmt.Errorf("the probe timeout is outside the range 0-%s", MaxTimeout)
	}
	if strings.ContainsAny(r.Target, " \t\n\r") || r.Target == "" {
		return fmt.Errorf("the probe target is empty or contains a forbidden character")
	}
	switch r.Kind {
	case ProbeHTTP:
		address, err := url.Parse(r.Target)
		if err != nil || address.Host == "" {
			return fmt.Errorf("the probe target %q is not a valid address", r.Target)
		}
		// The probe speaks HTTP and not any protocol: "file://" or "gopher://"
		// is not a check of a service but a read of the host.
		if address.Scheme != "http" && address.Scheme != "https" {
			return fmt.Errorf("the HTTP probe supports only http and https")
		}
		if r.ExpectStatus != 0 && (r.ExpectStatus < 100 || r.ExpectStatus > 599) {
			return fmt.Errorf("the expected response code %d is out of range", r.ExpectStatus)
		}
		if len(r.ExpectBody) > 512 {
			return fmt.Errorf("the expected body fragment is too long")
		}
	case ProbeTCP:
		host, port, err := net.SplitHostPort(r.Target)
		if err != nil || host == "" || port == "" {
			return fmt.Errorf("the probe target %q does not have the form host:port", r.Target)
		}
	default:
		return fmt.Errorf("unknown probe kind %q", r.Kind)
	}
	return nil
}

// Run carries the probe out and describes what the host saw.
func Run(ctx context.Context, request Request) Result {
	result := Result{Kind: request.Kind, Target: request.Target, ObservedAt: time.Now().UTC()}
	if err := request.Validate(); err != nil {
		result.Error = err.Error()
		return result
	}
	limit := time.Duration(request.TimeoutSeconds) * time.Second
	if limit <= 0 {
		limit = DefaultTimeout
	}
	probeCtx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()

	start := time.Now()
	switch request.Kind {
	case ProbeTCP:
		result = probeTCP(probeCtx, request, result)
	default:
		result = probeHTTP(probeCtx, request, result)
	}
	result.DurationMillis = time.Since(start).Milliseconds()
	return result
}

// probeTCP checks whether a connection can be opened.
func probeTCP(ctx context.Context, request Request, result Result) Result {
	dialer := &net.Dialer{}
	connection, err := dialer.DialContext(ctx, "tcp", request.Target)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer connection.Close()
	result.Reachable = true
	result.Passed = true
	return result
}

// probeHTTP checks what the service answers.
//
// The certificate is checked against the trust store of the host and not of the
// panel: the question is "can this host use this service", not "do I trust
// it".
func probeHTTP(ctx context.Context, request Request, result Result) Result {
	client := &http.Client{
		// Redirects are followed, but not forever: a redirect loop is a failure
		// of the service, not an answer.
		CheckRedirect: func(_ *http.Request, previous []*http.Request) error {
			if len(previous) >= 5 {
				return fmt.Errorf("the service redirects in a loop")
			}
			return nil
		},
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, request.Target, nil)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	httpRequest.Header.Set("User-Agent", "flotestro-probe/1")

	response, err := client.Do(httpRequest)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer response.Body.Close()
	result.Reachable = true
	code := response.StatusCode
	result.StatusCode = &code

	if response.TLS != nil && len(response.TLS.PeerCertificates) > 0 {
		leaf := response.TLS.PeerCertificates[0]
		deadline := leaf.NotAfter.UTC()
		result.TLSExpiry = &deadline
		result.TLSIssuer = leaf.Issuer.String()
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, maxBody))
	if err != nil {
		result.Error = err.Error()
		return result
	}
	if request.ExpectBody != "" {
		contains := strings.Contains(string(body), request.ExpectBody)
		result.BodyMatched = &contains
	}

	result.Passed = codeMatches(code, request.ExpectStatus) &&
		(result.BodyMatched == nil || *result.BodyMatched)
	if !result.Passed && result.Error == "" {
		result.Error = describeMismatch(code, request, result)
	}
	return result
}

func codeMatches(code, expected int) bool {
	if expected != 0 {
		return code == expected
	}
	return code >= 200 && code < 400
}

func describeMismatch(code int, request Request, result Result) string {
	if !codeMatches(code, request.ExpectStatus) {
		if request.ExpectStatus != 0 {
			return fmt.Sprintf("the service answered %d, expected %d", code, request.ExpectStatus)
		}
		return fmt.Sprintf("the service answered %d", code)
	}
	if result.BodyMatched != nil && !*result.BodyMatched {
		return "the answer does not contain the expected fragment"
	}
	return ""
}

// The tls import is here only to say that there is no "skip verification":
// the probe does not switch the certificate check off. A service with a
// certificate the host does not trust is a service this host will not use -
// and that is the answer of the probe, not a detail to skip.
var _ = tls.Config{}
