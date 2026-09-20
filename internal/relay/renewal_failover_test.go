package relay

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/endpoints"
	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
)

// quickGateways builds a manager with a pause short enough for a test: the
// order of the addresses is what matters here, not the length of the backoff.
func quickGateways(addresses ...string) *endpoints.Manager {
	return endpoints.New(addresses, time.Millisecond, time.Millisecond)
}

// TestTheRenewalFailsOverToALaterGateway guards what the gateway list is for:
// a relay whose first centre is down for the whole renewal window still
// renews, instead of letting its certificate expire beside a centre that
// answers.
func TestTheRenewalFailsOverToALaterGateway(t *testing.T) {
	var tried []string
	message, answered, err := requestCertificate(context.Background(),
		quickGateways("https://a:8443", "https://b:8443", "https://c:8443"),
		func(_ context.Context, gatewayURL string) (*agentv1.RenewRelayCertificateResponse, error) {
			tried = append(tried, gatewayURL)
			if gatewayURL != "https://b:8443" {
				return nil, errors.New("the renewal was rejected: dial tcp: connect: connection refused")
			}
			return &agentv1.RenewRelayCertificateResponse{CertificatePem: []byte("certificate")}, nil
		})
	if err != nil {
		t.Fatalf("the renewal gave up although a gateway answered: %v", err)
	}
	if answered != "https://b:8443" {
		t.Fatalf("the gateway that answered = %q", answered)
	}
	if len(tried) != 2 || tried[0] != "https://a:8443" || tried[1] != "https://b:8443" {
		t.Fatalf("the addresses were tried as %v", tried)
	}
	if string(message.GetCertificatePem()) != "certificate" {
		t.Fatalf("the certificate of the answer = %q", message.GetCertificatePem())
	}
}

// TestARenewalThatReachedNoGatewaySaysWhatItTried guards the honesty of the
// failure: a renewal nobody answered is reported with every address, and is
// not to be mistaken for a renewal that was not due.
func TestARenewalThatReachedNoGatewaySaysWhatItTried(t *testing.T) {
	addresses := []string{"https://a:8443", "https://b:8443"}
	message, answered, err := requestCertificate(context.Background(),
		quickGateways(addresses...),
		func(_ context.Context, _ string) (*agentv1.RenewRelayCertificateResponse, error) {
			return nil, errors.New("the renewal was rejected: dial tcp: connect: connection refused")
		})
	if err == nil {
		t.Fatal("a renewal that reached no gateway was reported as a success")
	}
	if message != nil || answered != "" {
		t.Fatalf("a failed renewal returned %v from %q", message, answered)
	}
	var failover *endpoints.Failover
	if !errors.As(err, &failover) {
		t.Fatalf("the answer of a total outage = %v", err)
	}
	for _, address := range addresses {
		if !strings.Contains(err.Error(), address) {
			t.Errorf("the failure does not name %s: %s", address, err)
		}
	}
}

// TestARevokedIdentityEndsTheRenewal guards the doctrine of the class: no
// gateway will renew a certificate the panel revoked, so the rest of the list
// is not walked.
func TestARevokedIdentityEndsTheRenewal(t *testing.T) {
	tried := 0
	_, _, err := requestCertificate(context.Background(),
		quickGateways("https://a:8443", "https://b:8443"),
		func(_ context.Context, _ string) (*agentv1.RenewRelayCertificateResponse, error) {
			tried++
			return nil, errors.New("the renewal was rejected: the certificate was revoked")
		})
	if !errors.Is(err, endpoints.ErrIdentityRejected) {
		t.Fatalf("the answer = %v", err)
	}
	if tried != 1 {
		t.Fatalf("the addresses tried = %d; a revoked identity is not a matter of the address", tried)
	}
}
