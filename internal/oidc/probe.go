package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// The connection test of the provider.

// Probe is what one round trip to the provider found: the issuer the discovery
// document names, where the signing keys are and how many of them there were.
type Probe struct {
	Issuer  string `json:"issuer"`
	JWKSURL string `json:"jwks_url"`
	Keys    int    `json:"keys"`
	// Elapsed is how long both fetches took together.
	Elapsed time.Duration `json:"-"`
	At      time.Time     `json:"at"`
}

// ProbeTimeout bounds the connection test: a provider that takes longer
// to answer a discovery document is one the login would time out on too.
const ProbeTimeout = 5 * time.Second

// probeBodyLimit caps a discovery document or a key set. Both are a few
// kilobytes; a megabyte here is a proxy's error page, not a provider.
const probeBodyLimit = 1 << 20

// Probe fetches the discovery document and the signing keys it points at.
func (p *Provider) Probe(ctx context.Context) (Probe, error) {
	result, err := p.probe(ctx)
	p.rememberProbe(result, err)
	return result, err
}

func (p *Provider) probe(ctx context.Context) (Probe, error) {
	ctx, cancel := context.WithTimeout(ctx, ProbeTimeout)
	defer cancel()
	started := time.Now()

	var discovery struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := p.fetchJSON(ctx, p.Issuer()+"/.well-known/openid-configuration", &discovery); err != nil {
		return Probe{}, fmt.Errorf("discovery_unreachable: %w", err)
	}
	// The issuer of the document has to be the one the panel was told, or every
	// token the provider signs is refused at login for the wrong issuer - the
	// check go-oidc makes on every ID token.
	if strings.TrimSuffix(discovery.Issuer, "/") != p.Issuer() {
		return Probe{}, fmt.Errorf("issuer_mismatch: the discovery document names %q, the panel is configured for %q",
			discovery.Issuer, p.Issuer())
	}
	if discovery.JWKSURI == "" {
		return Probe{}, fmt.Errorf("jwks_missing: the discovery document names no jwks_uri")
	}

	var keySet struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := p.fetchJSON(ctx, discovery.JWKSURI, &keySet); err != nil {
		return Probe{}, fmt.Errorf("jwks_unreachable: %w", err)
	}
	if len(keySet.Keys) == 0 {
		return Probe{}, fmt.Errorf("jwks_empty: the provider publishes no signing key")
	}

	return Probe{
		Issuer:  discovery.Issuer,
		JWKSURL: discovery.JWKSURI,
		Keys:    len(keySet.Keys),
		Elapsed: time.Since(started),
		At:      time.Now().UTC(),
	}, nil
}

// ProbeCached answers from the last probe when it is younger than maxAge, and
// probes otherwise.
func (p *Provider) ProbeCached(ctx context.Context, maxAge time.Duration) (Probe, error) {
	p.probeMu.Lock()
	fresh := !p.probeAt.IsZero() && time.Since(p.probeAt) < maxAge
	result, err := p.lastProbe, p.lastProbeErr
	p.probeMu.Unlock()
	if fresh {
		return result, err
	}
	return p.Probe(ctx)
}

func (p *Provider) rememberProbe(result Probe, err error) {
	p.probeMu.Lock()
	defer p.probeMu.Unlock()
	p.lastProbe, p.lastProbeErr, p.probeAt = result, err, time.Now()
}

// fetchJSON reads one JSON document over the provider's own HTTP client, so a
// private CA or a proxy configured for the login applies to the test as well.
func (p *Provider) fetchJSON(ctx context.Context, address string, out any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	response, err := p.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, probeBodyLimit))
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("%s answered %d", address, response.StatusCode)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("%s did not answer with JSON: %w", address, err)
	}
	return nil
}

// probeState is the memory of the last connection test, kept on the
// provider so the checklist does not ask on every read.
type probeState struct {
	probeMu      sync.Mutex
	lastProbe    Probe
	lastProbeErr error
	probeAt      time.Time
}
