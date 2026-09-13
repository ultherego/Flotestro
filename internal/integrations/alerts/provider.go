// Package alerts reads the alerts and creates silences in the system that
// manages them.
//
// The panel has no alert rules of its own and will not have any: a second
// definition of what a failure is would mean two different statements about
// the same host. A silence is created where the alerts are born - and always
// with a deadline, an owner and a reason, because a silence without a deadline
// is an alert switched off for good by somebody who is no longer with the
// company.
package alerts

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/integrations"
)

// MaxSilence limits a silence created from the panel.
//
// A silence longer than a day stops being "I know, I am working on it" and
// becomes switching the alert off. Such a switch-off has a different place and
// a different owner than a button in the panel of a host.
const MaxSilence = 24 * time.Hour

// DefaultSilence holds when the operator gives no other duration.
const DefaultSilence = 2 * time.Hour

// Alert is one alert as seen at the source.
type Alert struct {
	Name        string            `json:"name"`
	Severity    string            `json:"severity,omitempty"`
	State       string            `json:"state,omitempty"`
	Summary     string            `json:"summary,omitempty"`
	Description string            `json:"description,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	StartsAt    *time.Time        `json:"starts_at,omitempty"`
	// SilencedBy lists the silences that cover this alert.
	SilencedBy []string `json:"silenced_by,omitempty"`
	// GeneratorURL leads to the rule at the source; the panel does not copy
	// its content.
	GeneratorURL string `json:"generator_url,omitempty"`
}

// Silence is a silence of alerts.
type Silence struct {
	ID string `json:"id,omitempty"`
	// Matchers describe what the silence covers.
	Matchers  []Matcher `json:"matchers"`
	StartsAt  time.Time `json:"starts_at"`
	EndsAt    time.Time `json:"ends_at"`
	CreatedBy string    `json:"created_by"`
	Comment   string    `json:"comment"`
	Status    string    `json:"status,omitempty"`
}

// Matcher is one condition of a silence.
type Matcher struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	IsRegex bool   `json:"is_regex,omitempty"`
}

// Provider is a source of alerts.
type Provider interface {
	Name() string
	Configured() bool
	Health(ctx context.Context) integrations.State
	Alerts(ctx context.Context, filters []string) ([]Alert, error)
	Silences(ctx context.Context, filters []string) ([]Silence, error)
	Silence(ctx context.Context, silence Silence) (string, error)
	Unsilence(ctx context.Context, id string) error
}

// Alertmanager is the adapter of Alertmanager.
type Alertmanager struct {
	URL     string
	Client  *http.Client
	Limit   time.Duration
	breaker *integrations.Breaker
}

// NewAlertmanager creates the adapter. An empty address means an installation
// without alerts.
func NewAlertmanager(address string, limit time.Duration) *Alertmanager {
	return &Alertmanager{
		URL:     strings.TrimRight(address, "/"),
		Client:  &http.Client{Timeout: limit + time.Second},
		Limit:   limit,
		breaker: integrations.NewBreaker(),
	}
}

func (a *Alertmanager) Name() string { return "alertmanager" }

func (a *Alertmanager) Configured() bool { return a != nil && a.URL != "" }

// Health asks the source about its readiness.
func (a *Alertmanager) Health(ctx context.Context) integrations.State {
	state := integrations.State{Name: a.Name(), Configured: a.Configured(), URL: a.URL}
	if !a.Configured() {
		state.Reason = "this installation has no alert source configured"
		return state
	}
	if a.breaker.Open() {
		state.Reason = integrations.ErrBreakerOpen.Error()
		return state
	}
	queryCtx, cancel := integrations.WithTimeout(ctx, a.Limit)
	defer cancel()

	start := time.Now()
	err := a.breaker.Do(func() error {
		response, err := a.send(queryCtx, http.MethodGet, "/-/ready", nil, nil)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return fmt.Errorf("the alert source answered %s", response.Status)
		}
		return nil
	})
	elapsed := time.Since(start).Milliseconds()
	checked := time.Now().UTC()
	state.LatencyMillis = &elapsed
	state.CheckedAt = &checked
	if err != nil {
		state.Reason = err.Error()
		return state
	}
	state.Healthy = true
	return state
}

// Alerts reads the active alerts matching the filters.
func (a *Alertmanager) Alerts(ctx context.Context, filters []string) ([]Alert, error) {
	if !a.Configured() {
		return nil, nil
	}
	params := url.Values{}
	for _, filter := range filters {
		params.Add("filter", filter)
	}
	params.Set("silenced", "true")
	params.Set("active", "true")
	params.Set("inhibited", "false")

	var alerty []Alert
	err := a.ask(ctx, http.MethodGet, "/api/v2/alerts", params, nil, func(data []byte) error {
		var result []struct {
			Labels       map[string]string `json:"labels"`
			Annotations  map[string]string `json:"annotations"`
			StartsAt     time.Time         `json:"startsAt"`
			GeneratorURL string            `json:"generatorURL"`
			Status       struct {
				State      string   `json:"state"`
				SilencedBy []string `json:"silencedBy"`
			} `json:"status"`
		}
		if err := json.Unmarshal(data, &result); err != nil {
			return fmt.Errorf("the answer of the alert source was not recognised: %w", err)
		}
		for _, entry := range result {
			start := entry.StartsAt.UTC()
			alerty = append(alerty, Alert{
				Name:         entry.Labels["alertname"],
				Severity:     entry.Labels["severity"],
				State:        entry.Status.State,
				Summary:      entry.Annotations["summary"],
				Description:  entry.Annotations["description"],
				Labels:       entry.Labels,
				StartsAt:     &start,
				SilencedBy:   entry.Status.SilencedBy,
				GeneratorURL: entry.GeneratorURL,
			})
		}
		return nil
	})
	return alerty, err
}

// Silences reads the silences matching the filters.
func (a *Alertmanager) Silences(ctx context.Context, filters []string) ([]Silence, error) {
	if !a.Configured() {
		return nil, nil
	}
	params := url.Values{}
	for _, filter := range filters {
		params.Add("filter", filter)
	}
	var ciszy []Silence
	err := a.ask(ctx, http.MethodGet, "/api/v2/silences", params, nil, func(data []byte) error {
		var result []struct {
			ID        string    `json:"id"`
			StartsAt  time.Time `json:"startsAt"`
			EndsAt    time.Time `json:"endsAt"`
			CreatedBy string    `json:"createdBy"`
			Comment   string    `json:"comment"`
			Status    struct {
				State string `json:"state"`
			} `json:"status"`
			Matchers []struct {
				Name    string `json:"name"`
				Value   string `json:"value"`
				IsRegex bool   `json:"isRegex"`
			} `json:"matchers"`
		}
		if err := json.Unmarshal(data, &result); err != nil {
			return fmt.Errorf("the answer of the alert source was not recognised: %w", err)
		}
		for _, entry := range result {
			// An expired silence is history rather than state: we show the
			// ones still in force or about to come into force.
			if entry.Status.State == "expired" {
				continue
			}
			silence := Silence{
				ID: entry.ID, StartsAt: entry.StartsAt.UTC(), EndsAt: entry.EndsAt.UTC(),
				CreatedBy: entry.CreatedBy, Comment: entry.Comment, Status: entry.Status.State,
			}
			for _, matcher := range entry.Matchers {
				silence.Matchers = append(silence.Matchers, Matcher{
					Name: matcher.Name, Value: matcher.Value, IsRegex: matcher.IsRegex,
				})
			}
			ciszy = append(ciszy, silence)
		}
		return nil
	})
	return ciszy, err
}

// Silence creates a silence and returns its identifier.
func (a *Alertmanager) Silence(ctx context.Context, silence Silence) (string, error) {
	if !a.Configured() {
		return "", fmt.Errorf("this installation has no alert source")
	}
	if err := ValidateSilence(silence); err != nil {
		return "", err
	}
	body, err := json.Marshal(map[string]any{
		"matchers":  matchersJSON(silence.Matchers),
		"startsAt":  silence.StartsAt.UTC().Format(time.RFC3339),
		"endsAt":    silence.EndsAt.UTC().Format(time.RFC3339),
		"createdBy": silence.CreatedBy,
		"comment":   silence.Comment,
	})
	if err != nil {
		return "", err
	}
	var identyfikator string
	err = a.ask(ctx, http.MethodPost, "/api/v2/silences", nil, body, func(data []byte) error {
		var result struct {
			SilenceID string `json:"silenceID"`
		}
		if err := json.Unmarshal(data, &result); err != nil {
			return fmt.Errorf("the answer of the alert source was not recognised: %w", err)
		}
		identyfikator = result.SilenceID
		return nil
	})
	return identyfikator, err
}

// Unsilence ends a silence ahead of time.
func (a *Alertmanager) Unsilence(ctx context.Context, id string) error {
	if !a.Configured() {
		return fmt.Errorf("this installation has no alert source")
	}
	if id == "" || strings.ContainsAny(id, "/?#") {
		return fmt.Errorf("an invalid identifier of a silence")
	}
	return a.ask(ctx, http.MethodDelete, "/api/v2/silence/"+url.PathEscape(id), nil, nil, nil)
}

// ValidateSilence checks a silence before it is sent.
//
// A silence without a deadline is an alert switched off for good; a silence
// without a reason is an alert switched off for who knows why. Neither may
// leave the panel.
func ValidateSilence(silence Silence) error {
	if len(silence.Matchers) == 0 {
		return fmt.Errorf("a silence has to name what it covers")
	}
	for _, matcher := range silence.Matchers {
		if matcher.Name == "" || strings.ContainsAny(matcher.Name, " \t\n=") {
			return fmt.Errorf("an invalid name of a label %q", matcher.Name)
		}
		if strings.ContainsAny(matcher.Value, "\n") {
			return fmt.Errorf("the value of a label contains a newline character")
		}
	}
	if silence.EndsAt.IsZero() || !silence.EndsAt.After(silence.StartsAt) {
		return fmt.Errorf("a silence requires an end date")
	}
	if silence.EndsAt.Sub(silence.StartsAt) > MaxSilence {
		return fmt.Errorf("a silence from the panel lasts at most %s", MaxSilence)
	}
	if len(strings.TrimSpace(silence.Comment)) < 8 {
		return fmt.Errorf("a silence requires a reason (at least 8 characters)")
	}
	if silence.CreatedBy == "" {
		return fmt.Errorf("a silence requires an owner")
	}
	return nil
}

func matchersJSON(matchers []Matcher) []map[string]any {
	result := make([]map[string]any, 0, len(matchers))
	for _, matcher := range matchers {
		result = append(result, map[string]any{
			"name": matcher.Name, "value": matcher.Value,
			"isRegex": matcher.IsRegex, "isEqual": true,
		})
	}
	return result
}

// ask sends a request through the breaker and passes the content of the
// answer on.
func (a *Alertmanager) ask(ctx context.Context, method, path string,
	params url.Values, body []byte, accept func([]byte) error) error {
	queryCtx, cancel := integrations.WithTimeout(ctx, a.Limit)
	defer cancel()

	return a.breaker.Do(func() error {
		response, err := a.send(queryCtx, method, path, params, body)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		data, err := io.ReadAll(io.LimitReader(response.Body, 8<<20))
		if err != nil {
			return err
		}
		if response.StatusCode >= 300 {
			description := strings.TrimSpace(string(data))
			if len(description) > 200 {
				description = description[:200]
			}
			return fmt.Errorf("the alert source answered %s: %s", response.Status, description)
		}
		if accept == nil {
			return nil
		}
		return accept(data)
	})
}

func (a *Alertmanager) send(ctx context.Context, method, path string,
	params url.Values, payload []byte) (*http.Response, error) {
	address := a.URL + path
	if len(params) > 0 {
		address += "?" + params.Encode()
	}
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}
	request, err := http.NewRequestWithContext(ctx, method, address, body)
	if err != nil {
		return nil, err
	}
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	return a.Client.Do(request)
}
