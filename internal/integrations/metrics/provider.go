// Package metrics reads the metrics from the system that already collects
// them.
//
// The panel has no time series database of its own and will not have one: the
// question "how much processor did this host use at three in the morning" has
// its answer in Prometheus, and duplicating it in the panel would mean a
// second database, a second retention problem and two different truths. The
// panel therefore shows somebody else's chart together with the name of the
// source and the time range - and says outright when the source does not
// answer.
package metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/integrations"
)

// Point is a single sample of a series.
type Point struct {
	At    time.Time `json:"at"`
	Value float64   `json:"value"`
}

// Series is a named run of values.
type Series struct {
	Name string `json:"name"`
	// Unit describes what the value is in - the panel does not guess it from
	// the name.
	Unit   string  `json:"unit,omitempty"`
	Points []Point `json:"points,omitempty"`
	// Last is the latest value. An empty pointer means missing data rather
	// than zero: a host without metrics and a host with zero load are
	// different things.
	Last *float64 `json:"last,omitempty"`
	// Query is the query the panel sent. The operator is to see where the
	// chart came from, so that they can repeat it at the source.
	Query string `json:"query,omitempty"`
	// UnavailableReason says why the series is missing.
	UnavailableReason string `json:"unavailable_reason,omitempty"`
}

// Query describes one panel of a chart.
type Query struct {
	Name   string
	Unit   string
	PromQL string
}

// Provider is a source of metrics.
type Provider interface {
	Name() string
	Configured() bool
	Health(ctx context.Context) integrations.State
	// Series computes the charts for one host.
	Series(ctx context.Context, label string, od, do time.Time) []Series
}

// Prometheus is the adapter of Prometheus and of everything that speaks its
// language.
type Prometheus struct {
	URL    string
	Client *http.Client
	Limit  time.Duration
	// Queries describe the panels of the chart. Empty means the default set.
	Queries []Query
	breaker *integrations.Breaker
}

// DefaultQueries are written for the vocabulary of node_exporter, because it
// is the de facto standard in the installations the panel connects to. An
// installation with a different set of metrics replaces them in the
// configuration instead of getting empty charts without an explanation.
func DefaultQueries() []Query {
	return []Query{
		{
			Name: "cpu", Unit: "%",
			PromQL: `100 - (avg by (instance) (rate(node_cpu_seconds_total{mode="idle",instance="%s"}[5m])) * 100)`,
		},
		{
			Name: "memory", Unit: "%",
			PromQL: `100 * (1 - node_memory_MemAvailable_bytes{instance="%s"} / node_memory_MemTotal_bytes{instance="%s"})`,
		},
		{
			Name: "load1", Unit: "",
			PromQL: `node_load1{instance="%s"}`,
		},
		{
			Name: "disk_root", Unit: "%",
			PromQL: `100 - (node_filesystem_avail_bytes{instance="%s",mountpoint="/"} / node_filesystem_size_bytes{instance="%s",mountpoint="/"} * 100)`,
		},
	}
}

// NewPrometheus creates the adapter. An empty address means an installation
// without metrics - and that is a correct state rather than a failure.
func NewPrometheus(address string, limit time.Duration, queries []Query) *Prometheus {
	if len(queries) == 0 {
		queries = DefaultQueries()
	}
	return &Prometheus{
		URL:     strings.TrimRight(address, "/"),
		Client:  &http.Client{Timeout: limit + time.Second},
		Limit:   limit,
		Queries: queries,
		breaker: integrations.NewBreaker(),
	}
}

func (p *Prometheus) Name() string { return "prometheus" }

func (p *Prometheus) Configured() bool { return p != nil && p.URL != "" }

// Health asks the source about its readiness.
func (p *Prometheus) Health(ctx context.Context) integrations.State {
	state := integrations.State{Name: p.Name(), Configured: p.Configured(), URL: p.URL}
	if !p.Configured() {
		state.Reason = "this installation has no metrics source configured"
		return state
	}
	if p.breaker.Open() {
		state.Reason = integrations.ErrBreakerOpen.Error()
		return state
	}
	queryCtx, cancel := integrations.WithTimeout(ctx, p.Limit)
	defer cancel()

	start := time.Now()
	err := p.breaker.Do(func() error {
		response, err := p.get(queryCtx, "/-/ready", nil)
		if err != nil {
			return err
		}
		response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return fmt.Errorf("the metrics source answered %s", response.Status)
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

// Series computes the charts for one host.
//
// An error of one panel must not take the others away: every series carries
// its own reason for being unavailable, and the operator sees the charts that
// could be computed.
func (p *Prometheus) Series(ctx context.Context, label string, od, do time.Time) []Series {
	result := make([]Series, 0, len(p.Queries))
	if !p.Configured() {
		return result
	}
	step := do.Sub(od) / 60
	if step < 15*time.Second {
		step = 15 * time.Second
	}
	for _, query := range p.Queries {
		series := Series{Name: query.Name, Unit: query.Unit}
		series.Query = substituteLabel(query.PromQL, label)
		points, err := p.rangeQuery(ctx, series.Query, od, do, step)
		if err != nil {
			series.UnavailableReason = err.Error()
			result = append(result, series)
			continue
		}
		series.Points = points
		if len(points) > 0 {
			last := points[len(points)-1].Value
			series.Last = &last
		}
		result = append(result, series)
	}
	return result
}

// substituteLabel puts the value of the label of a host into every place of a
// query.
func substituteLabel(query, label string) string {
	count := strings.Count(query, "%s")
	values := make([]any, count)
	for i := range values {
		values[i] = label
	}
	return fmt.Sprintf(query, values...)
}

// rangeQuery asks for a series in a window of time.
func (p *Prometheus) rangeQuery(ctx context.Context, query string,
	od, do time.Time, step time.Duration) ([]Point, error) {
	queryCtx, cancel := integrations.WithTimeout(ctx, p.Limit)
	defer cancel()

	params := url.Values{}
	params.Set("query", query)
	params.Set("start", strconv.FormatInt(od.Unix(), 10))
	params.Set("end", strconv.FormatInt(do.Unix(), 10))
	params.Set("step", strconv.Itoa(int(step.Seconds()))+"s")

	var points []Point
	err := p.breaker.Do(func() error {
		response, err := p.get(queryCtx, "/api/v1/query_range", params)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return fmt.Errorf("the metrics source answered %s", response.Status)
		}
		data, err := io.ReadAll(io.LimitReader(response.Body, 8<<20))
		if err != nil {
			return err
		}
		points, err = ParseRange(data)
		return err
	})
	if err != nil {
		return nil, err
	}
	return points, nil
}

// ParseRange reads the answer of query_range.
//
// We take the first series: the query of a panel is written to concern one
// host. Several series mean the label does not identify a host unambiguously -
// and it is then better to show one chart than a blend of several.
func ParseRange(data []byte) ([]Point, error) {
	var response struct {
		Status string `json:"status"`
		Error  string `json:"error"`
		Data   struct {
			Result []struct {
				Values [][2]json.RawMessage `json:"values"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, fmt.Errorf("the answer of the metrics source was not recognised: %w", err)
	}
	if response.Status != "success" {
		if response.Error != "" {
			return nil, fmt.Errorf("the metrics source: %s", response.Error)
		}
		return nil, fmt.Errorf("the metrics source rejected the query")
	}
	if len(response.Data.Result) == 0 {
		return nil, nil
	}
	var points []Point
	for _, pair := range response.Data.Result[0].Values {
		var mark float64
		if err := json.Unmarshal(pair[0], &mark); err != nil {
			continue
		}
		var text string
		if err := json.Unmarshal(pair[1], &text); err != nil {
			continue
		}
		value, err := strconv.ParseFloat(text, 64)
		if err != nil {
			// A NaN in a series is normal: it means a break in the collection
			// rather than a value of zero. We skip the point instead of
			// drawing a zero.
			continue
		}
		points = append(points, Point{
			At:    time.Unix(int64(mark), 0).UTC(),
			Value: value,
		})
	}
	return points, nil
}

func (p *Prometheus) get(ctx context.Context, path string, params url.Values) (*http.Response, error) {
	address := p.URL + path
	if len(params) > 0 {
		address += "?" + params.Encode()
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, err
	}
	return p.Client.Do(request)
}
