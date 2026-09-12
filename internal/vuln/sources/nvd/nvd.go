// Package nvd reads the descriptions of vulnerabilities from the NVD
// database.
//
// This source settles nothing. Version ranges from NVD do not cover the
// fixes backported by a distribution vendor, so used to assess a host they
// would speak about something other than the installed package. The panel
// takes from here only what the vendor does not say: the CVSS score and the
// description of the vulnerability.
package nvd

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

	"github.com/ultherego/flotestro/internal/vuln"
)

// Provider is the name of the source written down with every description.
const Provider = "nvd"

// DefaultURL points at the NVD API in version 2.0.
const DefaultURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// PageSize is the largest one NVD allows.
const PageSize = 2000

// MaxWindow is the longest period NVD allows asking about at once.
const MaxWindow = 120 * 24 * time.Hour

// MaxResponse limits a single page of results.
const MaxResponse = 128 << 20

// The intervals between requests. NVD asks for five requests per thirty
// seconds without a key and fifty with one; exceeding that ends in being cut
// off.
const (
	IntervalWithoutKey = 6 * time.Second
	IntervalWithKey    = 700 * time.Millisecond
)

// Reader fetches the descriptions of vulnerabilities from NVD.
type Reader struct {
	URL    string
	Key    string
	Client *http.Client
	// Interval between requests; zero means the interval proper for the key.
	Interval time.Duration
}

// New creates a reader.
func New(address, key string, limit time.Duration) *Reader {
	if address == "" {
		address = DefaultURL
	}
	if limit <= 0 {
		limit = 5 * time.Minute
	}
	return &Reader{URL: address, Key: key, Client: &http.Client{Timeout: limit}}
}

func (c *Reader) Name() string { return Provider }

// interval returns the pause between requests.
func (c *Reader) interval() time.Duration {
	if c.Interval > 0 {
		return c.Interval
	}
	if c.Key != "" {
		return IntervalWithKey
	}
	return IntervalWithoutKey
}

// Fetch pulls the descriptions changed since the given moment, page by page.
//
// It returns the moment the data are read up to. When the previous read is
// older than the window one is allowed to ask about, we take the whole set:
// that takes longer, but it is the only thing that gives the full picture.
func (c *Reader) Fetch(ctx context.Context, since time.Time,
	accept func([]vuln.CVEDetails) error) (time.Time, error) {
	now := time.Now().UTC()
	full := since.IsZero() || now.Sub(since) > MaxWindow

	index := 0
	newest := since
	for {
		page, total, err := c.page(ctx, since, now, index, full)
		if err != nil {
			return time.Time{}, err
		}
		if len(page) == 0 {
			break
		}
		for _, entry := range page {
			if entry.ModifiedAt != nil && entry.ModifiedAt.After(newest) {
				newest = *entry.ModifiedAt
			}
		}
		if err := accept(page); err != nil {
			return time.Time{}, err
		}
		index += len(page)
		if index >= total {
			break
		}
		select {
		case <-ctx.Done():
			return time.Time{}, ctx.Err()
		case <-time.After(c.interval()):
		}
	}
	if newest.IsZero() {
		newest = now
	}
	return newest, nil
}

// page fetches one page of results.
func (c *Reader) page(ctx context.Context, since, now time.Time, index int,
	full bool) ([]vuln.CVEDetails, int, error) {
	params := url.Values{}
	params.Set("resultsPerPage", strconv.Itoa(PageSize))
	params.Set("startIndex", strconv.Itoa(index))
	if !full {
		params.Set("lastModStartDate", Timestamp(since))
		params.Set("lastModEndDate", Timestamp(now))
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.URL+"?"+params.Encode(), nil)
	if err != nil {
		return nil, 0, err
	}
	request.Header.Set("User-Agent", "flotestro-vuln/1")
	if c.Key != "" {
		request.Header.Set("apiKey", c.Key)
	}

	response, err := c.Client.Do(request)
	if err != nil {
		return nil, 0, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("NVD answered %s", response.Status)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, MaxResponse))
	if err != nil {
		return nil, 0, err
	}
	return Parse(body)
}

// Timestamp writes a moment in the form NVD expects.
func Timestamp(moment time.Time) string {
	return moment.UTC().Format("2006-01-02T15:04:05.000") + "Z"
}

// nvdResponse is the part of the answer the panel reads.
type nvdResponse struct {
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE cveEntry `json:"cve"`
	} `json:"vulnerabilities"`
}

type cveEntry struct {
	ID           string `json:"id"`
	Published    string `json:"published"`
	LastModified string `json:"lastModified"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics map[string][]metric `json:"metrics"`
}

// metric is one CVSS score given by NVD.
//
// The severity in version two stands next to the data rather than inside
// them: that is what an NVD answer looks like, and without it the scores
// from before CVSS 3 would be left without a word.
type metric struct {
	Type         string `json:"type"`
	BaseSeverity string `json:"baseSeverity"`
	CVSSData     struct {
		Version      string  `json:"version"`
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
		VectorString string  `json:"vectorString"`
	} `json:"cvssData"`
}

// Parse reads one page of an NVD answer.
func Parse(body []byte) ([]vuln.CVEDetails, int, error) {
	var response nvdResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, 0, fmt.Errorf("NVD answer: %w", err)
	}
	result := make([]vuln.CVEDetails, 0, len(response.Vulnerabilities))
	for _, entry := range response.Vulnerabilities {
		details := detailsFromEntry(entry.CVE)
		if details.CVE == "" {
			continue
		}
		result = append(result, details)
	}
	return result, response.TotalResults, nil
}

// detailsFromEntry translates one NVD entry into a description of the panel.
func detailsFromEntry(entry cveEntry) vuln.CVEDetails {
	details := vuln.CVEDetails{
		CVE:    strings.ToValidUTF8(strings.TrimSpace(entry.ID), ""),
		Source: Provider,
	}
	for _, description := range entry.Descriptions {
		if description.Lang == "en" {
			details.Summary = shortened(description.Value)
			break
		}
	}
	if score, version, severity, vector, ok := BestScore(entry.Metrics); ok {
		details.CVSSScore = &score
		details.CVSSVersion = version
		details.CVSSSeverity = strings.ToLower(severity)
		details.CVSSVector = vector
	}
	details.PublishedAt = timestamp(entry.Published)
	details.ModifiedAt = timestamp(entry.LastModified)
	return details
}

// MetricOrder says which score wins when there are several.
//
// A newer version of CVSS describes the same vulnerability more precisely,
// so we take the newest one the source gave - rather than the first one at
// hand.
var MetricOrder = []string{"cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"}

// BestScore picks the CVSS score out of the metrics of an entry.
func BestScore(metrics map[string][]metric) (float64, string, string, string, bool) {
	for _, name := range MetricOrder {
		entries := metrics[name]
		if len(entries) == 0 {
			continue
		}
		chosen := entries[0]
		// A score from the producer of the data takes precedence over a
		// secondary one.
		for _, entry := range entries {
			if strings.EqualFold(entry.Type, "Primary") {
				chosen = entry
				break
			}
		}
		data := chosen.CVSSData
		if data.BaseScore == 0 && data.VectorString == "" {
			continue
		}
		severity := data.BaseSeverity
		if severity == "" {
			severity = chosen.BaseSeverity
		}
		return data.BaseScore, data.Version, severity, data.VectorString, true
	}
	return 0, "", "", "", false
}

// timestamp reads an NVD timestamp. The timestamps arrive without a zone and
// are in UTC.
func timestamp(mark string) *time.Time {
	mark = strings.TrimSpace(mark)
	if mark == "" {
		return nil
	}
	for _, layout := range []string{"2006-01-02T15:04:05.000", "2006-01-02T15:04:05", time.RFC3339} {
		if moment, err := time.Parse(layout, mark); err == nil {
			momentUTC := moment.UTC()
			return &momentUTC
		}
	}
	return nil
}

// shortened trims a description to 500 characters rather than bytes.
func shortened(description string) string {
	description = strings.ToValidUTF8(strings.TrimSpace(description), "")
	runes := []rune(description)
	if len(runes) > 500 {
		return string(runes[:500])
	}
	return description
}
