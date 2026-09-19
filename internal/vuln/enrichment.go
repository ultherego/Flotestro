package vuln

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
)

// CVEDetails are what an upstream source says about the vulnerability itself.
// This is enrichment, not a verdict.
type CVEDetails struct {
	CVE          string     `json:"cve"`
	Source       string     `json:"source"`
	CVSSScore    *float64   `json:"cvss_score,omitempty"`
	CVSSSeverity string     `json:"cvss_severity,omitempty"`
	CVSSVector   string     `json:"cvss_vector,omitempty"`
	CVSSVersion  string     `json:"cvss_version,omitempty"`
	Summary      string     `json:"summary,omitempty"`
	PublishedAt  *time.Time `json:"published_at,omitempty"`
	ModifiedAt   *time.Time `json:"modified_at,omitempty"`
}

// DetailSource is the adapter of an enrichment source.
type DetailSource interface {
	Name() string
	Fetch(ctx context.Context, since time.Time,
		accept func([]CVEDetails) error) (time.Time, error)
}

// SaveDetails adds or refreshes the descriptions of vulnerabilities.
func (s *Store) SaveDetails(ctx context.Context, details []CVEDetails) error {
	if len(details) == 0 {
		return nil
	}
	const save = `
		insert into vuln_cve_details (cve, source, cvss_score, cvss_severity, cvss_vector,
		                              cvss_version, summary, published_at, modified_at, fetched_at)
		values ($1, $2, $3, $4, $5, $6, $7, $8, $9, now())
		on conflict (cve) do update set
			source = excluded.source, cvss_score = excluded.cvss_score,
			cvss_severity = excluded.cvss_severity, cvss_vector = excluded.cvss_vector,
			cvss_version = excluded.cvss_version, summary = excluded.summary,
			published_at = excluded.published_at, modified_at = excluded.modified_at,
			fetched_at = now()`
	batch := &pgx.Batch{}
	for _, entry := range details {
		if entry.CVE == "" {
			continue
		}
		batch.Queue(save, entry.CVE, entry.Source, entry.CVSSScore, entry.CVSSSeverity,
			entry.CVSSVector, entry.CVSSVersion, entry.Summary, entry.PublishedAt, entry.ModifiedAt)
	}
	if batch.Len() == 0 {
		return nil
	}
	results := s.pool.SendBatch(ctx, batch)
	defer results.Close()
	for i := 0; i < batch.Len(); i++ {
		if _, err := results.Exec(); err != nil {
			return err
		}
	}
	return nil
}

// Details reads the descriptions of the named vulnerabilities.
func (s *Store) Details(ctx context.Context, numbers []string) (map[string]CVEDetails, error) {
	result := map[string]CVEDetails{}
	if len(numbers) == 0 {
		return result, nil
	}
	const query = `
		select cve, source, cvss_score, cvss_severity, cvss_vector, cvss_version,
		       summary, published_at, modified_at
		from vuln_cve_details where cve = any($1)`
	rows, err := s.pool.Query(ctx, query, numbers)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var entry CVEDetails
		if err := rows.Scan(&entry.CVE, &entry.Source, &entry.CVSSScore, &entry.CVSSSeverity,
			&entry.CVSSVector, &entry.CVSSVersion, &entry.Summary, &entry.PublishedAt,
			&entry.ModifiedAt); err != nil {
			return nil, err
		}
		result[entry.CVE] = entry
	}
	return result, rows.Err()
}

// EnrichmentState says up to when a source has been read.
func (s *Store) EnrichmentState(ctx context.Context, source string) (time.Time, error) {
	var mark *time.Time
	err := s.pool.QueryRow(ctx,
		`select last_modified from vuln_enrichment_state where source = $1`, source).Scan(&mark)
	if err != nil {
		if err == pgx.ErrNoRows {
			return time.Time{}, nil
		}
		return time.Time{}, err
	}
	if mark == nil {
		return time.Time{}, nil
	}
	return mark.UTC(), nil
}

// SaveEnrichmentState records up to when a source has been read.
func (s *Store) SaveEnrichmentState(ctx context.Context, source string, mark time.Time,
	entries int, reason string) error {
	const save = `
		insert into vuln_enrichment_state (source, last_modified, entries, updated_at, error)
		values ($1, $2, $3, now(), $4)
		on conflict (source) do update set
			last_modified = coalesce(excluded.last_modified, vuln_enrichment_state.last_modified),
			entries = vuln_enrichment_state.entries + excluded.entries,
			updated_at = now(), error = excluded.error`
	var pointer *time.Time
	if !mark.IsZero() {
		moment := mark.UTC()
		pointer = &moment
	}
	_, err := s.pool.Exec(ctx, save, source, pointer, entries, reason)
	return err
}

// Enricher keeps the descriptions of vulnerabilities in the database of the
// panel.
type Enricher struct {
	store    *Store
	source   DetailSource
	interval time.Duration
	log      *slog.Logger
}

// NewEnricher creates the enrichment cycle.
func NewEnricher(store *Store, source DetailSource, interval time.Duration,
	log *slog.Logger) *Enricher {
	if interval <= 0 {
		interval = 6 * time.Hour
	}
	return &Enricher{store: store, source: source, interval: interval, log: log}
}

// Run carries the enrichment on until the context is closed.
func (w *Enricher) Run(ctx context.Context) {
	w.Cycle(ctx)
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.Cycle(ctx)
		}
	}
}

// Cycle fetches the descriptions changed since the last read.
func (w *Enricher) Cycle(ctx context.Context) {
	since, err := w.store.EnrichmentState(ctx, w.source.Name())
	if err != nil {
		w.log.Error("the enrichment state was not read", "source", w.source.Name(), "err", err)
		return
	}
	saved := 0
	mark, err := w.source.Fetch(ctx, since, func(page []CVEDetails) error {
		if err := w.store.SaveDetails(ctx, page); err != nil {
			return err
		}
		saved += len(page)
		return nil
	})
	if err != nil {
		// A failed fetch does not erase what is already there: descriptions from a
		// day ago are better than none, and the assessment does not use them anyway.
		w.log.Error("the vulnerability descriptions were not fetched", "source", w.source.Name(), "err", err)
		_ = w.store.SaveEnrichmentState(ctx, w.source.Name(), time.Time{}, saved, err.Error())
		return
	}
	if err := w.store.SaveEnrichmentState(ctx, w.source.Name(), mark, saved, ""); err != nil {
		w.log.Error("the enrichment state was not saved", "source", w.source.Name(), "err", err)
		return
	}
	if saved > 0 {
		w.log.Info("the vulnerability descriptions were refreshed", "source", w.source.Name(),
			"entries", saved, "until", mark)
	}
}
