// Package metrics wystawia stan panelu w formacie tekstowym Prometheusa.
//
// Dokument wymaga SLO i alertow dla wieku kolejki, opoznienia dostarczania,
// liczby aktywnych sesji, bledow zadan i waznosci certyfikatow. Bez tego
// jedynym sposobem sprawdzenia panelu jest zagladanie do /proc i do bazy,
// czego nie da sie zrobic w instalacji klienta.
//
// Format jest generowany recznie: zestaw metryk jest niewielki i staly,
// a kazda zaleznosc w sciezce, ktora ma dzialac wlasnie wtedy, gdy panelowi
// dzieje sie zle, jest kosztem samym w sobie.
package metrics

import (
	"context"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// SessionCounter podaje liczbe aktywnych sesji agentow tej instancji.
type SessionCounter interface {
	Count() int
}

// CertificateSource podaje czas waznosci certyfikatu CA.
type CertificateSource interface {
	NotAfter() time.Time
}

type Collector struct {
	pool     *pgxpool.Pool
	sessions SessionCounter
	ca       CertificateSource
	gateway  string
	started  time.Time
}

func NewCollector(pool *pgxpool.Pool, sessions SessionCounter, ca CertificateSource,
	gatewayID string) *Collector {
	return &Collector{pool: pool, sessions: sessions, ca: ca,
		gateway: gatewayID, started: time.Now()}
}

// sample jest pojedyncza wartoscia z etykietami.
type sample struct {
	labels map[string]string
	value  float64
}

// metric grupuje wartosci pod jedna nazwa wraz z opisem.
type metric struct {
	name    string
	help    string
	kind    string
	samples []sample
}

// Gather zbiera stan panelu. Blad pojedynczego zapytania nie moze wygasic
// calej odpowiedzi: metryka, ktorej nie udalo sie ustalic, jest pomijana,
// a nie zerowana - zero znaczyloby "zmierzono zero".
func (c *Collector) Gather(ctx context.Context) []byte {
	metrics := []metric{
		{
			name: "flotestro_build_info", kind: "gauge",
			help:    "Instancja panelu; etykieta gateway odroznia procesy w instalacji wielobramkowej.",
			samples: []sample{{labels: map[string]string{"gateway": c.gateway}, value: 1}},
		},
		{
			name: "flotestro_uptime_seconds", kind: "gauge",
			help:    "Czas dzialania procesu panelu.",
			samples: []sample{{value: time.Since(c.started).Seconds()}},
		},
	}

	if c.sessions != nil {
		metrics = append(metrics, metric{
			name: "flotestro_agent_sessions_active", kind: "gauge",
			help: "Sesje agentow utrzymywane przez te instancje panelu.",
			samples: []sample{{
				labels: map[string]string{"gateway": c.gateway},
				value:  float64(c.sessions.Count()),
			}},
		})
	}

	if c.ca != nil {
		if notAfter := c.ca.NotAfter(); !notAfter.IsZero() {
			metrics = append(metrics, metric{
				name: "flotestro_ca_certificate_expires_in_seconds", kind: "gauge",
				help:    "Czas do wygasniecia certyfikatu CA floty.",
				samples: []sample{{value: time.Until(notAfter).Seconds()}},
			})
		}
	}

	metrics = append(metrics, c.runtimeMetrics()...)
	metrics = append(metrics, c.databaseMetrics(ctx)...)
	return render(metrics)
}

func (c *Collector) runtimeMetrics() []metric {
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	return []metric{
		{
			name: "flotestro_goroutines", kind: "gauge",
			help:    "Liczba goroutines procesu panelu.",
			samples: []sample{{value: float64(runtime.NumGoroutine())}},
		},
		{
			name: "flotestro_memory_bytes", kind: "gauge",
			help:    "Pamiec zarezerwowana przez proces panelu.",
			samples: []sample{{value: float64(memory.Sys)}},
		},
	}
}

// databaseMetrics czyta stan floty i kolejki. Zapytania sa agregatami po
// kolumnach z indeksami; scrape nie moze byc obciazeniem porownywalnym
// z praca panelu.
func (c *Collector) databaseMetrics(ctx context.Context) []metric {
	if c.pool == nil {
		return nil
	}
	queryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var result []metric

	if grouped, err := c.groupCount(queryCtx,
		`select connection_state, count(*) from hosts group by 1`); err == nil {
		result = append(result, metric{
			name: "flotestro_hosts", kind: "gauge",
			help:    "Hosty floty wedlug stanu polaczenia.",
			samples: labelled("connection_state", grouped),
		})
	}

	if grouped, err := c.groupCount(queryCtx,
		`select state, count(*) from jobs where created_at > now() - interval '24 hours' group by 1`); err == nil {
		result = append(result, metric{
			name: "flotestro_jobs", kind: "gauge",
			help:    "Zadania z ostatniej doby wedlug stanu.",
			samples: labelled("state", grouped),
		})
	}

	// Wiek najstarszego zadania w kolejce jest sygnalem, ze dostarczanie
	// przestalo nadazac. Sama liczba zadan tego nie pokazuje.
	var queueAge *float64
	if err := c.pool.QueryRow(queryCtx,
		`select extract(epoch from now() - min(created_at)) from jobs where state = 'queued'`).
		Scan(&queueAge); err == nil {
		wartosc := 0.0
		if queueAge != nil {
			wartosc = *queueAge
		}
		result = append(result, metric{
			name: "flotestro_job_queue_age_seconds", kind: "gauge",
			help:    "Wiek najstarszego zadania oczekujacego na dostarczenie.",
			samples: []sample{{value: wartosc}},
		})
	}

	// Opoznienie dostarczania liczymy od utworzenia zadania do przekazania go
	// agentowi. Czas rozpoczecia wykonania na hoscie nie jest agentowi
	// raportowany, wiec go tu nie ma - zamiast zgadywac, mierzymy to, co
	// panel faktycznie obserwuje.
	var avg, max *float64
	if err := c.pool.QueryRow(queryCtx, `
		select avg(extract(epoch from a.dispatched_at - j.created_at)),
		       max(extract(epoch from a.dispatched_at - j.created_at))
		from job_attempts a
		join jobs j on j.id = a.job_id
		where a.dispatched_at > now() - interval '15 minutes'`).Scan(&avg, &max); err == nil {
		if avg != nil {
			result = append(result, metric{
				name: "flotestro_dispatch_latency_seconds_avg", kind: "gauge",
				help:    "Sredni czas od utworzenia zadania do przekazania go agentowi, z ostatnich 15 minut.",
				samples: []sample{{value: *avg}},
			})
		}
		if max != nil {
			result = append(result, metric{
				name: "flotestro_dispatch_latency_seconds_max", kind: "gauge",
				help:    "Najdluzszy czas od utworzenia zadania do przekazania go agentowi, z ostatnich 15 minut.",
				samples: []sample{{value: *max}},
			})
		}
	}

	if grouped, err := c.groupCount(queryCtx, `
		select status, count(*) from job_attempts
		where finished_at > now() - interval '24 hours' group by 1`); err == nil {
		result = append(result, metric{
			name: "flotestro_task_results", kind: "gauge",
			help:    "Wyniki zadan z ostatniej doby wedlug statusu.",
			samples: labelled("status", grouped),
		})
	}

	return result
}

func (c *Collector) groupCount(ctx context.Context, query string) (map[string]float64, error) {
	rows, err := c.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	grouped := map[string]float64{}
	for rows.Next() {
		var key *string
		var count float64
		if err := rows.Scan(&key, &count); err != nil {
			return nil, err
		}
		nazwa := "unknown"
		if key != nil {
			nazwa = *key
		}
		grouped[nazwa] = count
	}
	return grouped, rows.Err()
}

func labelled(name string, grouped map[string]float64) []sample {
	klucze := make([]string, 0, len(grouped))
	for klucz := range grouped {
		klucze = append(klucze, klucz)
	}
	// Stala kolejnosc ulatwia porownywanie kolejnych scrape'ow okiem.
	sort.Strings(klucze)

	samples := make([]sample, 0, len(klucze))
	for _, klucz := range klucze {
		samples = append(samples, sample{
			labels: map[string]string{name: klucz}, value: grouped[klucz],
		})
	}
	return samples
}

func render(metrics []metric) []byte {
	var builder strings.Builder
	for _, m := range metrics {
		fmt.Fprintf(&builder, "# HELP %s %s\n", m.name, m.help)
		fmt.Fprintf(&builder, "# TYPE %s %s\n", m.name, m.kind)
		for _, s := range m.samples {
			builder.WriteString(m.name)
			if len(s.labels) > 0 {
				klucze := make([]string, 0, len(s.labels))
				for klucz := range s.labels {
					klucze = append(klucze, klucz)
				}
				sort.Strings(klucze)
				pary := make([]string, 0, len(klucze))
				for _, klucz := range klucze {
					// %q zabezpieczyloby wartosc drugi raz, dajac w wyniku
					// podwojne ukosniki; escape robi to raz i poprawnie.
					pary = append(pary, fmt.Sprintf(`%s="%s"`, klucz, escape(s.labels[klucz])))
				}
				builder.WriteString("{" + strings.Join(pary, ",") + "}")
			}
			fmt.Fprintf(&builder, " %g\n", s.value)
		}
	}
	return []byte(builder.String())
}

// escape zabezpiecza wartosc etykiety. Nazwa stanu pochodzi z bazy, a nie
// z kodu, wiec nie moze rozbic formatu odpowiedzi.
func escape(value string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return replacer.Replace(value)
}
