//go:build integration

package integration

import (
	"context"
	"encoding/csv"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// The fleet screens used to read the first five hundred hosts and add them up
// in the panel.

const (
	// scaleSite and scaleEnvironment place the synthetic fleet apart from
	// the lab hosts, so a principal can be scoped to it exactly.
	scaleSite        = "scale-test"
	scaleEnvironment = "test"
	// scaleHosts is one host past the five hundred the old screens read and past
	// the five hundred a page may hold, so a screen that still counted a page
	// would be caught by both bounds.
	scaleHosts = 1001
	// scaleFacts is how many of them report the fact each screen judges by.
	scaleFacts = 300
	// scaleCVEs is how many distinct CVEs the assessed hosts carry between
	// them: more than one page of the CVE list asks for below.
	scaleCVEs = 60
)

// fleetCoverageView is the head every fleet view answers with: the fleet in
// scope, the part of it the numbers describe, and the part nothing is known
// about.
type fleetCoverageView struct {
	TotalHosts     int            `json:"total_hosts"`
	EvaluatedHosts int            `json:"evaluated_hosts"`
	UnknownHosts   int            `json:"unknown_hosts"`
	Partial        bool           `json:"partial"`
	PartialReason  string         `json:"partial_reason"`
	UnknownReasons map[string]int `json:"unknown_reasons"`
	// Total is the number of rows of the detail list across every page,
	// and Count the number on this one.
	Total      int    `json:"total"`
	Count      int    `json:"count"`
	NextCursor string `json:"next_cursor"`
}

// fleetViews are the four screens of a fleet, each under the address the
// panel reads it at.
var fleetViews = []struct {
	name string
	path string
}{
	{name: "security", path: "/api/v1/security"},
	{name: "backups", path: "/api/v1/backups"},
	{name: "certificates", path: "/api/v1/certificates"},
	{name: "vulnerabilities", path: "/api/v1/vulnerabilities"},
}

// insertScaleFleet brings the synthetic fleet into the database and gives the
// first scaleFacts hosts of it, by name, the fact each screen judges by.
func insertScaleFleet(t *testing.T, ctx context.Context, h *harness) {
	t.Helper()
	pool := h.database(ctx)
	t.Cleanup(func() {
		// The fragments, the definitions and the assessments hang off the
		// host rows and go with them.
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := pool.Exec(cleanup, "delete from hosts where site = $1", scaleSite); err != nil {
			t.Errorf("removing the synthetic fleet: %v", err)
		}
	})

	if _, err := pool.Exec(ctx, `
		insert into hosts (id, machine_id, hostname, site, environment, os_family, os_distribution,
		                   os_version, architecture, agent_version, connection_state, lifecycle_state,
		                   enrolled_at)
		select gen_random_uuid(), 'scale-test-' || n, 'scale-' || lpad(n::text, 5, '0'),
		       $1, $2, 'debian', 'debian', '12', 'x86_64', '0.54.0', 'offline', 'active', now()
		  from generate_series(1, $3) as n`, scaleSite, scaleEnvironment, scaleHosts); err != nil {
		t.Fatalf("inserting the synthetic fleet: %v", err)
	}

	// The first hosts by name carry the facts, so which host is judged is
	// the same for every screen and reads the same on the CSV export.
	const firstByName = `(select id from hosts where site = $1 order by hostname limit $2)`
	for _, statement := range []struct {
		what  string
		query string
	}{
		{
			what: "backup definitions",
			query: `insert into backup_definitions (host_id, name, tool, repository, paths, created_by, updated_by)
			        select id, 'scale-daily', 'restic', 'sftp:scale@backup:/srv/scale', array['/etc'],
			               'fleet scale test', 'fleet scale test'
			          from ` + firstByName,
		},
		{
			what: "certificate fragments",
			query: `insert into host_module_inventory (host_id, module, revision, source, payload, observed_at)
			        select id, 'certificates', 'scale-1', 'fleet scale test',
			               jsonb_build_object('certificates', jsonb_build_array(jsonb_build_object(
			                   'path', '/etc/ssl/scale.pem', 'subject', 'CN=scale', 'issuer', 'CN=scale-ca',
			                   'not_after', to_char((now() + interval '20 days') at time zone 'utc',
			                                        'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
			                   'source', 'watched', 'renewal', 'manual')),
			                   'tracking_known', true),
			               now()
			          from ` + firstByName,
		},
		{
			what: "sshd fragments",
			query: `insert into host_module_inventory (host_id, module, revision, source, payload, observed_at)
			        select id, 'ssh', 'scale-1', 'fleet scale test',
			               '{"unit":"sshd.service","permit_root_login":"no","password_authentication":"no"}'::jsonb,
			               now()
			          from ` + firstByName,
		},
		{
			what: "vulnerability assessments",
			query: `insert into vuln_host_state (host_id, distribution, release, provider,
			                                     packages_total, packages_covered, affected,
			                                     affected_with_vendor_fix, affected_no_fix, unknown,
			                                     coverage_reason, evaluated_at)
			        select id, 'debian', '12', 'debian-security-tracker', 120, 120, 2, 1, 1, 0, '', now()
			          from ` + firstByName,
		},
		{
			// One affected finding per assessed host, its CVE drawn from a
			// small pool, so the CVE list is longer than one page of it
			// while the fleet behind it stays the same.
			what: "vulnerability findings",
			query: `insert into vuln_findings (host_id, provider, advisory_id, cve_ids, distribution,
			                                  release, source_package, binary_package, architecture,
			                                  installed_version, fixed_version, state, vendor_severity,
			                                  vendor_fix, evaluated_at)
			        select ranked.id, 'debian-security-tracker', 'DSA-' || ranked.n,
			               array['CVE-2026-' || lpad((((ranked.n - 1) % ` + strconv.Itoa(scaleCVEs) + `) + 1)::text, 4, '0')],
			               'debian', '12', 'openssl', 'openssl', 'amd64', '1.0', '1.1',
			               'affected', 'high', 'known', now()
			          from (select id, row_number() over (order by hostname) as n
			                  from hosts where site = $1 order by hostname limit $2) ranked`,
		},
	} {
		if _, err := pool.Exec(ctx, statement.query, scaleSite, scaleFacts); err != nil {
			t.Fatalf("inserting the %s: %v", statement.what, err)
		}
	}
}

// insertScaleFanOut orders a read across the whole synthetic fleet by hand:
// the ceiling on a fan-out ordered through the API is far below this fleet,
// and what is under test is the page the panel reads it back through.
func insertScaleFanOut(t *testing.T, ctx context.Context, h *harness) string {
	t.Helper()
	pool := h.database(ctx)
	fanOutID := uuid.NewString()
	t.Cleanup(func() {
		// The jobs go with the hosts; the fan-out row is its own.
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := pool.Exec(cleanup, "delete from jobs where fanout_id = $1", fanOutID); err != nil {
			t.Errorf("removing the jobs of the synthetic fan-out: %v", err)
		}
		if _, err := pool.Exec(cleanup, "delete from read_fanouts where id = $1", fanOutID); err != nil {
			t.Errorf("removing the synthetic fan-out: %v", err)
		}
	})
	if _, err := pool.Exec(ctx, `
		insert into read_fanouts (id, action, payload, created_by, reason, host_count)
		values ($1, 'dns.resolve.test', '{}'::jsonb, 'fleet scale test', 'the scale guard', $2)`,
		fanOutID, scaleHosts); err != nil {
		t.Fatalf("ordering the synthetic fan-out: %v", err)
	}
	// One job per host, and only the hosts that carry the facts have
	// answered: the rest are still on their way.
	if _, err := pool.Exec(ctx, `
		insert into jobs (id, host_id, action_type, payload, payload_hash, idempotency_key, state,
		                  expires_at, created_by, fanout_id, result_status, finished_at)
		select gen_random_uuid(), ranked.id, 'dns.resolve.test', '{}'::jsonb, decode('00', 'hex'),
		       'scale-fanout-' || ranked.n,
		       case when ranked.n <= $3 then 'succeeded' else 'queued' end,
		       now() + interval '1 hour', 'fleet scale test', $1,
		       case when ranked.n <= $3 then 'ok' end,
		       case when ranked.n <= $3 then now() end
		  from (select id, row_number() over (order by hostname) as n
		          from hosts where site = $2) ranked`,
		fanOutID, scaleSite, scaleFacts); err != nil {
		t.Fatalf("ordering the jobs of the synthetic fan-out: %v", err)
	}
	return fanOutID
}

// TestFleetViewsCountTheWholeFleet is the guard of chapter 5: a fleet past the
// old five-hundred bound is counted whole, the hosts nothing is known about
// are counted apart rather than as clean ones, and the reader's scope bounds
// what the counts cover.
func TestFleetViewsCountTheWholeFleet(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	// What the administrator sees before the synthetic fleet arrives: the lab has
	// hosts of its own, so the fleet-wide number is read as a difference rather
	// than as an absolute.
	before := map[string]int{}
	for _, view := range fleetViews {
		var head fleetCoverageView
		h.get(view.path, &head)
		before[view.name] = head.TotalHosts
	}

	insertScaleFleet(t, ctx, h)

	// A viewer bound to the synthetic site alone, and one bound to a site with
	// nothing in it: the first must see the fleet exactly, the second must see
	// nothing at all.
	scoped := h.withToken(h.createPrincipal(uniqueSubject("scale-viewer"), []map[string]string{
		{"role": "viewer", "site": scaleSite, "environment": scaleEnvironment},
	}))
	elsewhere := h.withToken(h.createPrincipal(uniqueSubject("scale-elsewhere"), []map[string]string{
		{"role": "viewer", "site": "scale-nowhere", "environment": scaleEnvironment},
	}))

	for _, view := range fleetViews {
		t.Run(view.name, func(t *testing.T) {
			var admin fleetCoverageView
			h.get(view.path, &admin)
			if grew := admin.TotalHosts - before[view.name]; grew != scaleHosts {
				t.Errorf("the administrator's fleet grew by %d hosts, expected %d; the view still counts a page",
					grew, scaleHosts)
			}

			var head fleetCoverageView
			scoped.get(view.path, &head)
			if head.TotalHosts != scaleHosts {
				t.Errorf("total_hosts = %d, expected %d", head.TotalHosts, scaleHosts)
			}
			if head.EvaluatedHosts != scaleFacts {
				t.Errorf("evaluated_hosts = %d, expected %d", head.EvaluatedHosts, scaleFacts)
			}
			// The hosts without the fact are unknown, never a zero: this is
			// the whole point of the chapter.
			if want := scaleHosts - scaleFacts; head.UnknownHosts != want {
				t.Errorf("unknown_hosts = %d, expected %d", head.UnknownHosts, want)
			}
			if head.EvaluatedHosts+head.UnknownHosts != head.TotalHosts {
				t.Errorf("%d judged and %d unknown do not add up to %d hosts",
					head.EvaluatedHosts, head.UnknownHosts, head.TotalHosts)
			}
			if head.Partial && head.PartialReason == "" {
				t.Error("the answer says it is partial without saying why")
			}
			if !head.Partial && head.PartialReason != "" {
				t.Errorf("a whole answer carries the reason %q", head.PartialReason)
			}
			// A page bounds the rows, never the counts.
			if head.Count > 500 {
				t.Errorf("one page carried %d rows", head.Count)
			}

			var outside fleetCoverageView
			elsewhere.get(view.path, &outside)
			if outside.TotalHosts != 0 || outside.EvaluatedHosts != 0 || outside.UnknownHosts != 0 {
				t.Errorf("a principal scoped to another site sees %+v, expected nothing", outside)
			}
			if outside.Count != 0 {
				t.Errorf("a principal scoped to another site got %d rows", outside.Count)
			}
		})
	}

	t.Run("the cursor joins the pages of a list past the page bound", func(t *testing.T) {
		fleetListJoinsUpAcrossPages(t, scoped)
	})

	t.Run("a read of the whole fleet says how much of it answered", func(t *testing.T) {
		fanOutReadsTheWholeFanOut(t, ctx, h, scoped)
	})

	t.Run("the CVE list says how much of the fleet it speaks for", func(t *testing.T) {
		cveListCarriesTheCoverageOfTheFleet(t, scoped)
	})

	t.Run("the export carries every row the screen counted", func(t *testing.T) {
		var head fleetCoverageView
		scoped.get("/api/v1/backups", &head)
		if head.Total != scaleFacts {
			t.Fatalf("the screen counts %d definitions, expected %d", head.Total, scaleFacts)
		}
		rows := readExportRows(t, scoped, "/api/v1/backups?format=csv")
		if len(rows) != head.Total {
			t.Errorf("the file carries %d rows, the screen counted %d", len(rows), head.Total)
		}
	})
}

// fleetListJoinsUpAcrossPages walks the certificate list of the synthetic
// fleet with the cursor and checks that the pages join up: no row twice, none
// missing, and as many in the end as the screen counted.
func fleetListJoinsUpAcrossPages(t *testing.T, scoped *harness) {
	type page struct {
		fleetCoverageView
		Items []struct {
			HostID string `json:"host_id"`
			Path   string `json:"path"`
		} `json:"items"`
	}
	seen := map[string]bool{}
	address := "/api/v1/certificates?limit=100"
	total := 0
	for requests := 0; ; requests++ {
		if requests > 20 {
			t.Fatal("the certificate list never reached its last page")
		}
		var one page
		scoped.get(address, &one)
		total = one.Total
		for _, item := range one.Items {
			key := item.HostID + " " + item.Path
			if seen[key] {
				t.Fatalf("%s came twice", key)
			}
			seen[key] = true
		}
		if one.NextCursor == "" {
			break
		}
		address = "/api/v1/certificates?limit=100&cursor=" + one.NextCursor
	}
	if len(seen) != scaleFacts || total != scaleFacts {
		t.Errorf("the cursor walked %d rows and the screen counted %d, expected %d", len(seen), total, scaleFacts)
	}

	// A cursor this list did not issue is refused rather than read as the
	// key of nothing.
	scoped.do(http.MethodGet, "/api/v1/certificates?cursor=not-a-cursor", nil, nil, http.StatusBadRequest)
}

// readExportRows reads a CSV export and returns its data rows.
func readExportRows(t *testing.T, h *harness, path string) [][]string {
	t.Helper()
	body := h.text(path)
	records, err := csv.NewReader(strings.NewReader(body)).ReadAll()
	if err != nil {
		t.Fatalf("the export is not a CSV file: %v", err)
	}
	if len(records) == 0 {
		t.Fatal("the export has no header row")
	}
	rows := records[1:]
	if len(rows) > 0 {
		switch first := rows[len(rows)-1][0]; first {
		case "truncated", "error":
			t.Fatalf("the export stopped before its end: %v", rows[len(rows)-1])
		}
	}
	return rows
}

// fanOutPage is the fan-out page as the panel reads it: the coverage head,
// the four counts of the status bar and one page of hosts.
type fanOutPage struct {
	fleetCoverageView
	HostCount int `json:"host_count"`
	Counts    struct {
		Queued    int `json:"queued"`
		Running   int `json:"running"`
		Succeeded int `json:"succeeded"`
		Failed    int `json:"failed"`
	} `json:"counts"`
	Hosts []struct {
		JobID    string `json:"job_id"`
		HostID   string `json:"host_id"`
		Hostname string `json:"hostname"`
		State    string `json:"state"`
	} `json:"hosts"`
}

// fanOutReadsTheWholeFanOut checks that a read ordered across a fleet larger
// than one page counts every host of it, says that the page carries a part,
// and that the cursor walks the rest.
func fanOutReadsTheWholeFanOut(t *testing.T, ctx context.Context, h, scoped *harness) {
	fanOutID := insertScaleFanOut(t, ctx, h)

	var first fanOutPage
	scoped.get("/api/v1/reads/"+fanOutID, &first)
	if first.HostCount != scaleHosts || first.TotalHosts != scaleHosts {
		t.Errorf("the read covers %d hosts and the head counts %d, expected %d",
			first.HostCount, first.TotalHosts, scaleHosts)
	}
	// The status bar is the database's count over the fan-out, not the
	// page's: a read of a thousand hosts is not finished after a hundred.
	if first.Counts.Succeeded != scaleFacts || first.Counts.Queued != scaleHosts-scaleFacts {
		t.Errorf("counts = %+v, expected %d succeeded and %d queued",
			first.Counts, scaleFacts, scaleHosts-scaleFacts)
	}
	if first.EvaluatedHosts != scaleFacts {
		t.Errorf("evaluated_hosts = %d, expected %d", first.EvaluatedHosts, scaleFacts)
	}
	// A host still on its way has not answered; it is unknown, not a host
	// with nothing to say.
	if want := scaleHosts - scaleFacts; first.UnknownHosts != want {
		t.Errorf("unknown_hosts = %d, expected %d", first.UnknownHosts, want)
	}
	if first.EvaluatedHosts+first.UnknownHosts != first.TotalHosts {
		t.Errorf("%d answered and %d unknown do not add up to %d hosts",
			first.EvaluatedHosts, first.UnknownHosts, first.TotalHosts)
	}
	if first.UnknownReasons["not_finished"] != scaleHosts-scaleFacts {
		t.Errorf("unknown_reasons = %v, expected %d under not_finished",
			first.UnknownReasons, scaleHosts-scaleFacts)
	}
	// The page carries a part of the read and has to say so, or the panel
	// would show a hundred hosts as the whole answer.
	if !first.Partial || first.PartialReason == "" {
		t.Errorf("a page of %d hosts out of %d does not say it is a part: %+v",
			len(first.Hosts), scaleHosts, first.fleetCoverageView)
	}
	if first.Count > 500 || first.Count != len(first.Hosts) {
		t.Errorf("the page carries %d hosts and counts %d", len(first.Hosts), first.Count)
	}
	if first.NextCursor == "" {
		t.Fatal("the read of a thousand hosts has no next page")
	}

	// The cursor walks the whole fan-out: every host once, and as many as
	// the head counted.
	seen := map[string]bool{}
	address := "/api/v1/reads/" + fanOutID + "?limit=250"
	for requests := 0; ; requests++ {
		if requests > 20 {
			t.Fatal("the fan-out never reached its last page")
		}
		var page fanOutPage
		scoped.get(address, &page)
		for _, host := range page.Hosts {
			if seen[host.HostID] {
				t.Fatalf("%s came twice", host.Hostname)
			}
			seen[host.HostID] = true
		}
		if page.NextCursor == "" {
			break
		}
		address = "/api/v1/reads/" + fanOutID + "?limit=250&cursor=" + page.NextCursor
	}
	if len(seen) != scaleHosts {
		t.Errorf("the cursor walked %d hosts, the read covers %d", len(seen), scaleHosts)
	}

	// A cursor this page did not issue is refused rather than read as the
	// key of nothing.
	scoped.do(http.MethodGet, "/api/v1/reads/"+fanOutID+"?cursor=not-a-cursor", nil, nil, http.StatusBadRequest)
}

// cveListCarriesTheCoverageOfTheFleet checks that the CVE list says over how
// much of the fleet it was counted, and that its pages join up.
func cveListCarriesTheCoverageOfTheFleet(t *testing.T, scoped *harness) {
	type cvePage struct {
		fleetCoverageView
		Items []struct {
			CVE   string `json:"cve"`
			Hosts int    `json:"hosts"`
		} `json:"items"`
	}
	var head cvePage
	scoped.get("/api/v1/vulnerabilities/cves", &head)
	if head.TotalHosts != scaleHosts {
		t.Errorf("total_hosts = %d, expected %d", head.TotalHosts, scaleHosts)
	}
	// A CVE list counted over three hundred assessed hosts says nothing
	// about the seven hundred nobody has assessed.
	if head.EvaluatedHosts != scaleFacts {
		t.Errorf("evaluated_hosts = %d, expected %d", head.EvaluatedHosts, scaleFacts)
	}
	if want := scaleHosts - scaleFacts; head.UnknownHosts != want {
		t.Errorf("unknown_hosts = %d, expected %d", head.UnknownHosts, want)
	}
	if head.EvaluatedHosts+head.UnknownHosts != head.TotalHosts {
		t.Errorf("%d assessed and %d unknown do not add up to %d hosts",
			head.EvaluatedHosts, head.UnknownHosts, head.TotalHosts)
	}
	if head.UnknownReasons["no_assessment"] != scaleHosts-scaleFacts {
		t.Errorf("unknown_reasons = %v, expected %d under no_assessment",
			head.UnknownReasons, scaleHosts-scaleFacts)
	}
	if head.Total != scaleCVEs {
		t.Errorf("the list counts %d CVEs, expected %d", head.Total, scaleCVEs)
	}

	seen := map[string]bool{}
	hosts := 0
	address := "/api/v1/vulnerabilities/cves?limit=25"
	for requests := 0; ; requests++ {
		if requests > 10 {
			t.Fatal("the CVE list never reached its last page")
		}
		var page cvePage
		scoped.get(address, &page)
		for _, item := range page.Items {
			if seen[item.CVE] {
				t.Fatalf("%s came twice", item.CVE)
			}
			seen[item.CVE] = true
			hosts += item.Hosts
		}
		if page.NextCursor == "" {
			break
		}
		address = "/api/v1/vulnerabilities/cves?limit=25&cursor=" + page.NextCursor
	}
	if len(seen) != scaleCVEs {
		t.Errorf("the cursor walked %d CVEs, the list counted %d", len(seen), scaleCVEs)
	}
	// Every assessed host carries one finding, so the CVEs between them
	// account for every one of those hosts.
	if hosts != scaleFacts {
		t.Errorf("the CVEs name %d affected hosts, expected %d", hosts, scaleFacts)
	}

	scoped.do(http.MethodGet, "/api/v1/vulnerabilities/cves?cursor=not-a-cursor", nil, nil, http.StatusBadRequest)
}
