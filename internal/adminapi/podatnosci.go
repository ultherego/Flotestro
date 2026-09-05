package adminapi

import (
	"net/http"
	"sort"
	"time"

	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/vuln"
)

// SetPodatnosci podlacza korelator podatnosci.
func (s *Server) SetPodatnosci(store *vuln.Store, pakiety *vuln.MagazynPakietow,
	maksymalnyWiekFeedu time.Duration) {
	s.podatnosci = store
	s.pakietyHostow = pakiety
	s.wiekFeedu = maksymalnyWiekFeedu
}

// raportPodatnosci jest odpowiedzia zakladki hosta.
//
// Liczba znalezisk bez pokrycia nic nie znaczy: host, ktorego feed nie
// obejmuje, i host bez podatnosci maja tak samo zero na liczniku. Dlatego
// pokrycie i powod jego braku stoja tu obok listy, a nie pod nia.
type raportPodatnosci struct {
	HostID   string            `json:"host_id"`
	State    vuln.StanHosta    `json:"state"`
	Findings []vuln.Assessment `json:"findings"`
	// PackageState opisuje liste pakietow, na ktorej oparto ocene.
	PackageState vuln.StanListy `json:"package_state"`
	// Snapshot opisuje dane, ktore rozstrzygnely.
	Snapshot *vuln.Snapshot `json:"snapshot,omitempty"`
	// SnapshotStale mowi, ze dane sa starsze, niz dopuszcza polityka.
	SnapshotStale bool `json:"snapshot_stale"`
	// CoveragePercent jest udzialem pakietow objetych feedem.
	CoveragePercent float64 `json:"coverage_percent"`
}

// handleHostVulnerabilities zwraca ustalenia i pokrycie oceny hosta.
func (s *Server) handleHostVulnerabilities(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	_, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	if _, ok := s.authorize(w, r, authz.PermVulnerabilityRead, scope, "host", hostID); !ok {
		return
	}
	if s.podatnosci == nil {
		problem(w, http.StatusNotImplemented, "vulnerability_correlator_disabled",
			"the vulnerability correlator is disabled in this installation")
		return
	}

	stany, err := s.podatnosci.StanyHostow(r.Context(), []string{hostID})
	if err != nil {
		s.fail(w, err)
		return
	}
	ustalenia, err := s.podatnosci.Ustalenia(r.Context(), hostID, false)
	if err != nil {
		s.fail(w, err)
		return
	}
	stanListy, err := s.pakietyHostow.Stan(r.Context(), hostID)
	if err != nil {
		s.fail(w, err)
		return
	}

	raport := raportPodatnosci{
		HostID: hostID, State: stany[hostID], PackageState: stanListy,
		Findings: ustalenia,
	}
	if raport.Findings == nil {
		raport.Findings = []vuln.Assessment{}
	}
	raport.CoveragePercent = raport.State.Pokrycie() * 100
	if raport.State.Provider != "" {
		if snapshot, err := s.podatnosci.AktywnySnapshot(r.Context(), raport.State.Provider); err == nil {
			raport.Snapshot = &snapshot
			raport.SnapshotStale = snapshot.Nieswiezy(s.wiekFeedu, time.Now().UTC())
		}
	}
	writeJSON(w, http.StatusOK, raport)
}

// hostPodatnosci opisuje jeden host na ekranie floty.
type hostPodatnosci struct {
	vuln.StanHosta
	CoveragePercent float64 `json:"coverage_percent"`
}

// handleFleetVulnerabilities zwraca ocene calej widocznej floty.
//
// Ekran ma dwie liczby, nie jedna: ile podatnosci i jaka czesc floty w ogole
// dalo sie ocenic. Bez tej drugiej pierwsza jest obietnica, a nie wynikiem.
func (s *Server) handleFleetVulnerabilities(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermVulnerabilityRead, "fleet")
	if !ok {
		return
	}
	if s.podatnosci == nil {
		problem(w, http.StatusNotImplemented, "vulnerability_correlator_disabled",
			"the vulnerability correlator is disabled in this installation")
		return
	}

	lista, err := s.hosts.List(r.Context(), hosts.ListFilter{Limit: 500})
	if err != nil {
		s.fail(w, err)
		return
	}
	nazwy := map[string]string{}
	identyfikatory := make([]string, 0, len(lista))
	for _, host := range lista {
		if principal.Can(authz.PermVulnerabilityRead,
			authz.Scope{Site: host.Site, Environment: host.Environment}) {
			nazwy[host.ID] = host.Hostname
			identyfikatory = append(identyfikatory, host.ID)
		}
	}

	stany, err := s.podatnosci.StanyHostow(r.Context(), identyfikatory)
	if err != nil {
		s.fail(w, err)
		return
	}
	snapshoty, err := s.podatnosci.Snapshoty(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}

	teraz := time.Now().UTC()
	pozycje := make([]hostPodatnosci, 0, len(identyfikatory))
	var podatnych, doZalatania, bezPoprawki, nieustalonych, ocenionych, bezOceny int
	powody := map[string]int{}
	for _, hostID := range identyfikatory {
		stan, oceniony := stany[hostID]
		stan.HostID = hostID
		stan.Hostname = nazwy[hostID]
		if !oceniony || stan.EvaluatedAt == nil {
			// Host jeszcze nieoceniony nie jest hostem bez podatnosci.
			bezOceny++
			stan.CoverageReason = vuln.RodzajBrakListy
		} else if stan.CoverageReason == "" {
			ocenionych++
		}
		if stan.CoverageReason != "" {
			powody[stan.CoverageReason]++
		}
		podatnych += stan.Affected
		doZalatania += stan.AffectedFixable
		bezPoprawki += stan.AffectedNoFix
		nieustalonych += stan.Unknown
		pozycje = append(pozycje, hostPodatnosci{
			StanHosta: stan, CoveragePercent: stan.Pokrycie() * 100,
		})
	}

	// Najgorsze na gorze: hosty z podatnosciami, potem te, ktorych nie dalo
	// sie ocenic, na koncu czyste.
	sort.SliceStable(pozycje, func(i, j int) bool {
		if pozycje[i].Affected != pozycje[j].Affected {
			return pozycje[i].Affected > pozycje[j].Affected
		}
		if (pozycje[i].CoverageReason == "") != (pozycje[j].CoverageReason == "") {
			return pozycje[i].CoverageReason != ""
		}
		return pozycje[i].Hostname < pozycje[j].Hostname
	})

	stanZrodel := make([]map[string]any, 0, len(snapshoty))
	for _, snapshot := range snapshoty {
		stanZrodel = append(stanZrodel, map[string]any{
			"provider": snapshot.Provider, "digest": snapshot.Digest,
			"advisories": snapshot.AdvisoryCount, "releases": snapshot.Releases,
			"fetched_at": snapshot.FetchedAt, "stale": snapshot.Nieswiezy(s.wiekFeedu, teraz),
			"error": snapshot.Error,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"items": pozycje, "affected": podatnych, "affected_fixable": doZalatania,
		"affected_no_fix": bezPoprawki, "unknown": nieustalonych,
		"hosts_total": len(identyfikatory), "hosts_assessed": ocenionych,
		"hosts_without_assessment": bezOceny,
		"coverage_reasons":         powody,
		"sources":                  stanZrodel,
		"max_snapshot_age_hours":   int(s.wiekFeedu.Hours()),
	})
}
