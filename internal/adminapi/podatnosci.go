package adminapi

import (
	"context"
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
	// PackageState opisuje liste pakietow, na ktorej oparto ocene,
	// a AdvisoryState - zestaw ustalen producenta znany hostowi. To dwa
	// osobne zrodla i dwa osobne cykle odswiezania.
	PackageState  vuln.StanListy   `json:"package_state"`
	AdvisoryState vuln.StanUstalen `json:"advisory_state"`
	// Snapshot opisuje dane, ktore rozstrzygnely.
	Snapshot *vuln.Snapshot `json:"snapshot,omitempty"`
	// SnapshotStale mowi, ze dane sa starsze, niz dopuszcza polityka.
	SnapshotStale bool `json:"snapshot_stale"`
	// CoveragePercent jest udzialem pakietow objetych feedem.
	CoveragePercent float64 `json:"coverage_percent"`
	// FullyAssessed mowi, czy ocena jest kompletna: bez przeszkody
	// w pokryciu, z feedem obejmujacym wszystkie pakiety i bez ani jednego
	// pakietu nieustalonego. Pusty powod sam w sobie tego nie znaczy.
	FullyAssessed bool `json:"fully_assessed"`
	// CVEDetails sa wzbogaceniem: ocena CVSS i opis podatnosci z bazy
	// upstreamowej. Stoja obok znalezisk, a nie w nich, bo niczego w nich
	// nie zmieniaja - o tym, czy pakiet jest podatny, mowi wylacznie
	// producent dystrybucji. Brak wpisu jest normalny.
	CVEDetails map[string]vuln.SzczegolyCVE `json:"cve_details,omitempty"`
}

// szczegolyCVE dobiera wzbogacenie do znalezisk.
//
// Bezglosnie: brak opisow nie moze przeszkodzic w pokazaniu oceny, bo ocena
// z nich nie korzysta. Gdy zrodla wzbogacajacego nie ma albo odczyt sie nie
// uda, zakladka pokazuje to samo co zawsze, tylko bez wagi upstreamowej.
func (s *Server) szczegolyCVE(ctx context.Context, ustalenia []vuln.Assessment) map[string]vuln.SzczegolyCVE {
	widziane := map[string]bool{}
	numery := make([]string, 0, len(ustalenia))
	for _, ustalenie := range ustalenia {
		for _, numer := range ustalenie.CVEIDs {
			if numer == "" || widziane[numer] {
				continue
			}
			widziane[numer] = true
			numery = append(numery, numer)
		}
	}
	if len(numery) == 0 {
		return nil
	}
	szczegoly, err := s.podatnosci.Szczegoly(ctx, numery)
	if err != nil {
		s.log.Error("nie odczytano opisow podatnosci", "err", err)
		return nil
	}
	return szczegoly
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

	stanUstalen, err := s.pakietyHostow.StanUstalenHosta(r.Context(), hostID)
	if err != nil {
		s.fail(w, err)
		return
	}

	raport := raportPodatnosci{
		HostID: hostID, State: stany[hostID], PackageState: stanListy,
		AdvisoryState: stanUstalen, Findings: ustalenia,
	}
	if raport.Findings == nil {
		raport.Findings = []vuln.Assessment{}
	}
	raport.CoveragePercent = raport.State.Pokrycie() * 100
	raport.FullyAssessed = raport.State.PelnaOcena()
	raport.CVEDetails = s.szczegolyCVE(r.Context(), raport.Findings)
	if raport.State.Provider != "" {
		if snapshot, err := s.podatnosci.AktywnySnapshot(r.Context(), raport.State.Provider); err == nil {
			raport.Snapshot = &snapshot
			raport.SnapshotStale = snapshot.Nieswiezy(s.wiekFeedu, time.Now().UTC())
		} else if raport.State.SnapshotDigest != "" {
			// Rodzina RPM czyta ustalenia z metadanych wlasnych repozytoriow,
			// wiec nie ma centralnego snapshotu. Panel i tak musi powiedziec,
			// co rozstrzygnelo ocene - inaczej wynik jest bez zrodla.
			ustalenia, zebrane, err := s.pakietyHostow.UstaleniaHosta(r.Context(), hostID)
			if err == nil {
				ile := 0
				for _, dla := range ustalenia {
					ile += len(dla)
				}
				snapshot := vuln.Snapshot{
					Provider: raport.State.Provider + " (metadane repozytoriow hosta)",
					Digest:   raport.State.SnapshotDigest, AdvisoryCount: ile,
					Releases: []string{raport.State.Release}, FetchedAt: zebrane, Active: true,
				}
				raport.Snapshot = &snapshot
				raport.SnapshotStale = snapshot.Nieswiezy(s.wiekFeedu, time.Now().UTC())
			}
		}
	}
	writeJSON(w, http.StatusOK, raport)
}

// hostPodatnosci opisuje jeden host na ekranie floty.
type hostPodatnosci struct {
	vuln.StanHosta
	CoveragePercent float64 `json:"coverage_percent"`
	// FullyAssessed mowi, czy ocena tego hosta jest kompletna. Bez tego pola
	// ekran musialby zgadywac z samego pustego powodu - a host z jednym
	// pakietem spoza dystrybucji ma pusty powod i niepelna ocene.
	FullyAssessed bool `json:"fully_assessed"`
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
	var pakietow, hostowPodatnych int
	powody := map[string]int{}
	// Unikaty licza sie na poziomie floty, a nie sumowaniem po hostach: to samo
	// CVE na dwudziestu hostach jest jedna sprawa producenta i dwudziestoma
	// hostami do ruszenia. Sumowanie licznikow hostow zamienia jedno w drugie.
	sprawy, err := s.podatnosci.Unikaty(r.Context(), identyfikatory)
	if err != nil {
		s.fail(w, err)
		return
	}
	for _, hostID := range identyfikatory {
		stan, oceniony := stany[hostID]
		stan.HostID = hostID
		stan.Hostname = nazwy[hostID]
		if !oceniony || stan.EvaluatedAt == nil {
			// Host jeszcze nieoceniony nie jest hostem bez podatnosci.
			bezOceny++
			stan.CoverageReason = vuln.RodzajBrakListy
		} else if stan.PelnaOcena() {
			// Kompletna ocena to nie tylko brak przeszkody: feed musi objac
			// wszystkie pakiety hosta i zaden nie moze zostac nieustalony.
			ocenionych++
		}
		if stan.CoverageReason != "" {
			powody[stan.CoverageReason]++
		}
		podatnych += stan.Affected
		doZalatania += stan.AffectedWithVendorFix
		bezPoprawki += stan.AffectedNoFix
		nieustalonych += stan.Unknown
		pakietow += stan.AffectedPackages
		if stan.Affected > 0 {
			hostowPodatnych++
		}
		pozycje = append(pozycje, hostPodatnosci{
			StanHosta: stan, CoveragePercent: stan.Pokrycie() * 100,
			FullyAssessed: stan.PelnaOcena(),
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
		"items": pozycje, "affected": podatnych,
		"affected_with_vendor_fix": doZalatania,
		"affected_no_fix":          bezPoprawki, "unknown": nieustalonych,
		// Cztery liczby, bo to cztery rozne pytania: ile CVE, ile spraw
		// producenta, ile instancji pakietow do ruszenia i ilu hostow to
		// dotyczy. Jedna liczba "znalezisk" nie odpowiada na zadne z nich.
		"unique_cves": sprawy.CVE, "unique_advisories": sprawy.Advisories,
		"affected_package_instances": pakietow, "hosts_affected": hostowPodatnych,
		"hosts_total": len(identyfikatory), "hosts_assessed": ocenionych,
		"hosts_without_assessment": bezOceny,
		"coverage_reasons":         powody,
		"sources":                  stanZrodel,
		"max_snapshot_age_hours":   int(s.wiekFeedu.Hours()),
	})
}
