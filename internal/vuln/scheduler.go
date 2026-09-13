package vuln

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/inventory"
	"github.com/ultherego/flotestro/internal/jobs"
	"github.com/ultherego/flotestro/internal/opspec"
)

// Source is the adapter of the security tracker of one distribution.
//
// The vendor settles the matter: the adapter translates its language into
// the findings of the panel and nothing more. Enrichment with a CVSS score or
// an upstream description may come later and has no right to change the
// answer "vulnerable / not vulnerable".
type Source interface {
	Name() string
	// Fetch pulls the findings for the named releases. It returns
	// ErrNotModified when the feed has not changed since the fetch described
	// by the etag.
	Fetch(ctx context.Context, releases []string, etag string) (Snapshot, []Advisory, error)
}

// ErrNotModified means a feed unchanged since the last fetch.
var ErrNotModified = errors.New("the feed has not changed since the last fetch")

// Settings describe the policy of the correlator.
type Settings struct {
	// Interval says how often the panel asks the trackers about changes.
	Interval time.Duration
	// MaxSnapshotAge is the age above which we consider the data stale. It
	// does not stop the assessment - data from a day ago are better than
	// none - but it has to be visible next to the result.
	MaxSnapshotAge time.Duration
	// Debounce says how long we gather requests to recompute a host before
	// carrying them out. A host reports its package list and its findings
	// separately, and several hosts can answer at once - one recomputation
	// for the whole group costs as much as one for the first of them.
	Debounce time.Duration
	// MaxAdvisoryAge is the age after which the panel asks a host to read
	// the metadata of its repositories again.
	//
	// Separate from the age of a snapshot, because it is a separate source
	// and a separate cycle: the vendor releases fixes also when not a single
	// package on the host has changed. A panel that tied the refresh of the
	// findings to a change of the package list would sometimes refresh them
	// never.
	MaxAdvisoryAge time.Duration
}

// DefaultSettings returns the default settings.
func DefaultSettings() Settings {
	return Settings{
		Interval: 30 * time.Minute, MaxSnapshotAge: 6 * time.Hour,
		MaxAdvisoryAge: 30 * time.Minute, Debounce: 15 * time.Second,
	}
}

// Scheduler synchronises the feeds and recomputes the assessment of the
// fleet.
type Scheduler struct {
	store     *Store
	packages  *PackageStore
	hosts     *hosts.Store
	inventory *inventory.Store
	jobs      *jobs.Store
	sources   []Source
	settings  Settings
	log       *slog.Logger
	// refreshes carries the hosts that have just sent new data. The
	// assessment is to keep up with what settles it: a host that answered a
	// request for a read must not show up as a host without one for half an
	// hour.
	refreshes chan string
}

// NewScheduler creates the schedule of the correlator.
func NewScheduler(store *Store, packageStore *PackageStore, hostStore *hosts.Store,
	inventoryStore *inventory.Store, jobStore *jobs.Store, sources []Source,
	settings Settings, log *slog.Logger) *Scheduler {
	if settings.Interval <= 0 {
		settings.Interval = DefaultSettings().Interval
	}
	if settings.MaxSnapshotAge <= 0 {
		settings.MaxSnapshotAge = DefaultSettings().MaxSnapshotAge
	}
	if settings.MaxAdvisoryAge <= 0 {
		settings.MaxAdvisoryAge = DefaultSettings().MaxAdvisoryAge
	}
	if settings.Debounce <= 0 {
		settings.Debounce = DefaultSettings().Debounce
	}
	return &Scheduler{
		store: store, packages: packageStore, hosts: hostStore, inventory: inventoryStore,
		jobs: jobStore, sources: sources, settings: settings, log: log,
		refreshes: make(chan string, 1024),
	}
}

// Refresh asks for the assessment of a host to be recomputed out of turn.
//
// Called by the gateway when a host sends its package list or the findings of
// its repositories. The request is only a request: when the queue is full the
// host waits for the ordinary cycle - that is worse by a dozen minutes, not
// by an answer.
func (h *Scheduler) Refresh(hostID string) {
	if hostID == "" {
		return
	}
	select {
	case h.refreshes <- hostID:
	default:
		h.log.Debug("the queue of assessment refreshes is full", "host_id", hostID)
	}
}

// Run carries the synchronisation and the assessment on until the context is
// closed.
func (h *Scheduler) Run(ctx context.Context) {
	// The first pass at once: after a start the panel must not show an
	// assessment from before the restart for half an hour without marking it
	// as old.
	h.Cycle(ctx)
	ticker := time.NewTicker(h.settings.Interval)
	defer ticker.Stop()

	// Requests to recompute are gathered for a moment and carried out
	// together. A host answers about its package list and about its findings
	// separately, and reading the feed findings for one release is up to a
	// million rows - there is no reason to do that twice in a row.
	pending := map[string]bool{}
	var delay *time.Timer
	var signal <-chan time.Time
	defer func() {
		if delay != nil {
			delay.Stop()
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.Cycle(ctx)
		case hostID := <-h.refreshes:
			pending[hostID] = true
			if delay == nil {
				delay = time.NewTimer(h.settings.Debounce)
				signal = delay.C
			}
		case <-signal:
			ids := make([]string, 0, len(pending))
			for hostID := range pending {
				ids = append(ids, hostID)
			}
			pending = map[string]bool{}
			delay, signal = nil, nil
			h.RecalculateHosts(ctx, ids)
		}
	}
}

// RecalculateHosts recomputes the assessment of the named hosts.
func (h *Scheduler) RecalculateHosts(ctx context.Context, ids []string) {
	if len(ids) == 0 {
		return
	}
	descriptions, err := h.describedHosts(ctx, ids)
	if err != nil {
		h.log.Error("the hosts to recompute the assessment for were not read", "err", err)
		return
	}
	h.Recalculate(ctx, descriptions)
}

// describedHosts gathers what the assessment needs about the named hosts.
func (h *Scheduler) describedHosts(ctx context.Context,
	ids []string) ([]HostDescription, error) {
	fragments, err := h.inventory.HostFragments(ctx, ids)
	if err != nil {
		return nil, err
	}
	descriptions := make([]HostDescription, 0, len(ids))
	for _, hostID := range ids {
		host, err := h.hosts.Get(ctx, hostID)
		if err != nil || host == nil {
			// A host deleted between the request and the recomputation is
			// not an error of the sweep: it is simply not there.
			continue
		}
		summary := hosts.Summary{
			ID: host.ID, Hostname: host.Hostname,
			OSDistribution: host.OSDistribution, OSVersion: host.OSVersion,
		}
		description := HostDescription{ID: host.ID, Hostname: host.Hostname}
		description.Distribution, description.Release = hostDistribution(summary, fragments[host.ID])
		description.InventoryDigest, description.InventoryReason = digestFromInventory(fragments[host.ID])
		descriptions = append(descriptions, description)
	}
	return descriptions, nil
}

// Cycle makes one pass: the synchronisation of the feeds and the assessment
// of the hosts.
func (h *Scheduler) Cycle(ctx context.Context) {
	descriptions, err := h.hostDescriptions(ctx)
	if err != nil {
		h.log.Error("the fleet to assess for vulnerabilities was not read", "err", err)
		return
	}
	h.Synchronize(ctx, descriptions)
	h.Recalculate(ctx, descriptions)
}

// HostDescription is what the panel knows about a host before the
// assessment.
type HostDescription struct {
	ID           string
	Hostname     string
	Distribution string
	// Release is the name of the release in the language of the vendor: the
	// codename for Debian and Ubuntu, the number for Fedora.
	Release string
	// InventoryDigest is the digest of the package list reported by the
	// host.
	InventoryDigest string
	InventoryReason string
}

// AdvisoriesFromHost says whether the findings for this distribution are read
// from the repository metadata of the host rather than from a central feed.
//
// For now Fedora alone. Its updateinfo carries full security findings along
// with the packages, so the host reads them from the same source it takes
// the fixes from.
//
// RHEL, AlmaLinux and Rocky have a poorer or incomplete updateinfo, and their
// settling source is the CSAF/VEX of the vendor - and until the panel reads
// those, a host of these distributions is left with the reason "feed
// missing". That is a more honest answer than an assessment from metadata
// that do not describe everything.
func AdvisoriesFromHost(distribution string) bool {
	return strings.ToLower(distribution) == "fedora"
}

// ProviderFor returns the name of the tracker proper for the distribution of
// a host.
//
// CentOS Stream, AlmaLinux and Rocky do not get the Red Hat tracker even
// though their packages carry the same names: their versions are their own
// (a rebuild appends a suffix of its own, Stream runs ahead of RHEL), so a
// Red Hat finding would speak about something else. Until the panel reads
// their own sources, their hosts are to get the reason "feed missing" - that
// is a more honest answer than somebody else's assessment.
func ProviderFor(distribution string) string {
	switch strings.ToLower(distribution) {
	case "debian":
		return "debian"
	case "ubuntu":
		return "ubuntu"
	case "fedora":
		return "fedora"
	case "rhel":
		return "redhat"
	}
	return ""
}

// hostDescriptions gathers what the assessment needs about every host.
//
// The whole fleet, page by page. The list for the UI has a limit and with too
// large a value it silently falls back to a hundred entries - a sweep that
// relied on it assessed a hundred hosts and said nothing about the rest. An
// unassessed host looks on the screen exactly like a host without
// vulnerabilities, so silence is the worst answer here.
func (h *Scheduler) hostDescriptions(ctx context.Context) ([]HostDescription, error) {
	var (
		descriptions []HostDescription
		afterName    string
		afterID      string
	)
	for {
		page, err := h.hosts.Sweep(ctx, afterName, afterID, hosts.PageSize)
		if err != nil {
			return nil, err
		}
		if len(page) == 0 {
			return descriptions, nil
		}

		ids := make([]string, 0, len(page))
		for _, host := range page {
			ids = append(ids, host.ID)
		}
		// The inventory fragments are taken for the page rather than for the
		// whole fleet: they carry the full payloads of the modules and as a
		// whole they do not fit in memory.
		fragments, err := h.inventory.HostFragments(ctx, ids)
		if err != nil {
			return nil, err
		}
		for _, host := range page {
			description := HostDescription{ID: host.ID, Hostname: host.Hostname}
			description.Distribution, description.Release = hostDistribution(host, fragments[host.ID])
			description.InventoryDigest, description.InventoryReason = digestFromInventory(fragments[host.ID])
			descriptions = append(descriptions, description)
		}

		last := page[len(page)-1]
		afterName, afterID = last.Hostname, last.ID
		if len(page) < hosts.PageSize {
			return descriptions, nil
		}
	}
}

// hostDistribution establishes the distribution and the release in the
// language of the vendor.
func hostDistribution(host hosts.Summary, fragments []inventory.Fragment) (string, string) {
	distribution := strings.ToLower(host.OSDistribution)
	release := host.OSVersion

	// The Debian and Ubuntu trackers speak in the names of releases rather
	// than in numbers. The name is in the inventory, because only the host
	// knows what its release is called.
	for _, fragment := range fragments {
		if fragment.Module != "system" || len(fragment.Payload) == 0 {
			continue
		}
		var content struct {
			OS struct {
				Distribution string `json:"distribution"`
				Version      string `json:"version"`
				Codename     string `json:"codename"`
			} `json:"os"`
		}
		if err := json.Unmarshal(fragment.Payload, &content); err != nil {
			continue
		}
		if content.OS.Distribution != "" {
			distribution = strings.ToLower(content.OS.Distribution)
		}
		if content.OS.Codename != "" && (distribution == "debian" || distribution == "ubuntu") {
			release = content.OS.Codename
		} else if content.OS.Version != "" {
			release = content.OS.Version
		}
	}
	return distribution, TrackerRelease(distribution, release)
}

// TrackerRelease reduces the release of a host to the form the tracker knows.
//
// Red Hat speaks about the major release: a host reports 9.4 and the findings
// concern the nine. Without this every RHEL host would come out as "a release
// outside the feed". Debian, Ubuntu and Fedora name their releases the same
// way their hosts do.
func TrackerRelease(distribution, release string) string {
	if ProviderFor(distribution) != "redhat" {
		return release
	}
	if major, _, ok := strings.Cut(release, "."); ok {
		return major
	}
	return release
}

// digestFromInventory reads the digest of the package list reported by the
// host.
func digestFromInventory(fragments []inventory.Fragment) (string, string) {
	for _, fragment := range fragments {
		if fragment.Module != "packages" || len(fragment.Payload) == 0 {
			continue
		}
		var content struct {
			InstalledDigest string `json:"installed_digest"`
			InstalledReason string `json:"installed_unavailable_reason"`
		}
		if err := json.Unmarshal(fragment.Payload, &content); err != nil {
			continue
		}
		return content.InstalledDigest, content.InstalledReason
	}
	return "", ""
}

// Synchronize fetches the feeds for the releases the fleet really has.
//
// We fetch only what concerns the hosts in this installation: a full dump
// describes more than a dozen releases and several hundred thousand findings,
// and the panel needs the ones it has something to answer about.
func (h *Scheduler) Synchronize(ctx context.Context, descriptions []HostDescription) {
	releases := map[string]map[string]bool{}
	for _, description := range descriptions {
		provider := ProviderFor(description.Distribution)
		if provider == "" || description.Release == "" {
			continue
		}
		if releases[provider] == nil {
			releases[provider] = map[string]bool{}
		}
		releases[provider][description.Release] = true
	}

	for _, source := range h.sources {
		set := releases[source.Name()]
		if len(set) == 0 {
			// We do not fetch the feed of a distribution this installation
			// does not have.
			continue
		}
		list := make([]string, 0, len(set))
		for release := range set {
			list = append(list, release)
		}

		etag := ""
		if previous, err := h.store.ActiveSnapshot(ctx, source.Name()); err == nil {
			// An etag makes sense only when we ask about the same range of
			// releases: otherwise "no changes" would mean "no changes in a
			// different range".
			if sameRange(previous.Releases, list) {
				etag = previous.ETag
			}
		}

		snapshot, advisories, err := source.Fetch(ctx, list, etag)
		if errors.Is(err, ErrNotModified) || (err != nil && strings.Contains(err.Error(), "has not changed")) {
			// "No changes" is a confirmation rather than a missing answer:
			// the data are still the ones in force. Without this record a
			// feed that changes once a day would look abandoned.
			if err := h.store.ConfirmSnapshot(ctx, source.Name()); err != nil {
				h.log.Error("the confirmation of the feed was not recorded",
					"provider", source.Name(), "err", err)
			}
			h.log.Debug("the feed has not changed", "provider", source.Name())
			continue
		}
		if err != nil {
			// A failed fetch does not take the previous snapshot away from
			// the panel: better to assess with older data and say they are
			// older.
			h.log.Error("the feed was not fetched", "provider", source.Name(), "err", err)
			_ = h.store.SaveFetchError(ctx, source.Name(), err.Error())
			continue
		}
		if _, err := h.store.SaveSnapshot(ctx, snapshot, advisories); err != nil {
			h.log.Error("the feed snapshot was not saved", "provider", source.Name(), "err", err)
			continue
		}
		h.log.Info("the feed snapshot was saved", "provider", source.Name(),
			"findings", len(advisories), "releases", list, "digest", snapshot.Digest[:12])
	}
}

func sameRange(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	set := map[string]bool{}
	for _, entry := range a {
		set[entry] = true
	}
	for _, entry := range b {
		if !set[entry] {
			return false
		}
	}
	return true
}

// Recalculate assesses the hosts with the active snapshot of their
// distribution.
//
// It recomputes only the ones whose input has changed. The assessment depends
// on three digests - of the feed snapshot, of the package list and of the set
// of findings of the host - and on what stands in the way of full coverage.
// When none of them has moved, the result would be the same to the byte, and
// the cost is reading several hundred packages and rewriting several thousand
// rows per host.
//
// A safety net stays in place: an assessment older than the age allowed for a
// feed is computed again regardless of the digests. An error in the reckoning
// of "what has changed" is to cost a delay rather than an assessment frozen
// for good.
func (h *Scheduler) Recalculate(ctx context.Context, descriptions []HostDescription) {
	snapshots := map[string]Snapshot{}
	feedAdvisories := map[string]map[string][]Advisory{}
	now := time.Now().UTC()
	previous := h.previousStates(ctx, descriptions)
	skipped := 0

	for _, description := range descriptions {
		provider := ProviderFor(description.Distribution)
		snapshot, ok := snapshots[provider]
		if !ok && provider != "" {
			if fetched, err := h.store.ActiveSnapshot(ctx, provider); err == nil {
				snapshot = fetched
			}
			snapshots[provider] = snapshot
		}

		listState, err := h.packages.State(ctx, description.ID)
		if err != nil {
			h.log.Error("the state of the package list was not read", "host_id", description.ID, "err", err)
			continue
		}

		input := Input{
			HostID: description.ID, Hostname: description.Hostname,
			Distribution: description.Distribution, Release: description.Release,
			InventoryDigest: listState.Digest,
			ListMissing:     listState.Digest == "" || listState.PackageCount == 0,
			// The host reports a digest other than the one the panel holds:
			// the assessment then describes the state from before the change.
			ListStale: description.InventoryDigest != "" && listState.Digest != "" &&
				description.InventoryDigest != listState.Digest,
		}

		// For Fedora the settling source is the repository metadata of the
		// host itself: they say which version closes a finding and whether it
		// lies in a repository this host takes packages from.
		set := map[string][]Advisory(nil)
		refreshAdvisories := false
		if AdvisoriesFromHost(description.Distribution) {
			advisoryState, err := h.packages.HostAdvisoryState(ctx, description.ID)
			if err != nil {
				h.log.Error("the state of the findings of the host was not read",
					"host_id", description.ID, "err", err)
				continue
			}
			fromHost, collected, err := h.packages.HostAdvisories(ctx, description.ID)
			if err != nil {
				h.log.Error("the findings of the host were not read",
					"host_id", description.ID, "err", err)
			}
			set = fromHost
			input.AdvisoryDigest = advisoryState.Digest
			input.AdvisoriesReason = advisoryState.UnavailableReason
			switch {
			case input.AdvisoriesReason != "":
				// There already is a reason - the read failed or there was
				// none.
				refreshAdvisories = true
			case advisoryState.CollectedAt == nil:
				input.AdvisoriesReason = ReasonHostAdvisoriesMissing
				refreshAdvisories = true
			case now.Sub(*advisoryState.CollectedAt) > h.settings.MaxAdvisoryAge:
				// The vendor releases fixes also when not a single package on
				// the host has changed. The findings therefore have a refresh
				// cycle of their own, independent of the digest of the
				// package list.
				input.AdvisoriesReason = ReasonHostAdvisoriesStale
				refreshAdvisories = true
			}

			// The snapshot here belongs to the host: its digest is the digest
			// of the set of findings, and its age - the moment the metadata
			// were read.
			snapshot = Snapshot{
				Provider: provider, Digest: advisoryState.Digest,
				Releases: []string{description.Release}, AdvisoryCount: len(fromHost),
				FetchedAt: collected, Active: true,
			}
		} else {
			key := provider + "\x1f" + description.Release
			if _, ok := feedAdvisories[key]; !ok && snapshot.ID != "" &&
				CoversRelease(snapshot, description.Release) {
				fetched, err := h.store.AdvisoriesForRelease(ctx, snapshot.ID,
					description.Distribution, description.Release)
				if err != nil {
					h.log.Error("the findings of the feed were not read",
						"provider", provider, "err", err)
				}
				feedAdvisories[key] = fetched
			}
			set = feedAdvisories[key]
		}

		// Ordering a read is independent of the recomputation: a host without
		// a list is to get one just as well when its assessment has not
		// changed since the last cycle. Otherwise a host skipped once would
		// never ask for it again.
		if input.ListMissing || input.ListStale || refreshAdvisories {
			h.requestRead(ctx, description, now)
		}

		if !h.toRecalculate(previous[description.ID], input, snapshot, now) {
			skipped++
			continue
		}
		pkgs, err := h.packages.Packages(ctx, description.ID)
		if err != nil {
			h.log.Error("the package list was not read", "host_id", description.ID, "err", err)
			continue
		}
		input.Packages = pkgs

		evaluation := Evaluate(input, snapshot, set, h.settings.MaxSnapshotAge, now)
		if err := h.store.SaveAdvisories(ctx, description.ID,
			evaluation.Findings, evaluation.State); err != nil {
			h.log.Error("the vulnerability assessment was not saved",
				"host_id", description.ID, "err", err)
			continue
		}
	}
	if skipped > 0 {
		// The skips are said out loud: a silent sweep that computed nothing
		// looks exactly like a sweep that found nothing.
		h.log.Info("the vulnerability assessment was recomputed", "hosts", len(descriptions),
			"skipped_unchanged", skipped)
	}
}

// previousStates reads the recorded assessments of the hosts, page by page.
func (h *Scheduler) previousStates(ctx context.Context, descriptions []HostDescription) map[string]HostState {
	result := map[string]HostState{}
	for start := 0; start < len(descriptions); start += hosts.PageSize {
		end := min(start+hosts.PageSize, len(descriptions))
		ids := make([]string, 0, end-start)
		for _, description := range descriptions[start:end] {
			ids = append(ids, description.ID)
		}
		states, err := h.store.HostStates(ctx, ids)
		if err != nil {
			// Without the previous states we recompute everything. It costs
			// more, but it does not leave an assessment frozen on an unknown
			// input.
			h.log.Error("the previous assessments were not read", "err", err)
			return map[string]HostState{}
		}
		for id, state := range states {
			result[id] = state
		}
	}
	return result
}

// toRecalculate says whether the assessment of a host has to be computed
// again.
//
// The input of an assessment is three digests and the reason for incomplete
// coverage. When none of them has changed, a new assessment would be a copy
// of the previous one - and computing it costs reading the whole package list
// and rewriting every finding.
func (h *Scheduler) toRecalculate(previous HostState, input Input,
	snapshot Snapshot, now time.Time) bool {
	if previous.EvaluatedAt == nil {
		return true
	}
	// The safety net: an assessment nobody has touched for longer than the
	// age allowed for a feed is computed again regardless of the digests.
	if now.Sub(*previous.EvaluatedAt) > h.settings.MaxSnapshotAge {
		return true
	}
	if previous.Distribution != input.Distribution ||
		previous.Release != input.Release ||
		previous.Provider != snapshot.Provider ||
		previous.SnapshotDigest != snapshot.Digest ||
		previous.InventoryDigest != input.InventoryDigest ||
		previous.AdvisoryDigest != input.AdvisoryDigest {
		return true
	}
	// The coverage reason depends on time as well: a feed fresh in the
	// morning is sometimes stale in the evening, and that changes the result
	// without a change of a single digest.
	reason, _ := CoverageReasonFor(input, snapshot, h.settings.MaxSnapshotAge, now)
	return reason != previous.CoverageReason
}

// requestRead orders the full package list from a host together with the
// vendor findings from the metadata of its repositories.
//
// We order it ourselves, because without it the assessment of this host is
// empty - and an empty assessment looks like a host without vulnerabilities.
func (h *Scheduler) requestRead(ctx context.Context, description HostDescription, now time.Time) {
	if h.jobs == nil || description.InventoryReason != "" {
		return
	}
	tx, err := h.jobs.Pool().Begin(ctx)
	if err != nil {
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// The key carries a time bucket rather than the digest of the list alone.
	// A key based on the digest stayed the same until the host changed - and
	// a job that failed once never came back: the following cycles hit the
	// same key and got the same failed order. A bucket closes that window
	// after one interval, and within it still guards against a repetition.
	bucket := now.Truncate(h.settings.Interval).UTC().Format(time.RFC3339)
	key := "vuln:packages:" + description.ID + ":" + bucket
	_, err = h.jobs.Create(ctx, tx, jobs.Spec{
		HostID:           description.ID,
		Action:           opspec.ActionPackageList,
		IdempotencyKey:   key,
		RequiresApproval: false,
		CreatedBy:        "flotestro/vuln",
		Preconditions: jobs.Preconditions{
			RequiredCapabilities: []string{opspec.ActionPackageList.RequiredCapability()},
		},
	})
	if err != nil {
		return
	}
	if err := tx.Commit(ctx); err != nil {
		return
	}
	h.log.Info("a package read was ordered", "host_id", description.ID,
		"host_digest", description.InventoryDigest, "bucket", bucket)
}
