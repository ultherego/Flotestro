package adminapi

import (
	"context"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/buildinfo"
	"github.com/ultherego/flotestro/internal/cryptostate"
	"github.com/ultherego/flotestro/internal/housekeeping"
	"github.com/ultherego/flotestro/internal/relays"
	"github.com/ultherego/flotestro/internal/secrets"
)

// The status screen: is this panel well, and if not, which part of it is
// not. The metrics endpoint carries the same facts for a scraper; the
// screen is for the person who has no scraper and asks "is it the
// database, the publisher or the feed" while the fleet waits.
//
// Every block says whether it is fine, and when it is not, why. A block
// the panel cannot judge - a connector not configured, a sweep that has
// not run yet - is unknown, never fine: a green light that means "nobody
// looked" is the one that costs an outage.

// processStarted is when this process came up; the uptime counts from it.
var processStarted = time.Now()

// Process gathers what the process resolved at start that the effective
// configuration does not carry: the loops with a state of their own and
// the switches read by the gateway and the scheduler rather than by the
// API server. The settings screen shows the switches; the status screen
// reads the loops.
type Process struct {
	// Crypto is the cryptographic state of the installation as the
	// startup guard left it; nil means a panel started without the guard,
	// which the status screen reports as unknown.
	Crypto *cryptostate.Runtime
	// Housekeeping is the retention sweeper; nil means a panel started
	// without one, which the status screen reports as unknown.
	Housekeeping *housekeeping.Sweeper
	// DispatchRate is the pace of the scheduler in envelopes per second;
	// zero means no pacing.
	DispatchRate int
	// ClonePolicy is the gateway's reaction to a copied identity.
	ClonePolicy string
	// RelayIdentity is what the gateway does with a relayed session that
	// names the host without the certificate it presented.
	RelayIdentity string
	// SessionGroupRefresh is how often the group snapshot of a live panel
	// session is confirmed with the identity provider; zero means never.
	SessionGroupRefresh time.Duration
	// OIDCAdminLogout says whether a disabled user is also logged out at
	// the identity provider.
	OIDCAdminLogout bool
}

// SetProcess hands the loops and switches of the process to the screens.
func (s *Server) SetProcess(process Process) {
	s.process = &process
}

// statusBlock is one part of the panel as the screen judges it. OK is
// nil when the panel cannot tell; Reason explains a false OK; Attention
// is a note on a block that is fine but deserves a look - a webhook
// receiver that fails, a certificate that runs out next week.
type statusBlock struct {
	OK        *bool          `json:"ok"`
	Reason    string         `json:"reason,omitempty"`
	Attention string         `json:"attention,omitempty"`
	Facts     map[string]any `json:"facts"`
}

func statusOK(facts map[string]any) statusBlock {
	ok := true
	return statusBlock{OK: &ok, Facts: facts}
}

func statusFailed(reason string, facts map[string]any) statusBlock {
	ok := false
	if facts == nil {
		facts = map[string]any{}
	}
	return statusBlock{OK: &ok, Reason: reason, Facts: facts}
}

func statusUnknown(reason string, facts map[string]any) statusBlock {
	if facts == nil {
		facts = map[string]any{}
	}
	return statusBlock{Reason: reason, Facts: facts}
}

// statusQueryTimeout bounds every query of the screen. A status page that
// hangs on the database it is asking about answers nothing to the person
// who needs to know that the database hangs.
const statusQueryTimeout = 5 * time.Second

// handleStatus returns the condition of every part of the panel. The
// permission is the one of the settings screen: whoever may see how the
// panel is set up may see how it is doing. The read leaves no audit event,
// unlike the settings: the screen refreshes itself every few seconds, and
// a trail of one event per refresh would bury the events that matter.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	principal := authz.FromContext(r.Context())
	if !principal.Authenticated() || !principal.Can(authz.PermSettingsRead, authz.GlobalScope) {
		if _, ok := s.authorize(w, r, authz.PermPrincipalManage, authz.GlobalScope, "status", ""); !ok {
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), statusQueryTimeout)
	defer cancel()

	blocks := map[string]statusBlock{
		"database":            s.databaseStatus(ctx),
		"migrations":          s.migrationsStatus(ctx),
		"outbox":              s.outboxStatus(ctx),
		"scheduler":           s.schedulerStatus(ctx),
		"sessions":            s.sessionsStatus(ctx),
		"relays":              s.relaysStatus(ctx),
		"directory":           s.directoryStatus(),
		"vulnerability_feeds": s.feedsStatus(ctx),
		"certificates":        s.certificatesStatus(ctx),
		"crypto":              s.cryptoStatus(ctx),
		"housekeeping":        s.housekeepingStatus(),
		"build":               s.buildStatus(),
	}
	// The verdict of the whole: false when any block that could be judged
	// is not fine; unknown blocks do not make it green, they make it
	// incomplete, and the screen says so next to the verdict.
	overall := true
	unknown := 0
	for _, block := range blocks {
		if block.OK == nil {
			unknown++
			continue
		}
		if !*block.OK {
			overall = false
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC(),
		"ok":           overall,
		"unknown":      unknown,
		"blocks":       blocks,
		"links": map[string]string{
			"openapi": "/api/v1/openapi.json",
			"metrics": "/metrics",
		},
	})
}

// databaseStatus asks the database about itself. The latency is the round
// trip of the simplest query; a panel that answers slowly starts here.
func (s *Server) databaseStatus(ctx context.Context) statusBlock {
	facts := map[string]any{"reachable": false}
	started := time.Now()
	var one int
	if err := s.pool.QueryRow(ctx, `select 1`).Scan(&one); err != nil {
		facts["error"] = err.Error()
		return statusFailed("the database does not answer", facts)
	}
	facts["reachable"] = true
	facts["latency_ms"] = float64(time.Since(started).Microseconds()) / 1000

	stat := s.pool.Stat()
	facts["pool_used"] = stat.TotalConns()
	facts["pool_max"] = stat.MaxConns()

	var size *int64
	if err := s.pool.QueryRow(ctx, `select pg_database_size(current_database())`).Scan(&size); err == nil && size != nil {
		facts["size_bytes"] = *size
	}
	var used, maximum *int
	if err := s.pool.QueryRow(ctx, `
		select (select count(*) from pg_stat_activity where datname = current_database()),
		       current_setting('max_connections')::int`).Scan(&used, &maximum); err == nil {
		if used != nil {
			facts["connections_used"] = *used
		}
		if maximum != nil {
			facts["connections_max"] = *maximum
		}
	}
	// The oldest open transaction: a report that holds one for an hour
	// holds the vacuum and the sweeps with it.
	var oldest *float64
	if err := s.pool.QueryRow(ctx, `
		select extract(epoch from now() - min(xact_start))
		  from pg_stat_activity
		 where datname = current_database() and xact_start is not null and state <> 'idle'`).
		Scan(&oldest); err == nil {
		if oldest == nil {
			facts["oldest_transaction_seconds"] = 0
		} else {
			facts["oldest_transaction_seconds"] = *oldest
		}
	}
	var version string
	if err := s.pool.QueryRow(ctx, `show server_version`).Scan(&version); err == nil {
		facts["server_version"] = version
	}

	block := statusOK(facts)
	if used != nil && maximum != nil && *maximum > 0 && *used*10 >= *maximum*8 {
		block.Attention = "the server is near its connection limit"
	} else if oldest != nil && *oldest > 600 {
		block.Attention = "a transaction has been open for more than ten minutes"
	}
	return block
}

// migrationsStatus reads the schema level. The migrations are named by a
// number and a word; the number is the level.
func (s *Server) migrationsStatus(ctx context.Context) statusBlock {
	var latest string
	var applied int
	if err := s.pool.QueryRow(ctx,
		`select coalesce(max(version), ''), count(*) from schema_migrations`).Scan(&latest, &applied); err != nil {
		return statusUnknown("the migration table could not be read: "+err.Error(), nil)
	}
	level := 0
	if number, _, _ := strings.Cut(latest, "_"); number != "" {
		level, _ = strconv.Atoi(number)
	}
	facts := map[string]any{"level": level, "latest": latest, "applied": applied}
	if level == 0 {
		return statusFailed("no migration is recorded", facts)
	}
	return statusOK(facts)
}

// outboxStatus reads the durable trail: what waits for the publisher and
// where every external consumer has got to. An event that waits longer
// than a couple of rounds of the publisher is a publisher that stopped.
func (s *Server) outboxStatus(ctx context.Context) statusBlock {
	var pending int
	var oldest *float64
	var lastPublished *time.Time
	if err := s.pool.QueryRow(ctx, `
		select count(*) filter (where published_at is null),
		       extract(epoch from now() - (min(occurred_at) filter (where published_at is null))),
		       max(published_at)
		  from outbox_events`).Scan(&pending, &oldest, &lastPublished); err != nil {
		return statusUnknown("the durable trail could not be read: "+err.Error(), nil)
	}
	facts := map[string]any{
		"pending":                pending,
		"oldest_pending_seconds": 0.0,
		"last_published_at":      lastPublished,
	}
	if oldest != nil {
		facts["oldest_pending_seconds"] = *oldest
	}

	type consumer struct {
		Name      string    `json:"name"`
		Behind    int64     `json:"behind"`
		Failures  int       `json:"failures"`
		LastError string    `json:"last_error,omitempty"`
		UpdatedAt time.Time `json:"updated_at"`
	}
	consumers := []consumer{}
	rows, err := s.pool.Query(ctx, `
		select name, (select coalesce(max(id), 0) from outbox_events) - last_id, failures, last_error, updated_at
		  from outbox_consumers order by name`)
	if err != nil {
		return statusUnknown("the consumers of the durable trail could not be read: "+err.Error(), facts)
	}
	defer rows.Close()
	failing := []string{}
	for rows.Next() {
		var c consumer
		if err := rows.Scan(&c.Name, &c.Behind, &c.Failures, &c.LastError, &c.UpdatedAt); err != nil {
			return statusUnknown("the consumers of the durable trail could not be read: "+err.Error(), facts)
		}
		if c.Behind < 0 {
			c.Behind = 0
		}
		if c.Failures > 0 {
			failing = append(failing, c.Name)
		}
		consumers = append(consumers, c)
	}
	facts["consumers"] = consumers
	if rows.Err() != nil {
		return statusUnknown("the consumers of the durable trail could not be read: "+rows.Err().Error(), facts)
	}

	if oldest != nil && *oldest > 120 {
		return statusFailed("an event has waited for the publisher for more than two minutes", facts)
	}
	block := statusOK(facts)
	if len(failing) > 0 {
		// A receiver that is down is the receiver's condition, not the
		// panel's: the cursor holds and nothing is lost.
		block.Attention = "a consumer fails its deliveries: " + strings.Join(failing, ", ")
	}
	return block
}

// schedulerStatus reads the queue. The throughput counters live in the
// metrics endpoint; here is what waits and how long the oldest has.
func (s *Server) schedulerStatus(ctx context.Context) statusBlock {
	rows, err := s.pool.Query(ctx, `
		select state, count(*) from jobs
		 where state in ('awaiting_approval', 'queued', 'leased', 'dispatched', 'running', 'cancel_requested')
		 group by 1`)
	if err != nil {
		return statusUnknown("the queue could not be read: "+err.Error(), nil)
	}
	defer rows.Close()
	facts := map[string]any{
		"awaiting_approval": 0, "queued": 0, "leased": 0, "dispatched": 0, "running": 0,
		"dispatch_rate": 0,
	}
	for rows.Next() {
		var state string
		var count int
		if err := rows.Scan(&state, &count); err != nil {
			return statusUnknown("the queue could not be read: "+err.Error(), facts)
		}
		facts[state] = count
	}
	if rows.Err() != nil {
		return statusUnknown("the queue could not be read: "+rows.Err().Error(), facts)
	}
	var oldest *float64
	if err := s.pool.QueryRow(ctx,
		`select extract(epoch from now() - min(created_at)) from jobs where state = 'queued'`).
		Scan(&oldest); err != nil {
		return statusUnknown("the queue could not be read: "+err.Error(), facts)
	}
	facts["oldest_queued_seconds"] = 0.0
	if oldest != nil {
		facts["oldest_queued_seconds"] = *oldest
	}
	if s.process != nil {
		facts["dispatch_rate"] = s.process.DispatchRate
	}
	block := statusOK(facts)
	// A task queued for an hour is a host that is offline or a budget that
	// is full, not a scheduler that stopped; the screen points at it
	// without calling the scheduler broken.
	if oldest != nil && *oldest > 3600 {
		block.Attention = "the oldest queued task has waited for more than an hour"
	}
	return block
}

// sessionsStatus counts who is connected: the agents on this gateway, the
// hosts the database calls online across every gateway, the live browser
// sessions.
func (s *Server) sessionsStatus(ctx context.Context) statusBlock {
	facts := map[string]any{"agents_on_this_gateway": s.registry.Count()}
	var online, stale, web int
	if err := s.pool.QueryRow(ctx, `
		select (select count(*) from hosts where connection_state = 'online'),
		       (select count(*) from hosts where connection_state = 'stale'),
		       (select count(*) from web_sessions
		         where revoked_at is null and absolute_expires_at > now() and idle_expires_at > now())`).
		Scan(&online, &stale, &web); err != nil {
		return statusUnknown("the sessions could not be counted: "+err.Error(), facts)
	}
	facts["hosts_online"] = online
	facts["hosts_stale"] = stale
	facts["web_sessions"] = web
	return statusOK(facts)
}

// relaysStatus counts the relays by state. A silent relay is a site whose
// hosts are about to lose their results; a relay never seen is one that
// was registered and has not started yet.
func (s *Server) relaysStatus(ctx context.Context) statusBlock {
	if s.relays == nil {
		return statusUnknown("this installation keeps no relays", map[string]any{"total": 0})
	}
	list, err := s.relays.List(ctx)
	if err != nil {
		return statusUnknown("the relays could not be read: "+err.Error(), nil)
	}
	counts := map[string]int{}
	now := time.Now()
	for _, relay := range list {
		counts[relayState(relay, now)]++
	}
	facts := map[string]any{
		"total":      len(list) - counts[relays.StateRevoked],
		"active":     counts[relays.StateActive],
		"silent":     counts[relays.StateSilent],
		"never_seen": counts[relays.StateNeverSeen],
		"revoked":    counts[relays.StateRevoked],
		"degraded":   counts[relays.StateSilent] + counts[relays.StateNeverSeen],
	}
	if counts[relays.StateSilent] > 0 {
		return statusFailed(strconv.Itoa(counts[relays.StateSilent])+" relays have not reported for ten minutes", facts)
	}
	block := statusOK(facts)
	if counts[relays.StateNeverSeen] > 0 {
		block.Attention = strconv.Itoa(counts[relays.StateNeverSeen]) + " relays were registered and have never reported"
	}
	return block
}

// relayState names the state of a relay the way the list and the metrics
// do, so the three agree on every count.
func relayState(relay relays.Relay, now time.Time) string {
	switch {
	case relay.RevokedAt != nil:
		return relays.StateRevoked
	case relay.LastSeenAt == nil:
		return relays.StateNeverSeen
	case relay.LastSeenAt.Before(now.Add(-relays.SilentAfter)):
		return relays.StateSilent
	default:
		return relays.StateActive
	}
}

// directoryStatus reads the connector's own record of its calls. No call
// reaches the directory here: a status page must answer at once when the
// directory does not.
func (s *Server) directoryStatus() statusBlock {
	if s.directory == nil {
		return statusUnknown("the directory connector is not configured", map[string]any{"configured": false})
	}
	health := s.directory.Health()
	facts := map[string]any{
		"configured":      true,
		"principal":       health.Principal,
		"keytab_readable": health.KeytabReadable,
		"last_success_at": health.LastSuccessAt,
		"last_error":      health.LastError,
		"last_error_at":   health.LastErrorAt,
		"last_refusal":    health.LastRefusal,
		"last_refusal_at": health.LastRefusalAt,
		"cache_entries":   health.CacheEntries,
	}
	if !health.KeytabReadable {
		return statusFailed("the keytab holds no entries or was not read", facts)
	}
	if health.LastSuccessAt == nil && health.LastErrorAt == nil {
		return statusUnknown("no call has reached the directory since the panel started", facts)
	}
	if health.LastErrorAt != nil && (health.LastSuccessAt == nil || health.LastErrorAt.After(*health.LastSuccessAt)) {
		return statusFailed("the last call to the directory failed: "+health.LastError, facts)
	}
	block := statusOK(facts)
	if health.LastRefusalAt != nil && health.LastSuccessAt != nil && health.LastRefusalAt.After(*health.LastSuccessAt) {
		block.Attention = "the directory refused the last command: " + health.LastRefusal
	}
	return block
}

// feedsStatus reads the age of every vulnerability feed. A feed is stale
// when the panel has not confirmed it within the configured age, not when
// its data have not changed.
func (s *Server) feedsStatus(ctx context.Context) statusBlock {
	if s.vulnerabilities == nil {
		return statusUnknown("the vulnerability correlator is not enabled", map[string]any{"enabled": false})
	}
	snapshots, err := s.vulnerabilities.Snapshots(ctx)
	if err != nil {
		return statusUnknown("the feed snapshots could not be read: "+err.Error(), map[string]any{"enabled": true})
	}
	type feed struct {
		Provider   string  `json:"provider"`
		AgeSeconds float64 `json:"age_seconds"`
		Stale      bool    `json:"stale"`
		Advisories int     `json:"advisories"`
		Error      string  `json:"error,omitempty"`
	}
	now := time.Now().UTC()
	feeds := []feed{}
	stale := []string{}
	failing := []string{}
	for _, snapshot := range snapshots {
		checked := snapshot.FetchedAt
		if snapshot.CheckedAt != nil && snapshot.CheckedAt.After(checked) {
			checked = *snapshot.CheckedAt
		}
		item := feed{
			Provider:   snapshot.Provider,
			AgeSeconds: now.Sub(checked).Seconds(),
			Stale:      snapshot.Stale(s.feedAge, now),
			Advisories: snapshot.AdvisoryCount,
			Error:      snapshot.Error,
		}
		if item.Stale {
			stale = append(stale, snapshot.Provider)
		}
		if item.Error != "" {
			failing = append(failing, snapshot.Provider)
		}
		feeds = append(feeds, item)
	}
	facts := map[string]any{
		"enabled":                  true,
		"max_snapshot_age_seconds": s.feedAge.Seconds(),
		"feeds":                    feeds,
	}
	if len(feeds) == 0 {
		return statusUnknown("no feed has been read yet", facts)
	}
	if len(stale) > 0 {
		return statusFailed("stale feeds: "+strings.Join(stale, ", "), facts)
	}
	block := statusOK(facts)
	if len(failing) > 0 {
		block.Attention = "the last fetch failed for: " + strings.Join(failing, ", ")
	}
	return block
}

// certificatesStatus reads the fleet CA and the agent certificates about
// to run out. The counts are the ones the metrics endpoint exposes, read
// the same way, so the screen and the alert agree.
func (s *Server) certificatesStatus(ctx context.Context) statusBlock {
	if s.trust == nil {
		return statusUnknown("this panel holds no trust set", nil)
	}
	ca := s.trust.Active()
	if ca == nil || ca.Certificate == nil {
		return statusFailed("no active CA", nil)
	}
	notAfter := ca.Certificate.NotAfter
	facts := map[string]any{
		"ca_subject":         ca.Certificate.Subject.CommonName,
		"ca_not_after":       notAfter.UTC(),
		"ca_expires_in_days": int(time.Until(notAfter).Hours() / 24),
		"authorities":        len(s.trust.Authorities()),
	}
	var within7, within30 int
	if err := s.pool.QueryRow(ctx, `
		select count(*) filter (where soonest < now() + interval '7 days'),
		       count(*) filter (where soonest < now() + interval '30 days')
		  from (select h.id, min(c.not_after) as soonest
		          from agent_certificates c join hosts h on h.id = c.host_id
		         where c.revoked_at is null and c.not_after > now() and h.lifecycle_state <> 'retired'
		         group by h.id) t`).Scan(&within7, &within30); err != nil {
		return statusUnknown("the agent certificates could not be counted: "+err.Error(), facts)
	}
	facts["agents_expiring_7d"] = within7
	facts["agents_expiring_30d"] = within30

	if time.Until(notAfter) < 30*24*time.Hour {
		return statusFailed("the fleet CA expires within thirty days", facts)
	}
	block := statusOK(facts)
	if within7 > 0 {
		block.Attention = strconv.Itoa(within7) + " hosts hold a certificate that expires within a week"
	}
	return block
}

// cryptoStatus repeats the self-test of the startup guard: the active
// key is there and opens the installation sentinel, and the CA on disk is
// the recorded issuer. The counts by key are what a key rotation is
// judged by - the old key may go only when nothing names it.
func (s *Server) cryptoStatus(ctx context.Context) statusBlock {
	if s.process == nil || s.process.Crypto == nil {
		return statusUnknown("this panel started without the cryptographic state guard", nil)
	}
	report := s.process.Crypto.Report(ctx)
	facts := map[string]any{
		"installation_id":    report.InstallationID,
		"provider":           report.Provider,
		"active_key_id":      report.ActiveKeyID,
		"issuer_id":          report.IssuerID,
		"issuer_fingerprint": report.IssuerFingerprint,
		"revision":           report.Revision,
		"initialized_at":     report.InitializedAt.UTC(),
		"keys":               report.Keys,
		"versions_by_key":    report.VersionsByKey,
		"pending_rewrap":     report.PendingRewrap,
		"initialised":        report.Initialised,
		"adopted":            report.Adopted,
	}
	if report.Err != nil {
		return statusFailed("the cryptographic state of the installation is not usable: "+report.Err.Error(), facts)
	}
	block := statusOK(facts)
	if report.PendingRewrap > 0 {
		block.Attention = strconv.Itoa(report.PendingRewrap) + " secret versions are still on another key or in the old form; the rewrap runs in the background"
	} else if unused := unusedKeys(report); len(unused) > 0 {
		block.Attention = "keys that no version names any more may be removed: " + strings.Join(unused, ", ")
	}
	return block
}

// unusedKeys lists the keys the provider holds that are neither active
// nor named by any live version - the ones a finished rotation leaves
// behind. A version of the first form counts for the legacy key.
func unusedKeys(report cryptostate.Report) []string {
	var unused []string
	for _, key := range report.Keys {
		if key == report.ActiveKeyID {
			continue
		}
		inUse := report.VersionsByKey[key] > 0
		if key == secrets.LegacyKeyID {
			inUse = inUse || report.VersionsByKey[secrets.LegacyFormLabel] > 0
		}
		if !inUse {
			unused = append(unused, key)
		}
	}
	return unused
}

// housekeepingStatus reads the record of the last retention sweep.
func (s *Server) housekeepingStatus() statusBlock {
	if s.process == nil || s.process.Housekeeping == nil {
		return statusUnknown("this panel runs no retention sweep", nil)
	}
	report := s.process.Housekeeping.Report()
	facts := map[string]any{
		"last_sweep_at": report.LastSweepAt,
		"removed":       report.Removed,
		"retention":     report.Retention,
	}
	if report.LastSweepAt == nil {
		return statusUnknown("the sweep has not run since the panel started", facts)
	}
	if report.LastError != "" {
		facts["last_error"] = report.LastError
		return statusFailed("the last sweep failed: "+report.LastError, facts)
	}
	return statusOK(facts)
}

// buildStatus names the binary and the process; it is the block a bug
// report starts with.
func (s *Server) buildStatus() statusBlock {
	hostname, _ := os.Hostname()
	facts := map[string]any{
		"version":        buildinfo.Version,
		"commit":         buildinfo.ShortCommit(),
		"build_date":     buildinfo.Date,
		"go_version":     runtime.Version(),
		"platform":       runtime.GOOS + "/" + runtime.GOARCH,
		"agent_protocol": buildinfo.AgentProtocol,
		"started_at":     processStarted.UTC(),
		"uptime_seconds": time.Since(processStarted).Seconds(),
		"hostname":       hostname,
		"goroutines":     runtime.NumGoroutine(),
	}
	if s.settings != nil {
		facts["gateway_id"] = s.settings.GatewayID
	}
	return statusOK(facts)
}
