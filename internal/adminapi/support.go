package adminapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/buildinfo"
	"github.com/ultherego/flotestro/internal/secrets"
	"github.com/ultherego/flotestro/internal/support"
)

// The support bundle of the panel: a set of readings an operator hands to
// whoever is helping them (security remediation, chapter 14.6). Asking for one
// needs fresh authentication and a reason, fetching one needs a link that
// expires, and both are on the trail.

// supportBundleBudget bounds the assembly of one bundle: a panel whose
// database has stopped answering must still finish the attempt and say so.
const supportBundleBudget = 2 * time.Minute

// supportStore builds the store on the key material of the installation. A
// panel that cannot seal anything does not produce a bundle either: the
// refusal names the key material rather than the permission.
func (s *Server) supportStore(w http.ResponseWriter) (*support.Store, bool) {
	if s.process == nil || s.process.Crypto == nil {
		problem(w, http.StatusServiceUnavailable, "support_bundle_unsealed",
			"this panel holds no key material, so it neither makes nor opens a support bundle")
		return nil, false
	}
	return support.NewStore(s.pool, s.process.Crypto.Provider()), true
}

// supportBundleView is one bundle on the screen, with what the operator may
// do with it next.
type supportBundleView struct {
	support.Bundle
	// Downloadable says the archive is there to be fetched.
	Downloadable bool `json:"downloadable"`
}

func supportView(bundle support.Bundle) supportBundleView {
	return supportBundleView{Bundle: bundle, Downloadable: bundle.State == support.StateReady}
}

// handleListSupportBundles returns the bundles this panel holds.
func (s *Server) handleListSupportBundles(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorizeCollection(w, r, authz.PermSupportBundleRead, "support_bundle"); !ok {
		return
	}
	store, ok := s.supportStore(w)
	if !ok {
		return
	}
	bundles, err := store.List(r.Context(), 50)
	if err != nil {
		s.fail(w, err)
		return
	}
	views := make([]supportBundleView, 0, len(bundles))
	for _, bundle := range bundles {
		views = append(views, supportView(bundle))
	}
	retention := s.supportRetention()
	writeJSON(w, http.StatusOK, struct {
		Items []supportBundleView `json:"items"`
		Count int                 `json:"count"`
		// Retention says on the screen how long what is listed will be there,
		// and TokenTTL how long a link lasts.
		Retention map[string]string `json:"retention"`
		TokenTTL  string            `json:"token_ttl"`
	}{views, len(views), map[string]string{
		"bundles":       retention.Age.String(),
		"never_fetched": retention.Unfetched.String(),
	}, support.TokenTTL.String()})
}

// handleGetSupportBundle returns one bundle, which is how the screen watches
// one that is still being assembled.
func (s *Server) handleGetSupportBundle(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorizeCollection(w, r, authz.PermSupportBundleRead, "support_bundle"); !ok {
		return
	}
	store, ok := s.supportStore(w)
	if !ok {
		return
	}
	bundle, err := store.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		s.failSupport(w, err)
		return
	}
	writeJSON(w, http.StatusOK, supportView(bundle))
}

// handleCreateSupportBundle asks for a bundle. The reading is done after the
// answer: the row is what the screen watches, and an assembly that fails says
// so on the row rather than in a request that timed out.
func (s *Server) handleCreateSupportBundle(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermSupportBundleCreate, "support_bundle")
	if !ok {
		return
	}
	store, ok := s.supportStore(w)
	if !ok {
		return
	}
	reason, ok := requestReason(w, r, nil)
	if !ok {
		return
	}
	evidence, ok := s.requireStepUp(w, r, principal, reason, "support.bundle.create", "support_bundle", "")
	if !ok {
		return
	}

	// One at a time: a bundle is a reading of the whole panel, and a screen
	// that can queue them turns a support request into a load test.
	existing, err := store.List(r.Context(), 20)
	if err != nil {
		s.fail(w, err)
		return
	}
	for _, bundle := range existing {
		if bundle.State != support.StatePending {
			continue
		}
		if time.Since(bundle.RequestedAt) < supportBundleBudget {
			problem(w, http.StatusConflict, "support_bundle_in_flight",
				"a bundle is already being assembled; wait for it before asking for another")
			return
		}
		// A row still pending past the budget belongs to a panel that went
		// away mid-assembly. It is said to have failed rather than left to
		// look like work in progress for the rest of its retention.
		if err := store.Fail(r.Context(), bundle.ID, "support_bundle_abandoned"); err != nil {
			s.fail(w, err)
			return
		}
	}

	bundle, err := store.Request(r.Context(), principal.Subject, strings.TrimSpace(reason))
	if err != nil {
		s.fail(w, err)
		return
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "support.bundle.create", TargetType: "support_bundle", TargetID: bundle.ID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		// The detail names the bundle and nothing that is in it.
		Detail: withStepUp(map[string]any{"bundle_id": bundle.ID}, evidence),
	})

	// The assembly outlives the request that asked for it: the operator gets
	// the row now and watches it fill.
	go s.assembleSupportBundle(context.WithoutCancel(r.Context()), store, bundle)
	writeJSON(w, http.StatusAccepted, supportView(bundle))
}

// assembleSupportBundle collects the readings, scans them and seals the result
// onto the row.
func (s *Server) assembleSupportBundle(parent context.Context, store *support.Store, bundle support.Bundle) {
	ctx, cancel := context.WithTimeout(parent, supportBundleBudget)
	defer cancel()

	hostname, _ := os.Hostname()
	request := support.Request{
		BundleID: bundle.ID, Panel: hostname, Tool: "flotestro-control-plane " + buildinfo.Version,
		RequestedBy: bundle.RequestedBy, Reason: bundle.Reason, CreatedAt: time.Now().UTC(),
	}
	archive, manifest, err := support.Build(ctx, request, s.supportCollectors())
	if err == nil {
		err = store.Seal(ctx, bundle.ID, archive, manifest)
	}
	if err == nil {
		return
	}
	code := "support_bundle_failed"
	var leak *support.LeakError
	if errors.As(err, &leak) {
		code = leak.Code()
	}
	if errors.Is(err, secrets.ErrKeyUnavailable) {
		code = "support_bundle_unsealed"
	}
	s.log.Error("the support bundle was not assembled", "bundle_id", bundle.ID, "code", code, "err", err)
	// The refusal is recorded on a budget of its own: an assembly that ran out
	// of time must still be able to say that it did.
	noted, noteCancel := context.WithTimeout(parent, 10*time.Second)
	defer noteCancel()
	if failErr := store.Fail(noted, bundle.ID, code); failErr != nil {
		s.log.Error("the failed support bundle was not recorded", "bundle_id", bundle.ID, "err", failErr)
	}
}

// handleSupportBundleToken hands out the short-lived right to fetch one
// bundle. It is the step-up the chapter asks for at the download.
func (s *Server) handleSupportBundleToken(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermSupportBundleRead, "support_bundle")
	if !ok {
		return
	}
	store, ok := s.supportStore(w)
	if !ok {
		return
	}
	id := r.PathValue("id")
	reason, ok := requestReason(w, r, nil)
	if !ok {
		return
	}
	evidence, ok := s.requireStepUp(w, r, principal, reason, "support.bundle.download", "support_bundle", id)
	if !ok {
		return
	}
	token, err := store.Issue(r.Context(), id, principal.Subject, time.Now())
	if err != nil {
		s.failSupport(w, err)
		return
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "support.bundle.token", TargetType: "support_bundle", TargetID: id,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: withStepUp(map[string]any{
			"bundle_id": id, "expires_at": token.ExpiresAt.Format(time.RFC3339),
		}, evidence),
	})
	writeJSON(w, http.StatusCreated, struct {
		// URL is the whole link, so the screen does not assemble one of its own.
		URL       string    `json:"url"`
		ExpiresAt time.Time `json:"expires_at"`
	}{supportDownloadURL(id, token.Value), token.ExpiresAt})
}

// supportDownloadURL is the link a token opens.
func supportDownloadURL(id, token string) string {
	return "/api/v1/support/bundles/" + id + "/archive?token=" + token
}

// handleDownloadSupportBundle hands the archive over against a token that
// expires and is spent by this one fetch.
func (s *Server) handleDownloadSupportBundle(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermSupportBundleRead, "support_bundle")
	if !ok {
		return
	}
	store, ok := s.supportStore(w)
	if !ok {
		return
	}
	id := r.PathValue("id")
	token := r.URL.Query().Get("token")
	if token == "" {
		s.denySupportDownload(w, r, principal, id, "support_bundle_token_required", http.StatusUnauthorized,
			"the archive is fetched with the link the panel issued; ask for one and follow it")
		return
	}
	bundle, err := store.Redeem(r.Context(), token, principal.Subject, time.Now())
	if err != nil {
		code, status, detail := supportRefusal(err)
		if code == "" {
			s.fail(w, err)
			return
		}
		s.denySupportDownload(w, r, principal, id, code, status, detail)
		return
	}
	if bundle.ID != id {
		// The token names its own bundle; a link pointed at another one is not
		// a link to that one.
		s.denySupportDownload(w, r, principal, id, "support_bundle_token_mismatch", http.StatusForbidden,
			"this link opens another bundle")
		return
	}

	archive, err := store.Open(r.Context(), bundle.ID)
	if err != nil {
		if errors.Is(err, secrets.ErrKeyUnavailable) {
			s.denySupportDownload(w, r, principal, id, "support_bundle_unsealed", http.StatusServiceUnavailable,
				"the key this bundle was sealed under is not available to this panel")
			return
		}
		s.fail(w, err)
		return
	}
	if err := store.Fetched(r.Context(), bundle.ID, time.Now()); err != nil {
		s.log.Error("the download of a support bundle was not recorded", "bundle_id", bundle.ID, "err", err)
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "support.bundle.download", TargetType: "support_bundle", TargetID: bundle.ID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"bundle_id": bundle.ID, "archive_sha256": bundle.ArchiveSHA256, "size_bytes": bundle.SizeBytes,
		},
	})

	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=%q", "flotestro-support-"+bundle.ID+".tar.gz"))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Flotestro-Bundle-SHA256", bundle.ArchiveSHA256)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(archive)
}

// denySupportDownload refuses a fetch and says so on the trail: a link that
// did not work is exactly the event somebody wants to read about later.
func (s *Server) denySupportDownload(w http.ResponseWriter, r *http.Request,
	principal authz.Principal, id, code string, status int, detail string) {
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "support.bundle.download", TargetType: "support_bundle", TargetID: id,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeDenied,
		Detail: map[string]any{"bundle_id": id, "reason": code},
	})
	problem(w, status, code, detail)
}

// supportRefusal turns a refusal of the store into the code and the status the
// API answers with.
func supportRefusal(err error) (code string, status int, detail string) {
	switch {
	case errors.Is(err, support.ErrNotFound):
		return "support_bundle_not_found", http.StatusNotFound, "no such support bundle"
	case errors.Is(err, support.ErrNotReady):
		return "support_bundle_not_ready", http.StatusConflict,
			"the bundle is still being assembled; it can be fetched once it is ready"
	case errors.Is(err, support.ErrTokenUnknown):
		return "support_bundle_token_invalid", http.StatusUnauthorized,
			"this link is not one this panel issued, or the bundle behind it is gone"
	case errors.Is(err, support.ErrTokenExpired):
		return "support_bundle_token_expired", http.StatusUnauthorized,
			"this link has expired; ask for a new one"
	case errors.Is(err, support.ErrTokenSpent):
		return "support_bundle_token_spent", http.StatusUnauthorized,
			"this link has already been followed; ask for a new one"
	case errors.Is(err, support.ErrTokenForeign):
		return "support_bundle_token_foreign", http.StatusForbidden,
			"this link was issued to another identity"
	default:
		return "", 0, ""
	}
}

// failSupport answers a refusal of the store, or reports a real failure.
func (s *Server) failSupport(w http.ResponseWriter, err error) {
	if code, status, detail := supportRefusal(err); code != "" {
		problem(w, status, code, detail)
		return
	}
	s.fail(w, err)
}

// supportRetention is what this panel keeps its bundles for: the sweeper's
// setting where there is one, the package default otherwise.
func (s *Server) supportRetention() support.Retention {
	retention := support.Retention{}
	if s.process != nil && s.process.Housekeeping != nil {
		options := s.process.Housekeeping.Options()
		retention = support.Retention{Age: options.SupportBundles, Unfetched: options.SupportBundlesUnfetched}
	}
	return retention.WithDefaults()
}

/* ---------------------------------------------------------------------- */
/* What the bundle is made of. Every collector declares its fields.        */
/* ---------------------------------------------------------------------- */

// supportCollectors lists the readings of the panel, in the order they are
// read. No collector reads a credential: what would carry one is declared
// secret and never fetched.
func (s *Server) supportCollectors() []support.Collector {
	return []support.Collector{
		support.JSONCollector("panel.json", "the build and the process of this panel",
			[]support.Field{
				{Name: "version, commit, platform", Sensitivity: support.FieldPublic},
				{Name: "hostname, uptime, gateway id", Sensitivity: support.FieldSensitive},
			},
			func(context.Context) (any, error) { return s.buildStatus().Facts, nil }),

		support.JSONCollector("status.json", "the status screen of this panel",
			[]support.Field{
				{Name: "the verdict of every part of the panel", Sensitivity: support.FieldPublic},
				{Name: "counts, ages, addresses of relays and replicas", Sensitivity: support.FieldSensitive},
			},
			func(ctx context.Context) (any, error) { return s.supportStatus(ctx), nil }),

		support.JSONCollector("settings.json", "the settings this panel was started with",
			[]support.Field{
				{Name: "step-up, preview, retention and session settings", Sensitivity: support.FieldSensitive},
				{Name: "public url and production environments", Sensitivity: support.FieldSensitive},
				{Name: "identity provider client secret, database password, secret store keys", Sensitivity: support.FieldSecret, Why: "whoever reads one can sign in as this panel or open its store, so the bundle never reads them"},
			},
			func(context.Context) (any, error) { return s.supportSettings(), nil }),

		support.JSONCollector("housekeeping.json", "the retention sweep of this panel",
			[]support.Field{{Name: "retentions and what the last sweep removed", Sensitivity: support.FieldPublic}},
			func(context.Context) (any, error) { return s.housekeepingStatus().Facts, nil }),

		support.JSONCollector("fleet.json", "the counts of the fleet",
			[]support.Field{
				{Name: "hosts by state, agent versions, jobs of the last day", Sensitivity: support.FieldSensitive},
				{Name: "hostnames, addresses and payloads", Sensitivity: support.FieldSecret, Why: "a bundle answers what the panel is doing, not who it is doing it to; the counts carry no host"},
			},
			s.supportFleet),
	}
}

// supportStatus is the status screen as the bundle carries it: the same
// verdicts, without the blocks that only repeat what the other readings say.
func (s *Server) supportStatus(ctx context.Context) map[string]statusBlock {
	return map[string]statusBlock{
		"database":            s.databaseStatus(ctx),
		"replicas":            s.replicasStatus(ctx),
		"migrations":          s.migrationsStatus(ctx),
		"outbox":              s.outboxStatus(ctx),
		"scheduler":           s.schedulerStatus(ctx),
		"sessions":            s.sessionsStatus(ctx),
		"relays":              s.relaysStatus(ctx),
		"directory":           s.directoryStatus(),
		"vulnerability_feeds": s.feedsStatus(ctx),
		"certificates":        s.certificatesStatus(ctx),
		"crypto":              s.cryptoStatus(ctx),
		"monitoring":          s.monitoringStatus(ctx),
	}
}

// supportSettings is what the panel was started with, named fact by fact. The
// effective configuration is not marshalled as a whole on purpose: a field
// added to it later would end up in the bundle without anybody deciding so.
func (s *Server) supportSettings() map[string]any {
	environments := make([]string, 0, len(s.productionEnvironments))
	for environment := range s.productionEnvironments {
		environments = append(environments, environment)
	}
	settings := map[string]any{
		"public_url":               s.publicURL,
		"production_environments":  environments,
		"session_idle":             s.sessionLimits.Idle.String(),
		"session_absolute":         s.sessionLimits.Absolute.String(),
		"step_up_max_age":          s.stepUp.MaxAge.String(),
		"step_up_acr":              s.stepUp.ACR,
		"step_up_refuses_tokens":   s.stepUp.RefuseTokens,
		"campaign_preview_mode":    string(s.previewMode),
		"directory_write":          s.directoryWrite,
		"secret_store":             s.secrets != nil,
		"notifications":            s.notifications != nil,
		"support_bundle_retention": s.supportRetention().Age.String(),
	}
	if s.settings != nil {
		settings["gateway_id"] = s.settings.GatewayID
	}
	return settings
}

// supportFleet counts what the panel manages. It is a tally and never a list:
// a bundle that carries host names carries the customer's estate with it.
func (s *Server) supportFleet(ctx context.Context) (any, error) {
	fleet := map[string]any{}
	for _, tally := range []struct {
		key   string
		query string
	}{
		{"hosts_by_connection", `select connection_state, count(*) from hosts group by 1`},
		{"hosts_by_lifecycle", `select lifecycle_state, count(*) from hosts group by 1`},
		{"agent_versions", `select coalesce(nullif(agent_version, ''), 'unknown'), count(*) from hosts group by 1`},
		{"jobs_last_day", `select state, count(*) from jobs where created_at > now() - interval '1 day' group by 1`},
	} {
		counts, err := s.countBy(ctx, tally.query)
		if err != nil {
			return fleet, err
		}
		fleet[tally.key] = counts
	}
	fleet["goroutines"] = runtime.NumGoroutine()
	return fleet, nil
}

// countBy runs a "value, count" query into a map.
func (s *Server) countBy(ctx context.Context, query string) (map[string]int64, error) {
	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	counts := map[string]int64{}
	for rows.Next() {
		var key string
		var count int64
		if err := rows.Scan(&key, &count); err != nil {
			return nil, err
		}
		counts[key] = count
	}
	return counts, rows.Err()
}
