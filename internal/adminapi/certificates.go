package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"time"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	certificatestore "github.com/ultherego/flotestro/internal/certificates"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/inventory"
	certmodule "github.com/ultherego/flotestro/internal/modules/certificates"
	"github.com/ultherego/flotestro/internal/secrets"
)

// certificateView joins what the host sees with what the panel knows about
// the file.
//
// The certificate alone does not answer the operator's question. The
// question is: is what lies on the host what the panel put there, who will
// renew it and what breaks when the date passes. Only the combination of the
// host observation, the watch scope and the deployment history answers that.
type certificateView struct {
	certmodule.Certificate
	// Status is the panel's judgement, not a fact from the host.
	Status string `json:"status"`
	// DaysToExpiry may be negative: an expired certificate is to describe
	// how long ago, not flatten to "0 days".
	DaysToExpiry *int `json:"days_to_expiry,omitempty"`
	// Watched says the panel watches this file from its own configuration.
	Watched bool `json:"watched"`
	// Managed says this particular certificate was deployed by the panel:
	// the fingerprint from the history matches the fingerprint from the host.
	Managed bool `json:"managed"`
	// DeployedAt and DeployedBy describe the last deployment of this file
	// from the panel.
	DeployedAt *time.Time `json:"deployed_at,omitempty"`
	DeployedBy string     `json:"deployed_by,omitempty"`
	// KeySecret is the name of the secret holding the key. The name, not
	// the value.
	KeySecret   string `json:"key_secret,omitempty"`
	ReloadUnit  string `json:"reload_unit,omitempty"`
	ProbeTarget string `json:"probe_target,omitempty"`
}

// certificateReport is the answer of the host tab.
type certificateReport struct {
	HostID       string            `json:"host_id"`
	Certificates []certificateView `json:"certificates"`
	// Targets lists the panel's watch scope. A target without an
	// observation is a separate message: the panel watches a file the host
	// has not reported yet - most often because nobody ordered a scan.
	Targets []certificatestore.Target `json:"targets"`
	Status  string                    `json:"status"`
	// TrackingKnown and KeysKnown say what could not be established.
	TrackingKnown     bool              `json:"tracking_known"`
	TrackingReason    string            `json:"tracking_reason,omitempty"`
	KeysKnown         bool              `json:"keys_known"`
	Missing           map[string]string `json:"missing,omitempty"`
	ObservedAt        *time.Time        `json:"observed_at,omitempty"`
	Revision          string            `json:"revision,omitempty"`
	Stale             bool              `json:"stale"`
	UnavailableReason string            `json:"unavailable_reason,omitempty"`
}

// handleHostCertificates returns the host certificates together with the
// expiry assessment.
func (s *Server) handleHostCertificates(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	_, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	if _, ok := s.authorize(w, r, authz.PermCertificateRead, scope, "host", hostID); !ok {
		return
	}

	targets, err := s.certificates.Targets(r.Context(), hostID)
	if err != nil {
		s.fail(w, err)
		return
	}
	deployments, err := s.certificates.Latest(r.Context(), hostID)
	if err != nil {
		s.fail(w, err)
		return
	}
	fragment, err := s.inventory.Fragment(r.Context(), hostID, "certificates")
	if err != nil {
		s.fail(w, err)
		return
	}

	report := composeCertificateReport(hostID, fragment, targets, deployments, time.Now().UTC())
	writeJSON(w, http.StatusOK, report)
}

// composeCertificateReport joins the host observation with the panel's
// knowledge.
func composeCertificateReport(hostID string, fragment *inventory.Fragment,
	targets []certificatestore.Target, deployments map[string]certificatestore.Deployment,
	now time.Time) certificateReport {
	// An empty state means a host whose certificates nobody has pointed at
	// yet: the panel does not assess something it was not asked about.
	report := certificateReport{HostID: hostID, Targets: targets}
	if report.Targets == nil {
		report.Targets = []certificatestore.Target{}
	}
	report.Certificates = []certificateView{}

	watched := map[string]certificatestore.Target{}
	for _, target := range targets {
		watched[target.Path] = target
	}

	var snapshot certmodule.Snapshot
	if fragment != nil {
		report.Revision = fragment.Revision
		report.UnavailableReason = fragment.UnavailableReason
		if len(fragment.Payload) > 0 {
			_ = json.Unmarshal(fragment.Payload, &snapshot)
		}
		observation := fragment.ObservedAt.UTC()
		report.ObservedAt = &observation
		report.Stale = certificatestore.Stale(observation, now)
	} else {
		// A missing fragment is not an empty certificate list: it is a host
		// that has not been asked about them yet.
		report.Stale = true
	}

	report.TrackingKnown = snapshot.TrackingKnown
	report.TrackingReason = snapshot.TrackingReason
	report.KeysKnown = snapshot.KeysKnown
	report.Missing = snapshot.Missing

	for _, certificate := range snapshot.Certificates {
		view := certificateView{Certificate: certificate}
		view.Status = certificatestore.State(certificate.NotAfter, now)
		if certificate.UnavailableReason != "" {
			view.Status = certificatestore.StateUnknown
		}
		view.DaysToExpiry = certificate.DaysToExpiry(now)
		if target, isWatched := watched[certificate.Path]; isWatched {
			view.Watched = true
			view.KeySecret = target.KeySecret
			view.ReloadUnit = target.ReloadUnit
			view.ProbeTarget = target.ProbeTarget
			if view.OwnerService == "" {
				view.OwnerService = target.Service
			}
		}
		if deployment, deployed := deployments[certificate.Path]; deployed {
			moment := deployment.DeployedAt.UTC()
			view.DeployedAt = &moment
			view.DeployedBy = deployment.DeployedBy
			// A deployment from the panel and the file on the host are two
			// different things: a certificate swapped outside the panel has a
			// different fingerprint, while the history row stays. That is why
			// the fingerprints are compared.
			if deployment.FingerprintSHA256 == certificate.FingerprintSHA256 {
				view.Managed = true
				view.Source = certmodule.SourcePanel
			}
		}
		report.Status = certificatestore.Worse(report.Status, view.Status)
		report.Certificates = append(report.Certificates, view)
	}

	// A target the host did not report is an unknown state, not the absence
	// of a problem: the file may not exist, may be unreadable, and the scan
	// may never have run.
	observed := map[string]bool{}
	for _, certificate := range snapshot.Certificates {
		observed[certificate.Path] = true
	}
	for _, target := range targets {
		if observed[target.Path] {
			continue
		}
		report.Certificates = append(report.Certificates, certificateView{
			Certificate: certmodule.Certificate{
				Path:              target.Path,
				OwnerService:      target.Service,
				Source:            certmodule.SourceExternal,
				Renewal:           certmodule.RenewalUnknown,
				UnavailableReason: "the host has not reported this file yet; scan it",
			},
			Status: certificatestore.StateUnknown, Watched: true,
			KeySecret: target.KeySecret, ReloadUnit: target.ReloadUnit, ProbeTarget: target.ProbeTarget,
		})
		report.Status = certificatestore.Worse(report.Status, certificatestore.StateUnknown)
	}

	sort.SliceStable(report.Certificates, func(i, j int) bool {
		return report.Certificates[i].Path < report.Certificates[j].Path
	})
	return report
}

// watchRequest describes a file the panel is to watch.
type watchRequest struct {
	Path        string `json:"path"`
	KeyPath     string `json:"key_path,omitempty"`
	KeySecret   string `json:"key_secret,omitempty"`
	ReloadUnit  string `json:"reload_unit,omitempty"`
	ProbeTarget string `json:"probe_target,omitempty"`
	Service     string `json:"service,omitempty"`
	Note        string `json:"note,omitempty"`
}

// handleWatchCertificate creates or updates a watched file.
//
// This is not an operation on the host and does not go through opspec: it
// changes what the panel watches, not the machine state. The host learns
// about the change at the next scan - and only then answers what lies under
// that path.
func (s *Server) handleWatchCertificate(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	_, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	principal, ok := s.authorize(w, r, authz.PermCertificateWatch, scope, "host", hostID)
	if !ok {
		return
	}

	var request watchRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&request); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return
	}
	// The same rule that binds the host: a path outside the certificate
	// directories does not become allowed because somebody typed it here.
	if err := certmodule.ValidatePath(request.Path); err != nil {
		problem(w, http.StatusBadRequest, "invalid_path", err.Error())
		return
	}
	if request.KeyPath != "" {
		if err := certmodule.ValidatePath(request.KeyPath); err != nil {
			problem(w, http.StatusBadRequest, "invalid_key_path", err.Error())
			return
		}
	}
	if err := certmodule.ValidateUnit(request.ReloadUnit); err != nil {
		problem(w, http.StatusBadRequest, "invalid_unit", err.Error())
		return
	}
	if err := certmodule.ValidateTarget(request.ProbeTarget); err != nil {
		problem(w, http.StatusBadRequest, "invalid_probe_target", err.Error())
		return
	}
	// The secret named in the configuration must exist: otherwise the error
	// would come out only at deployment, that is at the worst moment.
	if request.KeySecret != "" {
		if s.secrets == nil {
			problem(w, http.StatusServiceUnavailable, "secrets_disabled",
				"this installation has no secret store")
			return
		}
		if _, err := s.secrets.Secret(r.Context(), request.KeySecret); errors.Is(err, secrets.ErrNotFound) {
			problem(w, http.StatusBadRequest, "secret_not_found", "no secret named "+request.KeySecret)
			return
		} else if err != nil {
			s.fail(w, err)
			return
		}
	}

	target, err := s.certificates.Set(r.Context(), certificatestore.Target{
		HostID: hostID, Path: request.Path, KeyPath: request.KeyPath,
		KeySecret: request.KeySecret, ReloadUnit: request.ReloadUnit,
		ProbeTarget: request.ProbeTarget, Service: request.Service, Note: request.Note,
		UpdatedBy: principal.Subject,
	})
	if err != nil {
		s.fail(w, err)
		return
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "certificate.watch", TargetType: "host", TargetID: hostID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"path": target.Path, "key_secret": target.KeySecret, "reload_unit": target.ReloadUnit,
		},
	})
	writeJSON(w, http.StatusOK, target)
}

// handleUnwatchCertificate stops watching a file.
func (s *Server) handleUnwatchCertificate(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	_, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	principal, ok := s.authorize(w, r, authz.PermCertificateWatch, scope, "host", hostID)
	if !ok {
		return
	}
	path := r.URL.Query().Get("path")
	if path == "" {
		problem(w, http.StatusBadRequest, "path_required", "path query parameter is required")
		return
	}
	err := s.certificates.Delete(r.Context(), hostID, path)
	if errors.Is(err, certificatestore.ErrNotFound) {
		problem(w, http.StatusNotFound, "target_not_found", "the panel does not watch that path")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "certificate.unwatch", TargetType: "host", TargetID: hostID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{"path": path},
	})
	w.WriteHeader(http.StatusNoContent)
}

// handleCertificateDeployments returns the deployment history on the host.
func (s *Server) handleCertificateDeployments(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	_, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	if _, ok := s.authorize(w, r, authz.PermCertificateRead, scope, "host", hostID); !ok {
		return
	}
	deployments, err := s.certificates.Deployments(r.Context(), hostID, r.URL.Query().Get("path"), 0)
	if err != nil {
		s.fail(w, err)
		return
	}
	if deployments == nil {
		deployments = []certificatestore.Deployment{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": deployments, "count": len(deployments)})
}

// FleetCertificateLimit bounds the list on the fleet screen. The counts are
// exact; the list is a sample, so that the screen does not become an
// inventory printout.
const FleetCertificateLimit = 100

// fleetCertificate describes one certificate at fleet scale.
type fleetCertificate struct {
	HostID       string     `json:"host_id"`
	Hostname     string     `json:"hostname"`
	Path         string     `json:"path"`
	Subject      string     `json:"subject,omitempty"`
	Issuer       string     `json:"issuer,omitempty"`
	NotAfter     *time.Time `json:"not_after,omitempty"`
	DaysToExpiry *int       `json:"days_to_expiry,omitempty"`
	Status       string     `json:"status"`
	Renewal      string     `json:"renewal"`
	Service      string     `json:"owner_service,omitempty"`
	Reason       string     `json:"unavailable_reason,omitempty"`
}

// handleFleetCertificates returns the certificate expiries of the whole
// visible fleet.
//
// This is the basic mode of this module. A certificate expires quietly and
// always at the worst moment; the only defence is a list on which all the
// dates stand side by side, sorted from the nearest.
func (s *Server) handleFleetCertificates(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermCertificateRead, "fleet")
	if !ok {
		return
	}
	list, err := s.hosts.List(r.Context(), hosts.ListFilter{Limit: 500})
	if err != nil {
		s.fail(w, err)
		return
	}
	visible := make([]hosts.Host, 0, len(list))
	ids := make([]string, 0, len(list))
	for _, host := range list {
		if principal.Can(authz.PermCertificateRead, authz.Scope{Site: host.Site, Environment: host.Environment}) {
			visible = append(visible, host)
			ids = append(ids, host.ID)
		}
	}
	fragments, err := s.inventory.HostFragments(r.Context(), ids)
	if err != nil {
		s.fail(w, err)
		return
	}

	now := time.Now().UTC()
	items := make([]fleetCertificate, 0, len(visible))
	counts := map[string]int{}
	withoutObservation := 0

	for _, host := range visible {
		fragment := moduleFragment(fragments[host.ID], "certificates")
		if fragment == nil {
			withoutObservation++
			continue
		}
		var snapshot certmodule.Snapshot
		if len(fragment.Payload) > 0 {
			_ = json.Unmarshal(fragment.Payload, &snapshot)
		}
		if len(snapshot.Certificates) == 0 {
			withoutObservation++
			continue
		}
		for _, certificate := range snapshot.Certificates {
			state := certificatestore.State(certificate.NotAfter, now)
			if certificate.UnavailableReason != "" {
				state = certificatestore.StateUnknown
			}
			counts[state]++
			item := fleetCertificate{
				HostID: host.ID, Hostname: host.Hostname, Path: certificate.Path,
				Subject: certificate.Subject, Issuer: certificate.Issuer,
				DaysToExpiry: certificate.DaysToExpiry(now), Status: state,
				Renewal: certificate.Renewal, Service: certificate.OwnerService,
				Reason: certificate.UnavailableReason,
			}
			item.NotAfter = certificate.NotAfter
			items = append(items, item)
		}
	}

	// Sorted from the nearest date; a certificate without a date goes last,
	// because its problem is different: it is unknown what lies there.
	sort.SliceStable(items, func(i, j int) bool {
		if (items[i].NotAfter == nil) != (items[j].NotAfter == nil) {
			return items[j].NotAfter == nil
		}
		if items[i].NotAfter == nil {
			return items[i].Hostname < items[j].Hostname
		}
		return items[i].NotAfter.Before(*items[j].NotAfter)
	})
	// The expiry timeline is computed before truncating the list: the
	// truncation concerns what is shown, not what the fleet really has.
	all := items
	truncated := false
	if len(items) > FleetCertificateLimit {
		items = items[:FleetCertificateLimit]
		truncated = true
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"items": items, "counts": counts, "truncated": truncated,
		"timeline":    expiryTimeline(all),
		"hosts_total": len(visible), "hosts_without_certificates": withoutObservation,
		"thresholds": map[string]int{
			"critical_days": int(certificatestore.CriticalThreshold.Hours() / 24),
			"warning_days":  int(certificatestore.WarningThreshold.Hours() / 24),
		},
	})
}

// moduleFragment picks the fragment of one module from the host's fragment
// list.
func moduleFragment(fragments []inventory.Fragment, module string) *inventory.Fragment {
	for i := range fragments {
		if fragments[i].Module == module {
			return &fragments[i]
		}
	}
	return nil
}

// fleetAnchor describes one authority seen from the whole fleet.
type fleetAnchor struct {
	FingerprintSHA256 string     `json:"fingerprint_sha256,omitempty"`
	Subject           string     `json:"subject,omitempty"`
	AnchorID          string     `json:"anchor_id,omitempty"`
	Managed           bool       `json:"managed"`
	NotAfter          *time.Time `json:"not_after,omitempty"`
	Hosts             int        `json:"hosts"`
	Sample            []string   `json:"sample,omitempty"`
	// Reason carries why the anchor could not be described.
	Reason string `json:"unavailable_reason,omitempty"`
}

// handleFleetTrust shows which authority which host trusts.
//
// This is the rotation screen: during a rotation part of the fleet trusts
// both authorities at once, and only this view says whether the old one can
// be withdrawn yet. Without it the operator would infer that from campaigns
// that finished a week ago.
func (s *Server) handleFleetTrust(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermCertificateRead, "fleet")
	if !ok {
		return
	}
	list, err := s.hosts.List(r.Context(), hosts.ListFilter{Limit: 500})
	if err != nil {
		s.fail(w, err)
		return
	}
	visible := make([]hosts.Host, 0, len(list))
	ids := make([]string, 0, len(list))
	for _, host := range list {
		if principal.Can(authz.PermCertificateRead, authz.Scope{Site: host.Site, Environment: host.Environment}) {
			visible = append(visible, host)
			ids = append(ids, host.ID)
		}
	}
	fragments, err := s.inventory.HostFragments(r.Context(), ids)
	if err != nil {
		s.fail(w, err)
		return
	}

	order := []string{}
	byKey := map[string]*fleetAnchor{}
	withoutStore := map[string]int{}
	unknown := 0

	for _, host := range visible {
		fragment := moduleFragment(fragments[host.ID], "certificates")
		if fragment == nil || len(fragment.Payload) == 0 {
			unknown++
			continue
		}
		var snapshot certmodule.Snapshot
		if err := json.Unmarshal(fragment.Payload, &snapshot); err != nil || snapshot.Trust == nil {
			// A host that has not reported its store yet is not a host without
			// trust: it is missing knowledge and is to be counted as such.
			unknown++
			continue
		}
		if snapshot.Trust.UnavailableReason != "" {
			withoutStore[snapshot.Trust.UnavailableReason]++
			continue
		}
		for _, anchor := range snapshot.Trust.Anchors {
			// The store has hundreds of distribution authorities; the panel
			// shows the ones it installed itself. The rest is the content of
			// the host image, not of the fleet.
			if !anchor.Managed {
				continue
			}
			key := anchor.FingerprintSHA256
			if key == "" {
				key = anchor.Path + ":" + anchor.UnavailableReason
			}
			entry, present := byKey[key]
			if !present {
				entry = &fleetAnchor{
					FingerprintSHA256: anchor.FingerprintSHA256,
					Subject:           anchor.Subject,
					AnchorID:          anchor.ID,
					Managed:           anchor.Managed,
					NotAfter:          anchor.NotAfter,
					Reason:            anchor.UnavailableReason,
				}
				byKey[key] = entry
				order = append(order, key)
			}
			entry.Hosts++
			if len(entry.Sample) < 12 {
				entry.Sample = append(entry.Sample, host.Hostname)
			}
		}
	}

	anchors := make([]fleetAnchor, 0, len(order))
	for _, key := range order {
		anchors = append(anchors, *byKey[key])
	}
	// Those trusted by the most hosts first: during a rotation they are the
	// ones that say how far it has got.
	sort.SliceStable(anchors, func(i, j int) bool { return anchors[i].Hosts > anchors[j].Hosts })

	reasons := make([]hostGroup, 0, len(withoutStore))
	for reason, count := range withoutStore {
		reasons = append(reasons, hostGroup{Reason: reason, Count: count})
	}
	sort.SliceStable(reasons, func(i, j int) bool { return reasons[i].Reason < reasons[j].Reason })

	writeJSON(w, http.StatusOK, map[string]any{
		"items": anchors, "hosts_total": len(visible),
		"hosts_without_trust_store": reasons,
		"hosts_unknown":             unknown,
	})
}

// expiryTimeline groups the fleet certificates by the time they have left.
//
// A list sorted by date answers the question "what is on fire now". It does
// not answer "when is the next wave" - and that is what decides whether the
// rotation has to be planned for this week or for the quarter.
func expiryTimeline(items []fleetCertificate) []hostGroup {
	buckets := []struct {
		name string
		days int
	}{
		{"expired", 0}, {"7 days", 7}, {"30 days", 30}, {"90 days", 90}, {"later", -1},
	}
	counts := make([]int, len(buckets))
	unknown := 0

	for _, item := range items {
		if item.DaysToExpiry == nil {
			// A certificate without a date is not a certificate valid for
			// long: it is missing knowledge and is to stand apart.
			unknown++
			continue
		}
		days := *item.DaysToExpiry
		placed := false
		for i, bucket := range buckets {
			if bucket.days < 0 {
				continue
			}
			if (bucket.days == 0 && days < 0) || (bucket.days > 0 && days >= 0 && days <= bucket.days) {
				counts[i]++
				placed = true
				break
			}
		}
		if !placed {
			counts[len(buckets)-1]++
		}
	}

	groups := make([]hostGroup, 0, len(buckets)+1)
	for i, bucket := range buckets {
		groups = append(groups, hostGroup{Reason: bucket.name, Count: counts[i]})
	}
	groups = append(groups, hostGroup{Reason: "no expiry", Count: unknown})
	return groups
}
