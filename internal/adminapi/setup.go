package adminapi

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/freeipa"
	"github.com/ultherego/flotestro/internal/oidc"
)

// The first run.

// The states of a step. The pair that carries the weight is optional against
// warning: an integration nobody configured is optional and is left out of the
// count entirely, because a panel with no identity provider and no directory is
// a supported installation and not an unfinished one; an integration that is
// configured and does not answer is a warning, which is counted and says what
// went wrong. Undone stays for what the installation itself still has to do.
const (
	setupDone     = "done"
	setupUndone   = "undone"
	setupWarning  = "warning"
	setupOptional = "optional"
)

// setupStep is one row of the checklist: its state, a sentence on what
// was found, and the page where it is dealt with.
type setupStep struct {
	Key    string `json:"key"`
	State  string `json:"state"`
	Detail string `json:"detail"`
	Path   string `json:"path"`
}

// setupChecklist is the answer: the steps in the order they are taken,
// counted, with the key of the first that still needs doing.
type setupChecklist struct {
	Steps []setupStep `json:"steps"`
	Done  int         `json:"done"`
	Total int         `json:"total"`
	// Complete says whether nothing required is left; the warnings and
	// the optional steps do not hold it back.
	Complete bool `json:"complete"`
	// Next is the first step that is undone, or empty when none is.
	Next string `json:"next,omitempty"`
	// BootstrapLive says whether the bootstrap token still opens the
	// panel; the login screen and the dashboard card read it to say so.
	BootstrapLive bool `json:"bootstrap_live"`
}

// setupProbeMaxAge is how long the checklist trusts the last answer of
// the identity provider before asking again.
const setupProbeMaxAge = time.Minute

// setupCAWarningDays is the margin before the fleet CA's end at which the
// checklist starts to warn: a rotation needs every agent to renew once under
// the new CA, and agent certificates live thirty days.
const setupCAWarningDays = 30

// bootstrapRecentUse is the window in which a use of the bootstrap token
// counts as current.
const bootstrapRecentUse = 24 * time.Hour

// handleSetup returns the checklist.
func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	principal := authz.FromContext(r.Context())
	if !principal.Authenticated() {
		w.Header().Set("WWW-Authenticate", `Bearer realm="flotestro"`)
		problem(w, http.StatusUnauthorized, "unauthenticated", "no valid token")
		return
	}
	checklist, err := s.setupChecklist(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, checklist)
}

// setupChecklist gathers the steps.
func (s *Server) setupChecklist(ctx context.Context) (setupChecklist, error) {
	var steps []setupStep

	// Whether an identity provider is configured at all decides how three of the
	// steps below read, so it is settled once here rather than guessed at each.
	providerConfigured := s.oidc != nil

	steps = append(steps, s.identityProviderStep(ctx))

	mappings, err := s.countRows(ctx, `select count(*) from group_role_mappings`)
	if err != nil {
		return setupChecklist{}, err
	}
	steps = append(steps, groupMappingStep(mappings, providerConfigured))

	bootstrap, live, err := s.bootstrapStep(ctx, mappings > 0, providerConfigured)
	if err != nil {
		return setupChecklist{}, err
	}
	steps = append(steps, bootstrap)

	steps = append(steps, s.directoryStep())

	steps = append(steps, s.advertisedAddressStep())

	hosts, err := s.countRows(ctx, `select count(*) from hosts where lifecycle_state <> 'retired'`)
	if err != nil {
		return setupChecklist{}, err
	}
	if hosts > 0 {
		steps = append(steps, setupStep{Key: "hosts", State: setupDone, Path: "/hosts",
			Detail: fmt.Sprintf("%d %s enrolled", hosts, plural(hosts, "host", "hosts"))})
	} else {
		steps = append(steps, setupStep{Key: "hosts", State: setupUndone, Path: "/hosts/new",
			Detail: "no host is enrolled yet; the add-host screen prints the one-line installation"})
	}

	relays, err := s.countRows(ctx, `select count(*) from relays where revoked_at is null`)
	if err != nil {
		return setupChecklist{}, err
	}
	if relays > 0 {
		steps = append(steps, setupStep{Key: "relay", State: setupDone, Path: "/relays",
			Detail: fmt.Sprintf("%d %s the sites that do not reach the panel directly", relays, plural(relays, "relay serves", "relays serve"))})
	} else {
		steps = append(steps, setupStep{Key: "relay", State: setupOptional, Path: "/relays",
			Detail: "no relay; needed only for a site whose hosts cannot reach the panel directly"})
	}

	policies, err := s.countRows(ctx, `select count(*) from policies`)
	if err != nil {
		return setupChecklist{}, err
	}
	if policies > 0 {
		steps = append(steps, setupStep{Key: "policy", State: setupDone, Path: "/policies",
			Detail: fmt.Sprintf("%d %s declare what is to be true on the hosts", policies, plural(policies, "policy", "policies"))})
	} else {
		steps = append(steps, setupStep{Key: "policy", State: setupUndone, Path: "/policies",
			Detail: "no policy: the panel reports the hosts as they are and judges nothing"})
	}

	steps = append(steps, s.alertRuleStep(ctx))
	steps = append(steps, s.notificationStep(ctx))
	steps = append(steps, s.fleetCAStep())

	checklist := tally(steps)
	checklist.BootstrapLive = live
	return checklist, nil
}

// tally counts the steps. An optional step is not counted at all - neither into
// the total nor against it - which is what makes an integration the installation
// deliberately has none of cost the operator nothing: the count reads "n of n"
// and the checklist is complete. A warning is counted but leads nowhere, so a
// configured integration that has stopped answering is visible without becoming
// a step somebody has to finish before the fleet can be run.
func tally(steps []setupStep) setupChecklist {
	checklist := setupChecklist{Steps: steps}
	for _, step := range steps {
		if step.State == setupOptional {
			continue
		}
		checklist.Total++
		switch step.State {
		case setupDone:
			checklist.Done++
		case setupUndone:
			if checklist.Next == "" {
				checklist.Next = step.Key
			}
		}
	}
	checklist.Complete = checklist.Next == ""
	return checklist
}

// advertisedAddressStep judges the address the agents are told to dial. It comes
// before the first host because no host can be enrolled until it is settled: the
// enrolment door refuses a host elsewhere while the panel is reachable only from
// the machine it runs on, and the certificate would not match the name anyway.
func (s *Server) advertisedAddressStep() setupStep {
	if s.advertised == nil {
		return setupStep{Key: "advertised_address", State: setupWarning, Path: "/setup",
			Detail: "this panel was started without the advertised-address setting; " +
				"the address it is seen under is whatever its environment names"}
	}
	state := s.advertised.State()
	names := strings.Join(state.InForce, ", ")
	switch {
	case state.Mismatch != "":
		return setupStep{Key: "advertised_address", State: setupWarning, Path: "/setup",
			Detail: state.Mismatch}
	case state.LoopbackOnly:
		return setupStep{Key: "advertised_address", State: setupUndone, Path: "/setup",
			Detail: "the panel tells the agents to dial " + names + ", which reaches only the " +
				"machine it runs on, so no host elsewhere can enrol"}
	case state.Source == "environment":
		return setupStep{Key: "advertised_address", State: setupDone, Path: "/settings",
			Detail: "the deployment declares " + names + " in the environment of the control plane"}
	default:
		return setupStep{Key: "advertised_address", State: setupDone, Path: "/setup",
			Detail: "the agents dial " + names + ", confirmed by " + state.ConfirmedBy}
	}
}

// plural picks the noun for a count; the detail is a sentence, and "1
// hosts" reads as a defect.
func plural(count int, one, many string) string {
	if count == 1 {
		return one
	}
	return many
}

func (s *Server) countRows(ctx context.Context, query string) (int, error) {
	var count int
	err := s.pool.QueryRow(ctx, query).Scan(&count)
	return count, err
}

// identityProviderStep asks the provider, through the cache, whether it still
// answers. An installation that named none is not behind on this step: it is an
// installation that signs its operators in with API tokens, which is a shape the
// panel supports. One that named a provider and cannot reach it is a fault, and
// the difference between the two is the whole point of the two states.
func (s *Server) identityProviderStep(ctx context.Context) setupStep {
	if s.oidc == nil {
		return setupStep{Key: "identity_provider", State: setupOptional, Path: "/settings",
			Detail: "no identity provider is configured: the panel accepts API tokens alone"}
	}
	probe, err := s.oidc.ProbeCached(ctx, setupProbeMaxAge)
	if err != nil {
		return setupStep{Key: "identity_provider", State: setupWarning, Path: "/setup",
			Detail: "the identity provider is configured but did not answer: " + err.Error()}
	}
	return setupStep{Key: "identity_provider", State: setupDone, Path: "/settings",
		Detail: fmt.Sprintf("%s answers with %d signing %s", probe.Issuer, probe.Keys, plural(probe.Keys, "key", "keys"))}
}

// groupMappingStep judges the mappings that turn a group of a login token into a
// role in a scope. With no identity provider there is no login token, so there is
// nothing a mapping could be written about: an absent mapping is then the shape of
// the installation and not a step left undone. With a provider configured it is a
// real half-configuration - the panel signs people in and grants them nothing -
// and that is the case the undone state is for.
func groupMappingStep(mappings int, providerConfigured bool) setupStep {
	switch {
	case mappings > 0:
		return setupStep{Key: "group_mapping", State: setupDone, Path: "/access?tab=mappings",
			Detail: fmt.Sprintf("%d group %s decide who gets which role at login", mappings, plural(mappings, "mapping", "mappings"))}
	case !providerConfigured:
		return setupStep{Key: "group_mapping", State: setupOptional, Path: "/access?tab=mappings",
			Detail: "no identity provider signs anybody in, so no group can be mapped: the roles ride on API tokens"}
	default:
		return setupStep{Key: "group_mapping", State: setupUndone, Path: "/setup",
			Detail: "no group is mapped to a role: whoever signs in through the identity provider gets nothing"}
	}
}

// bootstrapStep judges the token the installation started with. It is done when
// the token no longer works.
//
// What has to happen before it can be revoked is that somebody else holds the
// fleet administrator role - not that a group mapping exists. An installation
// with no identity provider can never write one, and a checklist that asked for
// it would leave the only key in the fleet lying live for good, with an
// instruction its operator cannot carry out. A mapping is only the first half of
// a handover anyway: the role binding appears when somebody signs in under it, so
// what to do next is said in terms of whichever half is still missing.
func (s *Server) bootstrapStep(ctx context.Context, mappingExists, providerConfigured bool) (setupStep, bool, error) {
	live, otherAdmins, err := s.authz.BootstrapTokenState(ctx)
	if err != nil {
		return setupStep{}, false, err
	}
	if !live {
		return setupStep{Key: "bootstrap_token", State: setupDone, Path: "/access?tab=identities",
			Detail: "the bootstrap token is revoked or expired"}, false, nil
	}
	var usedRecently bool
	err = s.pool.QueryRow(ctx, `
		select exists (
			select 1 from api_tokens t
			join principals p on p.id = t.principal_id
			where p.subject = $1 and t.revoked_at is null and t.last_used_at > now() - $2::interval)
		or exists (
			select 1 from web_sessions w
			join principals p on p.id = w.principal_id
			where p.subject = $1 and w.revoked_at is null and w.last_seen_at > now() - $2::interval)`,
		authz.BootstrapSubject, fmt.Sprintf("%d seconds", int(bootstrapRecentUse.Seconds()))).Scan(&usedRecently)
	if err != nil {
		return setupStep{}, false, err
	}
	step := setupStep{Key: "bootstrap_token", Path: "/access?tab=identities"}
	switch {
	case !otherAdmins && !providerConfigured:
		step.State = setupUndone
		step.Detail = "the bootstrap token is the only fleet administrator; issue an API token of your own with the platform_admin role, sign in with it, then revoke this one"
	case !otherAdmins && !mappingExists:
		step.State = setupUndone
		step.Detail = "the bootstrap token is the only fleet administrator; create the first group mapping, sign in through the provider, then revoke it"
	case !otherAdmins:
		step.State = setupUndone
		step.Detail = "a group is mapped but nobody has signed in under it yet, so the bootstrap token is still the only fleet administrator; sign in through the provider, then revoke it"
	case usedRecently:
		step.State = setupWarning
		step.Detail = "the bootstrap token was used in the last 24 hours; whoever can sign in without it should revoke it"
	default:
		step.State = setupUndone
		step.Detail = "the bootstrap token still works and nobody uses it; revoke it in the access screen"
	}
	return step, true, nil
}

// directoryStep reads the connector's own account of itself, without a round
// trip: the checklist must come back at once even when the directory is down,
// and the test button makes the round trip on demand.
func (s *Server) directoryStep() setupStep {
	if s.directory == nil {
		return setupStep{Key: "directory", State: setupOptional, Path: "/settings",
			Detail: "no directory connector; needed for the identity views and for joining hosts to a domain"}
	}
	health := s.directory.Health()
	step := setupStep{Key: "directory", Path: "/directory"}
	switch {
	case !health.KeytabReadable:
		step.State = setupUndone
		step.Detail = "the connector's keytab was not read: " + health.KeytabDetail
	case health.LastSuccessAt == nil && health.LastErrorAt == nil:
		step.State = setupWarning
		step.Path = "/setup"
		step.Detail = "the connector has not talked to the directory yet; run the test"
	case health.LastSuccessAt == nil || (health.LastErrorAt != nil && health.LastErrorAt.After(*health.LastSuccessAt)):
		step.State = setupWarning
		step.Detail = "the last call to the directory failed: " + health.LastError
	default:
		step.State = setupDone
		step.Detail = fmt.Sprintf("%s answered at %s", health.Principal, health.LastSuccessAt.Format(time.RFC3339))
	}
	return step
}

// alertRuleStep counts the rules the built-in monitoring evaluates; an
// installation without the module has nothing to count.
func (s *Server) alertRuleStep(ctx context.Context) setupStep {
	if s.monitoring == nil {
		return setupStep{Key: "alert_rule", State: setupOptional, Path: "/monitoring",
			Detail: "the built-in monitoring is not enabled in this installation"}
	}
	rules, err := s.countRows(ctx, `select count(*) from alert_rules where enabled`)
	if err != nil {
		return setupStep{Key: "alert_rule", State: setupWarning, Path: "/monitoring",
			Detail: "the alert rules could not be counted: " + err.Error()}
	}
	if rules > 0 {
		return setupStep{Key: "alert_rule", State: setupDone, Path: "/monitoring",
			Detail: fmt.Sprintf("%d alert %s enabled", rules, plural(rules, "rule", "rules"))}
	}
	return setupStep{Key: "alert_rule", State: setupUndone, Path: "/monitoring",
		Detail: "no alert rule: the panel samples the hosts and raises nothing"}
}

// notificationStep looks for the channels table before counting it.
func (s *Server) notificationStep(ctx context.Context) setupStep {
	var present bool
	if err := s.pool.QueryRow(ctx,
		`select to_regclass('notification_channels') is not null`).Scan(&present); err != nil || !present {
		return setupStep{Key: "notification_channel", State: setupOptional, Path: "/notifications",
			Detail: "alert notifications are not part of this installation; the alerts stand in the panel"}
	}
	channels, err := s.countRows(ctx, `select count(*) from notification_channels`)
	if err != nil {
		return setupStep{Key: "notification_channel", State: setupWarning, Path: "/notifications",
			Detail: "the notification channels could not be counted: " + err.Error()}
	}
	if channels > 0 {
		return setupStep{Key: "notification_channel", State: setupDone, Path: "/notifications",
			Detail: fmt.Sprintf("%d notification %s", channels, plural(channels, "channel", "channels"))}
	}
	return setupStep{Key: "notification_channel", State: setupOptional, Path: "/notifications",
		Detail: "no notification channel: an alert is seen only by whoever opens the panel"}
}

// fleetCAStep watches the end of the signing CA.
func (s *Server) fleetCAStep() setupStep {
	if s.trust == nil {
		return setupStep{Key: "fleet_ca", State: setupOptional, Path: "/access?tab=ca",
			Detail: "the fleet CA is not managed by this panel"}
	}
	notAfter := s.trust.NotAfter()
	if notAfter.IsZero() {
		return setupStep{Key: "fleet_ca", State: setupUndone, Path: "/access?tab=ca",
			Detail: "no signing CA is active"}
	}
	left := time.Until(notAfter)
	days := int(left.Hours() / 24)
	switch {
	case left <= 0:
		return setupStep{Key: "fleet_ca", State: setupUndone, Path: "/access?tab=ca",
			Detail: "the fleet CA expired on " + notAfter.Format("2006-01-02") + "; no agent can renew"}
	case days < setupCAWarningDays:
		return setupStep{Key: "fleet_ca", State: setupWarning, Path: "/access?tab=ca",
			Detail: fmt.Sprintf("the fleet CA ends in %d %s, on %s; prepare the next one", days, plural(days, "day", "days"), notAfter.Format("2006-01-02"))}
	}
	return setupStep{Key: "fleet_ca", State: setupDone, Path: "/access?tab=ca",
		Detail: fmt.Sprintf("the fleet CA is valid for %d more days, until %s", days, notAfter.Format("2006-01-02"))}
}

// connectionTest is the answer of a test button: whether the other side
// answered, and either what it said or a typed reason why not.
type connectionTest struct {
	OK     bool   `json:"ok"`
	Reason string `json:"reason,omitempty"`
	Detail string `json:"detail,omitempty"`
	// Provider carries the discovery result of the identity provider.
	Provider *oidc.Probe `json:"provider,omitempty"`
	// Summary is the directory's own answer to the ping, and Connector the
	// connector's account of itself after it.
	Summary   string          `json:"summary,omitempty"`
	Connector *freeipa.Health `json:"connector,omitempty"`
	ElapsedMS int64           `json:"elapsed_ms"`
}

// handleTestOIDC fetches the discovery document and the signing keys now, past
// the cache.
func (s *Server) handleTestOIDC(w http.ResponseWriter, r *http.Request) {
	principal := authz.FromContext(r.Context())
	if !principal.Authenticated() || !principal.Can(authz.PermSettingsRead, authz.GlobalScope) {
		if _, ok := s.authorize(w, r, authz.PermPrincipalManage, authz.GlobalScope, "setup", "oidc"); !ok {
			return
		}
	}
	if s.oidc == nil {
		writeJSON(w, http.StatusOK, connectionTest{OK: false, Reason: "oidc_disabled",
			Detail: "no identity provider is configured in this installation"})
		return
	}
	probe, err := s.oidc.Probe(r.Context())
	if err != nil {
		reason, detail, _ := strings.Cut(err.Error(), ": ")
		writeJSON(w, http.StatusOK, connectionTest{OK: false, Reason: reason, Detail: detail})
		return
	}
	writeJSON(w, http.StatusOK, connectionTest{OK: true, Provider: &probe, ElapsedMS: probe.Elapsed.Milliseconds()})
}

// handleTestDirectory pings the directory with the connector's own identity
// and returns what the connector knows afterwards.
func (s *Server) handleTestDirectory(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, authz.PermIdentityRead, authz.GlobalScope, "setup", "directory"); !ok {
		return
	}
	if s.directory == nil {
		writeJSON(w, http.StatusOK, connectionTest{OK: false, Reason: "directory_disabled",
			Detail: "no directory connector is configured in this installation"})
		return
	}
	started := time.Now()
	summary, err := s.directory.Ping(r.Context())
	health := s.directory.Health()
	elapsed := time.Since(started).Milliseconds()
	if err != nil {
		reason := "directory_unreachable"
		if !health.KeytabReadable {
			reason = "keytab_unreadable"
		}
		writeJSON(w, http.StatusOK, connectionTest{OK: false, Reason: reason, Detail: err.Error(),
			Connector: &health, ElapsedMS: elapsed})
		return
	}
	writeJSON(w, http.StatusOK, connectionTest{OK: true, Summary: summary, Connector: &health, ElapsedMS: elapsed})
}
