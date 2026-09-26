package adminapi

import (
	"encoding/json"
	"net/http"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/backup"
	"github.com/ultherego/flotestro/internal/budgets"
	"github.com/ultherego/flotestro/internal/campaigns"
	"github.com/ultherego/flotestro/internal/certificates"
	"github.com/ultherego/flotestro/internal/compliance"
	"github.com/ultherego/flotestro/internal/files"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/jobs"
	backupmodule "github.com/ultherego/flotestro/internal/modules/backup"
	"github.com/ultherego/flotestro/internal/monitoring"
	"github.com/ultherego/flotestro/internal/notify"
	"github.com/ultherego/flotestro/internal/opspec"
	"github.com/ultherego/flotestro/internal/policy"
	"github.com/ultherego/flotestro/internal/secrets"
	"github.com/ultherego/flotestro/internal/selector"
)

// The contract of the public API.

// route registers a handler and records it for the contract.
func (s *Server) route(mux *http.ServeMux, pattern string, handler http.HandlerFunc) {
	mux.HandleFunc(pattern, handler)
	method, path, _ := strings.Cut(pattern, " ")
	s.contract = append(s.contract, apiRoute{
		Method: method, Path: path, Handler: handlerName(handler),
	})
}

type apiRoute struct {
	Method, Path, Handler string
}

// handlerName reads the name of a handler method for the summary. A
// closure has no useful name and the summary then comes from the path.
func handlerName(handler http.HandlerFunc) string {
	name := runtime.FuncForPC(reflect.ValueOf(handler).Pointer()).Name()
	name = strings.TrimSuffix(name, "-fm")
	if i := strings.LastIndex(name, ".handle"); i >= 0 {
		return name[i+len(".handle"):]
	}
	return ""
}

// handleOpenAPI serves the contract.
func (s *Server) handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.openAPI())
}

// openAPI builds the document.
func (s *Server) openAPI() map[string]any {
	schemas := map[string]any{}
	register := func(name string, value any) {
		schemas[name] = schemaOf(reflect.TypeOf(value), schemas)
	}
	register("Host", hosts.Host{})
	register("HostDetail", hostDetail{})
	register("Job", jobs.Job{})
	register("Attempt", jobs.Attempt{})
	register("Campaign", campaigns.Campaign{})
	register("CampaignTarget", campaigns.Target{})
	register("TimelineEntry", campaigns.Event{})
	register("CampaignStep", campaigns.Step{})
	register("AuditEvent", audit.Record{})
	register("Payload", opspec.Payload{})
	register("Budget", budgets.State{})
	register("BudgetHolder", budgets.Holder{})
	register("SystemHistoryEntry", hosts.SystemHistoryEntry{})
	describe(schemas, "SystemHistoryEntry", "kernel",
		"The kernel release the host reported, as /proc/sys/kernel/osrelease names it.")
	describe(schemas, "SystemHistoryEntry", "first_seen_at",
		"When the panel first saw the host on this kernel and release; last_seen_at moves with every report that names the pair. "+
			"The panel keeps the twenty most recently seen pairs per host.")
	register("Policy", policy.Policy{})
	register("PolicyRule", policy.Rule{})
	register("PolicyVersion", policy.Version{})
	register("PolicyResult", policy.Result{})
	register("PolicyOutcome", policy.Outcome{})
	describe(schemas, "Policy", "version",
		"The published version the loop judges by; zero for a draft never published. Every publication bumps it.")
	describe(schemas, "Policy", "draft",
		"True when the document differs from the published version: the loop keeps judging by the published text until the next publication.")
	describe(schemas, "Policy", "remediation_mode",
		"report writes verdicts only; campaign turns a drift set into a campaign that waits for approval; "+
			"automatic does the same and approves it with the publication, which needs policy.remediate.auto.")
	describe(schemas, "Policy", "counts",
		"The verdicts of the latest evaluation, one count per verdict: compliant, drift, error, not_applicable. All four keys are always present.")
	describe(schemas, "Policy", "selector",
		"The hosts the policy concerns, in the shape a campaign takes; the expression, when present, decides alone.")
	describe(schemas, "PolicyRule", "kind",
		"package_installed {name}, package_absent {name}, unit_state {unit, enabled?, active?}, file_content {path, sha256}, "+
			"sysctl {key, value}, ssh_key_present {user, fingerprint, public_key?}. Any other kind is refused with unsupported_rule.")
	describe(schemas, "PolicyResult", "verdict",
		"compliant, drift, error (the fact is missing, failed or older than twice the module's pace - never a pass), "+
			"or not_applicable (the host has no adapter for the rule).")
	describe(schemas, "PolicyResult", "reason",
		"One line on the verdict; an error or a drift without a fix starts with its code: fact_missing, read_failed, "+
			"inventory_stale, package_list_stale, unsupported_system, no_remediation.")
	describe(schemas, "PolicyResult", "observed_revision", "The revision of the inventory module the verdict rests on.")
	register("HostAccess", hostAccessView{})
	register("HostAction", hostAction{})
	register("HostPackageList", hostPackageList{})
	register("CampaignSchedule", campaigns.Schedule{})
	register("NotificationChannel", notify.Channel{})
	register("NotificationDelivery", notify.Delivery{})
	register("Team", hosts.Team{})
	register("Relay", relayView{})
	register("Secret", secrets.Secret{})
	register("BackupReport", backupReport{})
	register("CertificateReport", certificateReport{})
	register("VulnerabilityReport", vulnerabilityReport{})
	register("ComplianceReport", compliance.Report{})
	register("FleetActivity", FleetActivity{})
	register("ServerCapabilities", serverCapabilities{})
	register("FleetBackups", fleetBackupsView{})
	register("FleetCertificates", fleetCertificatesView{})
	register("FleetTrust", fleetTrustView{})
	register("EnrollmentRequest", orderView{})
	register("HostMetrics", hostMetricsView{})
	register("HostMonitoring", hostMonitoringView{})
	register("HostGroup", groupView{})
	register("GroupMapping", authz.GroupMapping{})
	register("BackupRun", backup.Run{})
	register("CampaignApproval", campaigns.Approval{})
	register("CertificateDeployment", certificates.Deployment{})
	register("ManagedFile", fileView{})
	register("ManagedFileVersion", files.Version{})
	register("ComposeProjectVersion", projectVersion{})
	register("ErrorGuide", opspec.ErrorGuide{})
	register("Preferences", preferences{})
	register("AlertRule", monitoring.Rule{})
	register("Silence", monitoring.Silence{})
	register("PrincipalSession", authz.SessionView{})
	register("PrincipalToken", authz.Token{})
	register("CampaignReport", campaigns.ReportView{})
	register("FleetMonitoring", fleetMonitoringView{})
	register("FleetSecurity", fleetSecurityView{})
	register("RelayBufferHistory", relayBufferHistoryView{})
	describe(schemas, "AuditEvent", "actor",
		"The actor as it was when the event was written: principal_id, subject, display_name, kind, resource_type, resource_id, resource_name, credential_id.")
	describe(schemas, "Attempt", "verification",
		"The host's reading of itself after the change: verifier (the contract's verifier - unit_state, package_versions, file_content, sysctl, reboot, ...), verified, expected, observed and reason. "+
			"Absent when the attempt reported none: a read, an operation the panel settles on the host's return, or an agent from before the verifiers - which is not the same as a change nobody confirmed.")
	describe(schemas, "NotificationDelivery", "state",
		"pending and retry_wait wait for the worker, leased is being sent now, delivered is done, dead_letter needs the operator (the credentials were refused or the attempts ran out; POST .../retry puts it back), suppressed was silenced before it was ever sent.")
	describe(schemas, "HostAction", "allowed",
		"Whether this operator may order this action on this host now. The panel hides what is not allowed; the order itself is authorised again on the server, and this answer never stands in for that.")
	describe(schemas, "HostAction", "reason_code",
		"permission_denied, capability_missing, host_quarantined, host_recovery, host_retired, read_only_host, helper_unavailable or lifecycle_state_mismatch; empty when the action is allowed.")
	describe(schemas, "HostAction", "note",
		"A fact about an allowed action: the order will wait in the queue for an offline host, or it will ask for fresh authentication. It refuses nothing.")
	describe(schemas, "HostAccess", "known",
		"Whether the directory has an entry for the host. False leaves the directory's rules undetermined, not absent; the local rules are reported either way.")
	describe(schemas, "HostAccess", "local_sudo_rules",
		"The rules of /etc/sudoers and its drop-ins as the helper parsed them, each with its file and line, whether it reaches this host, "+
			"and whether it amounts to root. Empty when the policy was not read - local_sudoers.reason says why.")
	describe(schemas, "HostAccess", "root_equivalent_warnings",
		"One sentence per local grant that makes somebody root, in the order of the rules; empty when the policy was not read.")
	// The reflection inlines the holder into the budget; the contract
	// names it once, so the sentences below land on the shape a client sees.
	schemas["Budget"].(map[string]any)["properties"].(map[string]any)["holders"] =
		map[string]any{"type": "array", "items": ref("BudgetHolder")}
	// The reflection reads the shape, not the meaning.
	describe(schemas, "Campaign", "revision",
		"Grows with every state change; a client that read the campaign at one revision and orders a transition at another is answered with 409 concurrent_transition.")
	describe(schemas, "CampaignTarget", "cancel_outcome",
		"The host's answer to the cancel of its task: not_started, interrupted, not_interruptible or already_done; empty until the host answers.")
	describe(schemas, "CampaignTarget", "cancel_phase",
		"What the host was doing when the cancel arrived, as the agent named it.")
	describe(schemas, "Job", "cancel_requested_at",
		"When a cancel was asked of the host holding the task; the job stands cancel_requested with its budget tokens until the host answers or the operation's timeout passes (cancel_ack_timeout).")
	describe(schemas, "Job", "cancel_ack_at", "When the host acknowledged the cancel.")
	describe(schemas, "Job", "cancel_outcome",
		"not_started or interrupted end the job canceled; not_interruptible lets it run to its result; already_done means the result is in the host's journal.")
	describe(schemas, "Job", "cancel_phase", "The phase the host was in when the cancel arrived.")
	describe(schemas, "CampaignTarget", "cancel_requested_at",
		"When the cancel of a target already handed to a host was asked for; the target settles once the host acknowledges or its task is taken back from the queue.")
	describe(schemas, "Campaign", "retried_by",
		"The campaigns ordered to run this one's failed hosts again, oldest first, each with its state. "+
			"Read from the retrying campaigns; the record of this one never changes when a retry is ordered.")
	describe(schemas, "Campaign", "progress",
		"The tally of the campaign's hosts, on the list only: succeeded (no_change included), failed, unknown, "+
			"skipped (skipped, canceled, ineligible, excluded) and pending (everything not settled).")
	describe(schemas, "Campaign", "compensated_by",
		"The campaigns ordered to undo this one, oldest first, each with its state. "+
			"Read from the compensating campaigns; the record of this one never changes when a rollback is ordered.")
	describe(schemas, "Campaign", "changed_hosts",
		"How many hosts the campaign changed: the target succeeded, or failed only after its change landed "+
			"(in the reboot or the verification). A host that reported no change is not counted. "+
			"These are the hosts a compensation runs on. "+
			"Zero until the campaign has settled - a compensation is refused before that.")
	// The states are the contract a client filters and colours by; the reflection
	// sees a string.
	describe(schemas, "Campaign", "state",
		"planning (every host computes its plan), planned, awaiting_approval, canary, manual_gate, running, "+
			"pausing (a pause ordered while hosts still carry their tasks; paused once they settle), paused, "+
			"canceling (a cancel with hosts still carrying their tasks; canceled once they settle), "+
			"and the terminal states: completed, completed_with_issues (finished under the threshold with hosts "+
			"failed or unknown), failed (nothing got through), plan_failed (planning left no host to run on), "+
			"expired (the plans passed their time limit before any host started), canceled.")
	describe(schemas, "CampaignTarget", "state",
		"pending, planning, awaiting_budget, queued_offline, ineligible, excluded, "+
			"dispatched (the task is handed over and the agent has not reported a start), "+
			"awaiting_lock (the agent holds the task and waits for a resource of the host; blocker names it), "+
			"running, rebooting, verifying, and the terminal states: succeeded, no_change (the host already had the "+
			"desired state; a success without a mutation), failed, unknown (the task ended without a result - the "+
			"session broke or the agent restarted mid-task; not a success, counted as a failure by the threshold, "+
			"read the host before ordering again), skipped, canceled.")
	// The budget row grew additively: a client of the first shape reads the same
	// five fields, and the new ones say who holds the tokens and who waits for
	// them, which the numbers alone never did.
	describe(schemas, "Budget", "used", "The weight of the tokens under live leases of this exact key.")
	describe(schemas, "Budget", "claimants",
		"How many campaigns and job authors hold tokens of this key or wait for them; the fair share divides the capacity between them.")
	describe(schemas, "Budget", "waiting_jobs",
		"The single-host jobs queued behind this key. A job waits on the exact key of its site; it counts under a "+
			"pattern row (site:*:packages) only when no exact row took the site out from under the pattern.")
	describe(schemas, "Budget", "waiting_targets",
		"The hosts of running campaigns standing in awaiting_budget behind this key, attributed like the waiting jobs. "+
			"A paused campaign's hosts do not count: they ask for nothing until it resumes.")
	describe(schemas, "Budget", "holders",
		"The live leases of this key, newest first, at most 50; the per-class sum counts every lease. "+
			"Attributed like the waiting jobs, so a pattern row lists the leases of the sites under its policy.")
	describe(schemas, "Budget", "by_class",
		"The weight of the tokens in use per class of work: incident, interactive, maintenance, background, "+
			"or unknown for a lease the panel cannot place.")
	describe(schemas, "BudgetHolder", "owner",
		"The work holding the tokens: job:<id> for a single-host job, the target id for a campaign host, fanout:<id> for a fan-out read.")
	describe(schemas, "BudgetHolder", "claimant",
		"The unit of fairness the lease counts under: campaign:<id>, jobs:<author> or reads:<author>.")
	describe(schemas, "BudgetHolder", "class",
		"The class the lease was taken with, read from the holder because the lease records none; "+
			"unknown when the holder is neither a job, a campaign target nor a fan-out.")
	describe(schemas, "BudgetHolder", "tokens", "The weight of the lease.")
	describe(schemas, "BudgetHolder", "since", "When the lease was first taken; renewals keep it.")
	// The fleet summary grew additively as well: the attention counters of the
	// lifecycle document are computed in the database, and a counter the server
	// cannot answer honestly for the reader's view is left out rather than sent.
	register("FleetSummary", FleetSummary{})
	describe(schemas, "FleetSummary", "relays_buffer_high",
		"Relays whose buffer of results waiting for the centre is at least 70 % full by their latest heartbeat. "+
			"Global view only; missing while no relay has reported since the panel started.")
	describe(schemas, "FleetSummary", "duplicate_identities_24h",
		"Sessions the gateway opened in the last day while the same identity was alive on a different boot "+
			"(audit action security.duplicate_identity). Missing for a reader without the fleet-wide audit right.")
	describe(schemas, "FleetSummary", "enrollment_refusals_1h",
		"Enrollments the gateway turned away in the last hour (audit actions host.enroll and relay.enroll with "+
			"the outcome denied). Missing for a reader without the fleet-wide audit right.")
	describe(schemas, "FleetSummary", "agents_unsupported",
		"Visible hosts whose reported agent version speaks a protocol this panel does not. A host that reports "+
			"no version, or a word in its place, is unknown and not counted.")
	schemas["Problem"] = map[string]any{
		"type":        "object",
		"description": "The error answer. The code is stable and meant for programs; the message is for people.",
		"properties": map[string]any{
			"code":    map[string]any{"type": "string"},
			"message": map[string]any{"type": "string"},
			"status":  map[string]any{"type": "integer"},
		},
		"required": []string{"code", "message"},
	}

	paths := map[string]map[string]any{}
	for _, route := range s.contract {
		if !strings.HasPrefix(route.Path, "/api/") && !isProbePath(route.Path) && route.Path != "/metrics" {
			// The browser login flow is not a programmable interface.
			continue
		}
		path := openAPIPath(route.Path)
		if paths[path] == nil {
			paths[path] = map[string]any{}
		}
		paths[path][strings.ToLower(route.Method)] = s.operation(route)
	}

	return map[string]any{
		"openapi": "3.1.0",
		"info": map[string]any{
			"title":   "Flotestro control plane",
			"version": "v1",
			"description": "The public API of the Flotestro Linux fleet management panel. " +
				"Reads use GET; plans, operations and campaigns are created with POST and have " +
				"explicit approve, cancel, pause and resume endpoints. Every list is paged on the " +
				"server. Errors are Problem objects with a stable code.",
		},
		"servers": []map[string]any{{"url": "/"}},
		"components": map[string]any{
			"schemas": schemas,
			"securitySchemes": map[string]any{
				"bearer":  map[string]any{"type": "http", "scheme": "bearer", "description": "An API token of a principal."},
				"session": map[string]any{"type": "apiKey", "in": "cookie", "name": "flotestro_session", "description": "The browser session after an OIDC login."},
			},
		},
		"security": []map[string]any{{"bearer": []string{}}, {"session": []string{}}},
		"paths":    paths,
	}
}

// operation describes one route: a summary from the handler name, the
// path parameters, the known response schema and the error shape.
func (s *Server) operation(route apiRoute) map[string]any {
	op := map[string]any{
		"summary":     summaryOf(route),
		"tags":        []string{tagOf(route.Path)},
		"operationId": strings.ToLower(route.Method) + strings.NewReplacer("/", "_", "{", "", "}", "", "...", "", "-", "_").Replace(route.Path),
	}
	var params []map[string]any
	if route.Method == http.MethodPost && (route.Path == "/api/v1/campaigns" || strings.HasSuffix(route.Path, "/operations")) {
		params = append(params, map[string]any{
			"name": "Idempotency-Key", "in": "header", "required": false,
			"schema":      map[string]any{"type": "string"},
			"description": "A key chosen by the caller; a repeat with the same key returns the resource already created instead of a second one.",
		})
	}
	if route.Method == http.MethodGet && csvExports[route.Path] {
		params = append(params, map[string]any{
			"name": "format", "in": "query", "required": false,
			"schema":      map[string]any{"type": "string", "enum": []string{"json", "csv"}},
			"description": "The shape of the answer: JSON by default, or with format=csv a file with one row per item, the same filters applied and no page; a file past 50000 rows ends with a row marked truncated.",
		})
	}
	for _, parameter := range queryParameters[route.Method+" "+route.Path] {
		params = append(params, map[string]any{
			"name": parameter.name, "in": "query", "required": false,
			"schema":      map[string]any{"type": parameter.kind},
			"description": parameter.description,
		})
	}
	for _, segment := range strings.Split(route.Path, "/") {
		if strings.HasPrefix(segment, "{") {
			name := strings.Trim(segment, "{}")
			name = strings.TrimSuffix(name, "...")
			params = append(params, map[string]any{
				"name": name, "in": "path", "required": true, "schema": map[string]any{"type": "string"},
			})
		}
	}
	if len(params) > 0 {
		op["parameters"] = params
	}
	responses := map[string]any{
		"default": map[string]any{
			"description": "An error with a stable code.",
			"content":     map[string]any{"application/json": map[string]any{"schema": ref("Problem")}}},
	}
	status := "200"
	if route.Method == http.MethodPost && strings.HasSuffix(route.Path, "s") {
		status = "201"
	}
	if schema, ok := responseSchemas[route.Method+" "+route.Path]; ok {
		responses[status] = map[string]any{"description": "The resource.",
			"content": map[string]any{"application/json": map[string]any{"schema": schema}}}
	} else if strings.HasSuffix(route.Path, "/config") {
		responses[status] = map[string]any{"description": "The ready configuration file of the order, without the token.",
			"content": map[string]any{"application/yaml": map[string]any{"schema": map[string]any{"type": "string"}}}}
	} else if strings.HasSuffix(route.Path, "/events") {
		responses[status] = map[string]any{"description": "A stream of server-sent events; trail events carry an id for Last-Event-ID resumption.",
			"content": map[string]any{"text/event-stream": map[string]any{"schema": map[string]any{"type": "string"}}}}
	} else if route.Path == "/metrics" {
		responses[status] = map[string]any{"description": "The Prometheus exposition.",
			"content": map[string]any{"text/plain": map[string]any{"schema": map[string]any{"type": "string"}}}}
	} else {
		responses[status] = map[string]any{"description": "The answer.",
			"content": map[string]any{"application/json": map[string]any{"schema": map[string]any{"type": "object"}}}}
	}
	if route.Method == http.MethodGet && csvExports[route.Path] {
		answer, _ := responses[status].(map[string]any)
		content, _ := answer["content"].(map[string]any)
		content["text/csv"] = map[string]any{"schema": map[string]any{"type": "string"}}
	}
	op["responses"] = responses
	if route.Method == http.MethodPost || route.Method == http.MethodPut {
		key := route.Method + " " + route.Path
		if why, bodiless := bodilessRoutes[key]; bodiless {
			// No requestBody at all, rather than an object nothing reads: a caller
			// that sends one gets the same answer as one that does not.
			said, _ := op["description"].(string)
			if said != "" {
				said += "\n\n"
			}
			op["description"] = said + "Takes no request body: " + why + "."
		} else {
			body, ok := requestSchemas[key]
			if !ok {
				// Every writing route declares its body or declares that it reads
				// none; a test refuses one that declares neither, and this is what
				// the document says until that test is seen to.
				body = map[string]any{"type": "object"}
			}
			op["requestBody"] = map[string]any{"content": map[string]any{"application/json": map[string]any{"schema": body}}}
		}
	}
	return op
}

// queryParameter is one filter or paging control of a list.
type queryParameter struct {
	name, kind, description string
}

// The paging controls every cursor-paged list shares.
var pagingParameters = []queryParameter{
	{"limit", "integer", "The page size: 100 by default, 500 at most."},
	{"cursor", "string", "The next_cursor of the previous page; empty for the first page."},
}

// The query parameters of the lists.
var campaignScheduleSchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"name":       map[string]any{"type": "string"},
		"order":      map[string]any{"type": "object", "description": "The campaign order as POST /api/v1/campaigns takes it; placed at every moment under the same checks and the author's rights, and it always waits for approval."},
		"start_at":   map[string]any{"type": "string", "description": "RFC 3339. The only moment without a recurrence; the earliest one with it."},
		"recurrence": map[string]any{"type": "string", "description": "FREQ=MONTHLY;BYMONTHDAY=n;BYHOUR=h;BYMINUTE=m or FREQ=WEEKLY;BYDAY=MO,TH;BYHOUR=h;BYMINUTE=m."},
		"timezone":   map[string]any{"type": "string", "description": "IANA zone the rule's hours are read in; UTC by default."},
		"enabled":    map[string]any{"type": "boolean"},
		"reason":     map[string]any{"type": "string", "description": "Required, min. 8 characters; carried into every order the schedule places."},
	},
	"required": []string{"name", "order", "reason"},
}

// csvExports are the lists that answer format=csv with a file: the same
// filters and scope as the JSON answer, every row the caller may see, no page.
var csvExports = map[string]bool{
	"/api/v1/hosts": true, "/api/v1/jobs": true, "/api/v1/security": true,
	"/api/v1/vulnerabilities": true, "/api/v1/certificates": true, "/api/v1/backups": true,
	"/api/v1/policies/{id}/results": true, "/api/v1/monitoring/alerts": true,
	"/api/v1/campaigns/{id}/report": true, "/api/v1/access/review": true,
	"/api/v1/reports/{name}": true, "/api/v1/notifications/deliveries": true,
}

var queryParameters = map[string][]queryParameter{
	"GET /api/v1/hosts": append([]queryParameter{
		{"q", "string", "A fragment of the hostname, the management address, the machine identifier or the owner; case-insensitive."},
		{"site", "string", ""},
		{"environment", "string", ""},
		{"os_family", "string", ""},
		{"connection_state", "string", "online, offline, stale or unknown."},
		{"lifecycle_state", "string", "active, quarantined, recovery, retiring or retired."},
		{"owner", "string", ""},
		{"identity_domain", "string", "The directory domain the host is joined to, as its identity module reports it."},
		{"tag", "string", "A tag the host must carry; may repeat, and every listed tag has to be on the host."},
		{"channel", "string", "The release channel the host follows: stable or beta."},
		{"maintenance", "boolean", "true keeps the hosts inside a maintenance window now, false those outside one."},
		{"reboot_required", "boolean", "true keeps the hosts that need a reboot, false the ones that reported none; a host that has not reported is in neither."},
		{"security_updates", "boolean", "true keeps the hosts with a security update waiting, false the ones that reported none; an unknown count is in neither."},
		{"failed_units", "boolean", "true keeps the hosts with at least one failed unit, false the ones that reported none; a host that has not reported is in neither."},
		{"package_db_broken", "boolean", "true keeps the hosts (not retired) whose package database the last operation found broken, false the sound ones."},
		{"sssd_offline", "boolean", "true keeps the domain-joined hosts (not retired) whose SSSD reports itself offline, false those online; a host outside a domain is in neither."},
		{"agent_behind", "boolean", "true keeps the hosts whose agent is older than the newest version reported in the visible fleet, false those on it; a version that does not parse is in neither."},
		{"relay", "string", "The identifier of a relay; keeps the hosts whose open session it attested."},
		{"failure_domain", "string", "The failure domain an operator placed the host in."},
		{"team", "string", "The identifier of a team; keeps its hosts. The word none keeps the hosts nobody has placed in a team."},
		{"capability", "string", "An adapter the host must have available, such as packages.apt."},
		{"connection_refusal", "string", "The reason the gateway last turned the host away since its last session: certificate_expired, certificate_not_yet_valid, unknown_certificate, revoked_certificate, identity_mismatch or lifecycle_<state>."},
		{"sort", "string", "The order of the list as column or column:desc; the columns are " + strings.Join(hosts.SortColumns(), ", ") + ". The hostname ascending by default; an unknown column is refused with invalid_sort, and a cursor issued under one order is refused under another. A count the host has not reported sorts below zero, a host never seen before every host seen."},
	}, pagingParameters...),
	"GET /api/v1/jobs": append([]queryParameter{
		{"host_id", "string", "The host the tasks belong to."},
		{"hostname", "string", "The beginning of a host name; a full name keeps that host alone."},
		{"state", "string", ""},
		{"action", "string", "The operation type."},
		{"action_prefix", "string", "The beginning of an operation type; packages. keeps every package operation."},
		{"actor", "string", "The identity that ordered the task."},
		{"campaign_id", "string", ""},
		{"fanout_id", "string", "The read fan-out that ordered the tasks."},
		{"error_code", "string", "The result error code the task ended with."},
		{"since", "string", "RFC 3339; tasks created at or after this moment."},
		{"until", "string", "RFC 3339; tasks created before this moment."},
		{"sort", "string", "The order of the list as column, column:asc or column:desc; the columns are " + strings.Join(jobs.SortColumns(), ", ") + ". Newest first by default; an unknown column is refused with invalid_sort, and a cursor issued under one order is refused under another. A task not finished yet sorts before every finished one under finished_at."},
	}, pagingParameters...),
	"GET /api/v1/installation-profiles": {
		{"site", "string", "The site the host will live in; \"default\" when empty."},
		{"environment", "string", "The environment of the host; \"unassigned\" when empty."},
		{"kind", "string", "agent (default) or relay."},
		{"relay_id", "string", "The relay of the site the host connects through; empty means directly to the panel."},
		{"architecture", "string", "amd64 (default) or arm64."},
		{"channel", "string", "The repository channel; stable by default."},
	},
	"GET /api/v1/relays": {
		{"site", "string", "Only the relays of this site."},
	},
	"GET /api/v1/hosts/{id}/metrics": {
		{"range", "string", "The chart window: 3h (default), 24h, 7d or 30d; the first two answer with raw samples, the others with quarter-hour rollups."},
	},
	"GET /api/v1/vulnerabilities": {
		{"q", "string", "A fragment of the hostname; the summary numbers stay fleet-wide."},
		{"severity", "string", "critical, high, medium, low, negligible or unrated: hosts with an affected finding of that rung."},
		{"sort", "string", "affected (default), fixable or hostname."},
		{"limit", "integer", "The page size: 100 by default, 500 at most."},
		{"cursor", "string", "The next_cursor of the previous page; empty for the first page. A cursor issued under one order is refused under another."},
		{"offset", "integer", "Rows to skip; the cursor wins when both are given."},
	},
	// The fleet views count over every host in scope and hand the detail out a
	// page at a time, so each of them takes the paging controls besides its own
	// filters.
	"GET /api/v1/security": {
		{"check", "string", "The identifier of one check; the answer is then one page of the hosts failing it rather than the whole profile."},
		{"limit", "integer", "The page size of the host list of a check: 100 by default, 500 at most."},
		{"cursor", "string", "The next_cursor of the previous page; empty for the first page."},
	},
	"GET /api/v1/backups": {
		{"limit", "integer", "The page size: 100 by default, 500 at most."},
		{"cursor", "string", "The next_cursor of the previous page; empty for the first page. The moment the ages were judged at travels in it, so every page of one reading judges by the same clock."},
	},
	"GET /api/v1/certificates": {
		{"limit", "integer", "The page size: 100 by default, 500 at most."},
		{"cursor", "string", "The next_cursor of the previous page; empty for the first page."},
	},
	"GET /api/v1/vulnerabilities/cves": {
		{"q", "string", "A prefix of a CVE number or of an affected package name."},
		{"severity", "string", "critical, high, medium, low, negligible or unrated."},
		{"fixable", "boolean", "true keeps the CVEs with a vendor fix on at least one host."},
		{"limit", "integer", "The page size: 50 by default, 500 at most."},
		{"offset", "integer", "Rows to skip."},
	},
	"GET /api/v1/maintenance/calendar": {
		{"from", "string", "RFC 3339; the start of the range."},
		{"to", "string", "RFC 3339; the end of the range, a year after from at most."},
	},
	"GET /api/v1/reports/{name}": {
		{"from", "string", "RFC 3339; the start of the period. Both bounds or neither: without them the last thirty days."},
		{"to", "string", "RFC 3339; the end of the period, a year after from at most."},
		{"site", "string", "Narrows the report to one site."},
		{"environment", "string", "Narrows the report to one environment."},
		{"limit", "integer", "patch-status only: the page of host rows, 1000 by default and 5000 at most; next_cursor pages on, and the file carries them all."},
		{"cursor", "string", "patch-status only: the next page of host rows, as next_cursor gives it."},
		{"section", "string", "compliance with format=csv: policies (default), hosts or security."},
	},
	"GET /api/v1/notifications/deliveries": {
		{"channel_id", "string", "One channel's deliveries."},
		{"status", "string", "sent or failed, the words of the previous release."},
		{"state", "string", "pending, leased, delivered, retry_wait, dead_letter or suppressed."},
		{"since", "string", "RFC 3339; deliveries at or after this moment."},
		{"limit", "integer", "100 by default, 500 at most."},
	},
	"GET /api/v1/reads": pagingParameters,
	"GET /api/v1/search": {
		{"q", "string", "The beginning of a name: a hostname, machine identifier or management address, a campaign, policy, group, relay or secret name, an identity's subject or display name, at least eight characters of a job identifier, or a CVE identifier in full. Fewer than two characters answer with nothing; a kind the caller may not read is left out."},
		{"limit", "integer", "The hits per kind: 8 by default, 25 at most."},
	},
	"GET /api/v1/relays/{id}/buffer-history": {
		{"range", "string", "The chart window: 3h, 24h (the default), 7d, 30d or 90d; the first two answer with the raw reports, the others with the quarter-hour rollups."},
	},
	"GET /api/v1/host-groups/preview": {
		{"expression", "string", "The typed selector as JSON; the answer is the count within the caller's scope, a sample of up to 20 hostnames and the selector in one line."},
	},
	"GET /api/v1/campaigns/preview": {
		{"action", "string", "The operation type; without it the preview counts hosts and qualifies none. " +
			"For an operation the panel splits host by host (system.hostname.set) the answer also lists every ready host under hosts [{id, hostname}], for the mapping to name."},
		{"site", "string", ""},
		{"environment", "string", ""},
		{"os_family", "string", ""},
		{"expression", "string", "The typed selector as JSON; when present it decides alone."},
		{"exclude", "string", "A host identifier to leave out; may repeat."},
		{"exclude_reason", "string", ""},
		{"compensates", "string", "The campaign the order would undo; an empty selector then names the hosts that campaign changed, and the answer carries the original under compensates."},
		{"host_id", "string", "A host identifier to preview as an explicit list; may repeat. The list is strict: an unknown host, one outside the caller's scope for the operation, or one also excluded answers 422 targets_invalid with the reason per host."},
	},
	"GET /api/v1/enrollment-requests": {
		{"status", "string", "pending, enrolled, expired, revoked or failed."},
		{"kind", "string", "agent or relay."},
		{"site", "string", ""},
		{"environment", "string", ""},
		{"limit", "integer", "The page size: 200 by default, 500 at most."},
		{"cursor", "string", "The next_cursor of the previous page; empty for the first page."},
	},
	"GET /api/v1/policies/{id}/results": {
		{"host_id", "string", "Only the verdicts of this host."},
		{"verdict", "string", "compliant, drift, error or not_applicable."},
		{"limit", "integer", "The page size: 100 by default, 500 at most."},
		{"cursor", "string", "The next_cursor of the previous page; empty for the first page."},
	},
	"GET /api/v1/campaigns/{id}/steps": {
		{"host_id", "string", "Only the steps of this host."},
		{"limit", "integer", "How many hosts one page covers: 200 by default, 1000 at most; a page is cut between hosts, never inside one."},
		{"cursor", "string", "The next_cursor of the previous page; empty for the first page."},
	},
	"GET /api/v1/identity/users": {
		{"preserved", "string", "\"true\" lists the accounts removed with their entry kept, apart from the live ones; a preserved account reaches no host and belongs to no group."},
	},
	"GET /api/v1/identity/changes": {
		{"state", "string", "planned, awaiting_approval, running, succeeded, partially_applied, failed or canceled."},
		{"limit", "integer", "The most changes to return: 50 by default, 200 at most."},
	},
	"GET /api/v1/monitoring/alerts": append([]queryParameter{
		{"state", "string", "pending, firing or resolved."},
		{"acknowledged", "string", "true keeps the alerts somebody took, false the ones still waiting."},
		{"severity", "string", "critical, warning or info."},
		{"host_id", "string", ""},
	}, pagingParameters...),
	"GET /api/v1/hosts/{id}/audit": append([]queryParameter{
		{"actor", "string", "The identity that acted."},
		{"actor_kind", "string", "user, service, anonymous, agent, relay, machine or system."},
		{"actor_principal_id", "string", "The immutable identifier of the identity that acted."},
		{"actor_resource_id", "string", "The host, relay or campaign that acted."},
		{"action", "string", ""},
		{"action_prefix", "string", "The beginning of an action; job. keeps every event about a job."},
		{"outcome", "string", "success, failure or denied."},
		{"since", "string", "RFC 3339; events at or after this moment."},
		{"until", "string", "RFC 3339; events before this moment."},
	}, pagingParameters...),
	"GET /api/v1/audit": append([]queryParameter{
		{"target_id", "string", ""},
		{"target_type", "string", ""},
		{"actor", "string", "The identity that acted."},
		{"actor_kind", "string", "user, service, anonymous, agent, relay, machine or system."},
		{"actor_principal_id", "string", "The immutable identifier of the identity that acted."},
		{"actor_resource_id", "string", "The host, relay or campaign that acted."},
		{"action", "string", ""},
		{"action_prefix", "string", "The beginning of an action; job. keeps every event about a job."},
		{"outcome", "string", "success, failure or denied."},
		{"since", "string", "RFC 3339; events at or after this moment."},
		{"until", "string", "RFC 3339; events before this moment."},
	}, pagingParameters...),
}

// describe adds the sentence of one property to a schema already reflected.
func describe(schemas map[string]any, schema, property, description string) {
	properties := schemas[schema].(map[string]any)["properties"].(map[string]any)
	field, ok := properties[property].(map[string]any)
	if !ok {
		panic("openapi: " + schema + " has no property " + property)
	}
	field["description"] = description
}

func ref(name string) map[string]any {
	return map[string]any{"$ref": "#/components/schemas/" + name}
}

func collection(name string) map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"items": map[string]any{"type": "array", "items": ref(name)},
			"count": map[string]any{"type": "integer"},
		},
	}
}

// The endpoints whose answers are known resources. The rest answer with
// module-specific views described by their handlers.
var responseSchemas = map[string]map[string]any{
	"GET /api/v1/monitoring/rules":                      collection("AlertRule"),
	"GET /api/v1/monitoring/rules/{id}":                 ref("AlertRule"),
	"GET /api/v1/monitoring/silences":                   collection("Silence"),
	"GET /api/v1/monitoring":                            ref("FleetMonitoring"),
	"GET /api/v1/security":                              ref("FleetSecurity"),
	"GET /api/v1/relays/{id}/buffer-history":            ref("RelayBufferHistory"),
	"GET /api/v1/me/sessions":                           collection("PrincipalSession"),
	"GET /api/v1/principals/{id}/sessions":              collection("PrincipalSession"),
	"GET /api/v1/me/tokens":                             collection("PrincipalToken"),
	"GET /api/v1/campaigns/{id}/report":                 ref("CampaignReport"),
	"GET /api/v1/me/preferences":                        ref("Preferences"),
	"GET /api/v1/host-groups":                           collection("HostGroup"),
	"GET /api/v1/group-mappings":                        collection("GroupMapping"),
	"GET /api/v1/hosts/{id}/backups/runs":               collection("BackupRun"),
	"GET /api/v1/campaigns/{id}/approvals":              collection("CampaignApproval"),
	"GET /api/v1/hosts/{id}/certificates/deployments":   collection("CertificateDeployment"),
	"GET /api/v1/hosts/{id}/files":                      collection("ManagedFile"),
	"GET /api/v1/hosts/{id}/files/history":              collection("ManagedFileVersion"),
	"GET /api/v1/hosts/{id}/compose/{project}/versions": collection("ComposeProjectVersion"),
	"GET /api/v1/errors":                                collection("ErrorGuide"),
	"GET /api/v1/hosts/{id}/backups":                    ref("BackupReport"),
	"GET /api/v1/hosts/{id}/certificates":               ref("CertificateReport"),
	"GET /api/v1/hosts/{id}/vulnerabilities":            ref("VulnerabilityReport"),
	"GET /api/v1/hosts/{id}/security":                   ref("ComplianceReport"),
	"GET /api/v1/hosts/{id}/metrics":                    ref("HostMetrics"),
	"GET /api/v1/hosts/{id}/monitoring":                 ref("HostMonitoring"),
	"GET /api/v1/fleet/activity":                        ref("FleetActivity"),
	"GET /api/v1/capabilities":                          ref("ServerCapabilities"),
	"GET /api/v1/backups":                               ref("FleetBackups"),
	"GET /api/v1/certificates":                          ref("FleetCertificates"),
	"GET /api/v1/certificates/trust":                    ref("FleetTrust"),
	"GET /api/v1/enrollment-requests/{id}":              ref("EnrollmentRequest"),
	"GET /api/v1/host-groups/{id}":                      ref("HostGroup"),
	"GET /api/v1/notifications/channels":                collection("NotificationChannel"),
	"POST /api/v1/notifications/channels":               ref("NotificationChannel"),
	"GET /api/v1/notifications/channels/{id}":           ref("NotificationChannel"),
	"PUT /api/v1/notifications/channels/{id}":           ref("NotificationChannel"),
	"POST /api/v1/notifications/channels/{id}/test":     ref("NotificationDelivery"),
	"GET /api/v1/notifications/deliveries":              collection("NotificationDelivery"),
	"GET /api/v1/teams":                                 collection("Team"),
	"POST /api/v1/teams":                                ref("Team"),
	"GET /api/v1/teams/{id}":                            ref("Team"),
	"PUT /api/v1/teams/{id}":                            ref("Team"),
	"GET /api/v1/relays":                                collection("Relay"),
	"GET /api/v1/relays/{id}":                           ref("Relay"),
	"GET /api/v1/secrets":                               collection("Secret"),
	"GET /api/v1/secrets/{name}":                        ref("Secret"),
	"GET /api/v1/budgets/{key...}":                      ref("Budget"),
	"PUT /api/v1/budgets/{key...}":                      ref("Budget"),
	"GET /api/v1/hosts":                                 pagedCollection("Host"),
	"GET /api/v1/hosts/{id}":                            ref("HostDetail"),
	"PUT /api/v1/hosts/{id}/tags":                       ref("Host"),
	"PUT /api/v1/hosts/{id}/channel":                    ref("Host"),
	"PUT /api/v1/hosts/{id}/owner":                      ref("Host"),
	"PUT /api/v1/hosts/{id}/management-address":         ref("Host"),
	"PUT /api/v1/hosts/{id}/failure-domain":             ref("Host"),
	"PUT /api/v1/hosts/{id}/placement":                  ref("Host"),
	"GET /api/v1/jobs":                                  cursorCollection("Job"),
	"GET /api/v1/jobs/{id}":                             ref("Job"),
	"POST /api/v1/jobs/{id}/approve":                    ref("Job"),
	"POST /api/v1/jobs/{id}/cancel":                     ref("Job"),
	"GET /api/v1/jobs/{id}/attempts":                    collection("Attempt"),
	"POST /api/v1/hosts/{id}/operations":                ref("Job"),
	"GET /api/v1/campaigns":                             collection("Campaign"),
	"POST /api/v1/campaigns":                            ref("Campaign"),
	"GET /api/v1/campaigns/{id}":                        ref("Campaign"),
	"POST /api/v1/campaigns/{id}/approve":               ref("Campaign"),
	"POST /api/v1/campaigns/{id}/pause":                 ref("Campaign"),
	"POST /api/v1/campaigns/{id}/resume":                ref("Campaign"),
	"POST /api/v1/campaigns/{id}/cancel":                ref("Campaign"),
	"POST /api/v1/campaigns/{id}/retry":                 ref("Campaign"),
	"POST /api/v1/campaigns/{id}/targets/{host}/skip":   ref("CampaignTarget"),
	"POST /api/v1/notifications/deliveries/{id}/retry":  ref("NotificationDelivery"),
	"GET /api/v1/campaign-schedules":                    collection("CampaignSchedule"),
	"POST /api/v1/campaign-schedules":                   ref("CampaignSchedule"),
	"GET /api/v1/campaign-schedules/{id}":               ref("CampaignSchedule"),
	"PUT /api/v1/campaign-schedules/{id}":               ref("CampaignSchedule"),
	"POST /api/v1/campaign-schedules/{id}/run-now":      ref("Campaign"),
	"GET /api/v1/campaigns/{id}/targets":                pagedCollection("CampaignTarget"),
	"GET /api/v1/campaigns/{id}/timeline":               collection("TimelineEntry"),
	"GET /api/v1/campaigns/{id}/steps":                  cursorCollection("CampaignStep"),
	"GET /api/v1/audit":                                 cursorCollection("AuditEvent"),
	"GET /api/v1/budgets":                               items("Budget"),
	"GET /api/v1/fleet/summary":                         ref("FleetSummary"),
	"GET /api/v1/hosts/{id}/audit":                      cursorCollection("AuditEvent"),
	"GET /api/v1/hosts/{id}/packages":                   ref("HostPackageList"),
	"GET /api/v1/hosts/{id}/actions":                    collection("HostAction"),
	"GET /api/v1/hosts/{id}/system/history":             collection("SystemHistoryEntry"),
	"GET /api/v1/hosts/{id}/access":                     ref("HostAccess"),
	"GET /api/v1/policies":                              collection("Policy"),
	"POST /api/v1/policies":                             ref("Policy"),
	"GET /api/v1/policies/{id}":                         ref("Policy"),
	"PUT /api/v1/policies/{id}":                         ref("Policy"),
	"POST /api/v1/policies/{id}/publish":                ref("Policy"),
	"POST /api/v1/policies/{id}/evaluate":               ref("PolicyOutcome"),
	"GET /api/v1/policies/{id}/results":                 pagedCollection("PolicyResult"),
	"GET /api/v1/policies/{id}/versions":                collection("PolicyVersion"),
	"GET /api/v1/hosts/{id}/policies":                   collection("PolicyResult"),
}

// items is a whole list answered at once, without a count: the budgets
// are as many as somebody configured, and nobody pages through them.
func items(name string) map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"items": map[string]any{"type": "array", "items": ref(name)},
		},
	}
}

// cursorCollection is a list read page by page without a total: the task
// list and the audit trail are counted by nobody, only browsed.
func cursorCollection(name string) map[string]any {
	schema := collection(name)
	properties := schema["properties"].(map[string]any)
	properties["next_cursor"] = map[string]any{"type": "string", "description": "Empty on the last page."}
	return schema
}

func pagedCollection(name string) map[string]any {
	schema := cursorCollection(name)
	properties := schema["properties"].(map[string]any)
	properties["total"] = map[string]any{"type": "integer", "description": "How many match the filter across every page."}
	return schema
}

// reasonOnlyBody describes an order whose whole body is why it was placed. The
// body may be left out; the reason then comes from the query if it is there.
func reasonOnlyBody(what string) map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"reason": map[string]any{"type": "string", "description": what},
		},
	}
}

// roleNames lists the roles a binding may name, so a caller reads the
// vocabulary from the contract instead of guessing at the strings.
func roleNames() []string {
	names := make([]string, 0, len(authz.AllRoles()))
	for _, role := range authz.AllRoles() {
		names = append(names, string(role))
	}
	return names
}

// bindingScope is the scope half of a role binding: a site and an environment,
// each of which may be the wildcard.
func bindingScope() map[string]any {
	return map[string]any{
		"site":        map[string]any{"type": "string", "maxLength": hosts.MaxPlacementLength, "description": "The site the role is held over; '*' means every site."},
		"environment": map[string]any{"type": "string", "maxLength": hosts.MaxPlacementLength, "description": "The environment the role is held over; '*' means every environment."},
	}
}

// teamBodySchema is the register entry of a team: the two routes that write one
// take the same fields.
var teamBodySchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"name":        map[string]any{"type": "string", "maxLength": hosts.MaxTeamNameLength, "description": "What people call the team; unique, and not the identifier, so a rename keeps every host and every binding."},
		"description": map[string]any{"type": "string", "maxLength": hosts.MaxTeamDescriptionLength},
		"reason":      map[string]any{"type": "string", "description": "Kept in the audit trail; a team decides who may act on its hosts, so the trail asks for one."},
	},
	"required": []string{"name"},
}

// mergedProperties joins property sets into one map, so a body that shares a
// half with another body does not repeat it.
func mergedProperties(sets ...map[string]any) map[string]any {
	merged := map[string]any{}
	for _, set := range sets {
		for name, schema := range set {
			merged[name] = schema
		}
	}
	return merged
}

// transitionBodySchema is the body of a job transition: why, and the plan the
// approver saw.
var transitionBodySchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"reason": map[string]any{"type": "string", "description": "Kept in the audit trail."},
		"payload_hash": map[string]any{"type": "string",
			"description": "The hash of the payload as the job gives it, so the approval covers the plan that was read. A mismatch means the plan changed between viewing and approving, and the transition is refused."},
	},
}

// alertNoteBodySchema is the body of an acknowledgement or a note. The reason is
// taken in place of the note, so a client that sends every change the same way
// is not refused.
func alertNoteBodySchema(what string) map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"note":   map[string]any{"type": "string", "maxLength": maxAlertNote, "description": what},
			"reason": map[string]any{"type": "string", "maxLength": maxAlertNote, "description": "Taken in place of note when note is empty."},
		},
	}
}

// lifecycleBodySchema is the body of a change of a host's lifecycle state. The
// reason is required everywhere: a host cut off without one is a host nobody
// will know in a week why it is not working.
func lifecycleBodySchema(reason string) map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"reason":              map[string]any{"type": "string", "description": reason},
			"revoke_certificates": map[string]any{"type": "boolean", "description": "Revoke the host's certificates as well; for a suspected key leak."},
		},
		"required": []string{"reason"},
	}
}

// hostSelectorSchema is the scope of a rule: the flat fields, or an expression
// for a scope they cannot say.
func hostSelectorSchema() map[string]any {
	return map[string]any{
		"type":        "object",
		"description": "Which hosts the rule watches. Left empty it watches every host the reader may see.",
		"properties": map[string]any{
			"site":        map[string]any{"type": "string"},
			"environment": map[string]any{"type": "string"},
			"os_family":   map[string]any{"type": "string"},
			"tags": map[string]any{"type": "array", "items": map[string]any{"type": "string"},
				"description": "Keeps the hosts carrying every one of the tags, 'key' or 'key=value' as recorded on the host."},
			"groups": map[string]any{"type": "array", "items": map[string]any{"type": "string"},
				"description": "Keeps the hosts of any of the saved groups, named by identifier or by name."},
			"owner":      map[string]any{"type": "string"},
			"expression": map[string]any{"type": "string", "description": "The text form of a campaign selector, for a scope the flat fields cannot say."},
		},
	}
}

// alertRuleBodySchema is the rule an operator writes down. The vocabularies come
// from the monitoring package: a contract that restated them would be free to
// disagree with the evaluator.
var alertRuleBodySchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"name":      map[string]any{"type": "string"},
		"metric":    map[string]any{"type": "string", "enum": monitoring.Metrics},
		"operator":  map[string]any{"type": "string", "enum": monitoring.Operators},
		"threshold": map[string]any{"type": "number", "description": "Compared with the reading of the metric; a number, never NaN or an infinity."},
		"for_minutes": map[string]any{"type": "integer", "minimum": 0, "maximum": 24 * 60,
			"description": "How long the comparison has to hold before the alert fires; zero fires on the first reading."},
		"severity": map[string]any{"type": "string", "enum": monitoring.Severities},
		"selector": hostSelectorSchema(),
		"enabled":  map[string]any{"type": []string{"boolean", "null"}, "description": "Left out, a rule written down is a rule meant to run."},
		"expected_cadence_seconds": map[string]any{"type": "integer",
			"minimum":     int(monitoring.SamplingInterval / time.Second),
			"maximum":     int(monitoring.MaxCadence / time.Second),
			"description": "How often a reading is expected. It cannot be faster than the agents sample."},
		"max_gap_seconds": map[string]any{"type": "integer", "maximum": int(monitoring.MaxCadence / time.Second),
			"description": "The widest gap between readings that is not a gap. It cannot be narrower than the expected cadence, or a reading that arrives on time opens one."},
		"no_data_policy": map[string]any{"type": "string", "enum": monitoring.NoDataPolicies,
			"description": "What the evaluator does when the readings stop. A rule that does not say ignores gaps."},
	},
	"required": []string{"name", "metric", "operator", "severity"},
}

// channelBodySchema is a notification channel. The configuration stays free-form
// because it belongs to the kind - a webhook URL is not an address book - and the
// panel refuses a configuration its kind does not recognise.
var channelBodySchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"name":   map[string]any{"type": "string"},
		"kind":   map[string]any{"type": "string", "enum": notify.Kinds},
		"config": map[string]any{"type": "object", "description": "The settings of that kind; checked against the kind, not against this schema."},
		"events": map[string]any{"type": "array", "items": map[string]any{"type": "string"},
			"description": "The event types the channel carries; empty carries every type."},
		"filter": map[string]any{"type": "object", "description": "Which events reach the channel. A filter naming no part of the fleet is the channel of the whole installation, and the only one an event of unknown place reaches.",
			"properties": map[string]any{
				"severity_min": map[string]any{"type": "string", "enum": monitoring.Severities,
					"description": "The least severity of an alert the channel carries; an event that is not an alert has no severity and passes."},
				"site":        map[string]any{"type": "string"},
				"environment": map[string]any{"type": "string"},
			}},
		"enabled": map[string]any{"type": []string{"boolean", "null"}, "description": "Left out, a channel written down is meant to carry."},
		"reason": map[string]any{"type": "string", "minLength": minimalStepUpReason,
			"description": "What the channel is for, or why it changed; required."},
	},
	"required": []string{"name", "kind", "reason"},
}

// silenceBodySchema keeps alerts back for a while. An open-ended silence cannot
// be ordered: an alert nobody will ever see again is not silenced, it is lost.
func silenceBodySchema(scope string) map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"reason": map[string]any{"type": "string", "minLength": monitoring.MinSilenceReason,
				"description": "Why the alerts are kept back; required."},
			"minutes": map[string]any{"type": "integer", "minimum": 0,
				"maximum":     int(monitoring.MaxSilence / time.Minute),
				"description": "How long, counted from now; zero means an hour."},
			"rule_id":      map[string]any{"type": "string", "description": "Narrows the silence to one rule. " + scope},
			"global":       map[string]any{"type": "boolean", "description": "The silence that keeps back the security alerts of the installation. It names no host and no rule, and it needs a right of its own."},
			"send_summary": map[string]any{"type": "boolean", "description": "Send one message per channel when the silence ends, naming what it kept back."},
		},
		"required": []string{"reason"},
	}
}

// groupBodySchema is a saved group. A static group keeps the hosts it was given;
// a dynamic one keeps the expression and is answered when it is read, so its
// membership follows the fleet.
var groupBodySchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"name":        map[string]any{"type": "string"},
		"description": map[string]any{"type": "string"},
		"kind": map[string]any{"type": "string",
			"enum":        []string{string(selector.KindStatic), string(selector.KindDynamic)},
			"description": "Left out, the group is static."},
		"selector": map[string]any{"type": "object",
			"description": "The expression of a dynamic group, in the campaign selector's own form."},
		"host_ids": map[string]any{"type": "array", "items": map[string]any{"type": "string"},
			"description": "The members of a static group, given here so that the group and its members come into being in one order."},
	},
	"required": []string{"name"},
}

// fanOutActions lists the actions a read may fan out over, taken from the
// registry that refuses the rest: a contract restating them would be free to
// offer an action the panel turns down.
func fanOutActions() []string {
	names := make([]string, 0, len(opspec.AllActions()))
	for _, action := range opspec.AllActions() {
		if opspec.FanOutRefusal(action) == "" {
			names = append(names, string(action))
		}
	}
	sort.Strings(names)
	return names
}

// fleetRemediationBodySchema is a remediation over many hosts: which findings,
// which hosts, and how carefully it rolls out.
func fleetRemediationBodySchema(order bool) map[string]any {
	properties := map[string]any{
		"check_ids": map[string]any{"type": "array", "items": map[string]any{"type": "string"},
			"description": "The findings to fix. An empty list does not mean everything: there is no fix-all."},
		"selector": map[string]any{"type": "object", "description": "Which hosts, the way a campaign names them."},
	}
	if order {
		for name, schema := range map[string]any{
			"name":   map[string]any{"type": "string"},
			"reason": map[string]any{"type": "string", "description": "Kept in the audit trail."},
			"canary_size": map[string]any{"type": []string{"integer", "null"}, "minimum": 1,
				"description": "How many hosts go first, alone. Left out, the module's policy decides."},
			"wave_size": map[string]any{"type": []string{"integer", "null"}, "minimum": 1, "maximum": maxRemediationWave},
			"max_concurrent": map[string]any{"type": []string{"integer", "null"}, "minimum": 1,
				"description": "How many hosts change at once inside a wave."},
			"failure_threshold_percent": map[string]any{"type": []string{"integer", "null"}, "minimum": 0, "maximum": 100,
				"description": "The share of failures in a wave that stops the rollout."},
			"manual_gate": map[string]any{"type": []string{"boolean", "null"},
				"description": "Hold after the canary until somebody lets the waves in."},
			"offline_policy": map[string]any{"type": "string",
				"enum": []string{string(opspec.OfflineRequireOnline), string(opspec.OfflineSkip),
					string(opspec.OfflineWait), string(opspec.OfflineReplan)},
				"description": "What happens to a host that is not connected when its turn comes. It may only tighten what the operation declares; a weaker policy is refused."},
			"deadline_minutes": map[string]any{"type": []string{"integer", "null"}, "minimum": 1},
			"idempotency_key":  map[string]any{"type": "string", "description": "Repeating the order under the same key gives the rollout that already exists rather than a second one."},
		} {
			properties[name] = schema
		}
	}
	return map[string]any{"type": "object", "properties": properties, "required": []string{"check_ids"}}
}

// bodilessRoutes are the writing routes that read no body. They act on what the
// panel already holds - a stored configuration, a row named in the path - and the
// document said "send an object" for every one of them, which is a promise the
// panel does not keep. A route belongs here or in requestSchemas, never both and
// never neither.
var bodilessRoutes = map[string]string{
	"POST /auth/logout":                                        "the caller's own session is what ends",
	"POST /api/v1/enrollment-requests/{id}/revoke":             "the order is named in the path",
	"POST /api/v1/notifications/channels/{id}/test":            "the channel's own settings are what is tested",
	"POST /api/v1/notifications/deliveries/{id}/retry":         "the delivery is named in the path",
	"POST /api/v1/hosts/{id}/security/remediation/{plan}/stop": "the plan is named in the path",
	"POST /api/v1/policies/{id}/evaluate":                      "the published policy is what is judged",
	"POST /api/v1/setup/test-oidc":                             "the stored identity provider is what is probed",
	"POST /api/v1/setup/test-directory":                        "the stored directory connector is what is probed",
	"POST /api/v1/identity/directory/provision-preserve":       "the stored connector is what is read",
}

var requestSchemas = map[string]map[string]any{
	"POST /api/v1/vulnerabilities/snapshots/{id}/accept": reasonOnlyBody(
		"Why the snapshot is taken as the fleet's picture; kept in the audit trail."),
	"POST /api/v1/hosts/{id}/certificates/targets": {
		"type":        "object",
		"description": "A file on the host the panel watches and, when it has a plan, replaces.",
		"properties": map[string]any{
			"path":        map[string]any{"type": "string", "description": "The certificate on the host."},
			"key_path":    map[string]any{"type": "string", "description": "Its private key, when the panel is to place one."},
			"key_secret":  map[string]any{"type": "string", "description": "The name of the secret holding that key. The key itself never travels in this body."},
			"reload_unit": map[string]any{"type": "string", "description": "The unit to reload once the file has changed; without it the new certificate sits on disk unused."},
			"probe_target": map[string]any{"type": "string",
				"description": "Where to check afterwards what the service actually presents, so a reload that did not take is not read as success."},
			"service": map[string]any{"type": "string"},
			"note":    map[string]any{"type": "string"},
		},
		"required": []string{"path"},
	},
	"POST /api/v1/hosts/{id}/identity-recovery": {
		"type":        "object",
		"description": "A token that lets a host whose key is lost or stolen come back as itself. A retired host does not come back this way.",
		"properties": mergedProperties(bindingScope(), map[string]any{
			"description": map[string]any{"type": "string"},
			"kind":        map[string]any{"type": "string", "description": "What may register with the token: an agent or a relay."},
			"purpose":     map[string]any{"type": "string", "description": "What may be done with a machine the panel already knows."},
			"expected_machine_id": map[string]any{"type": "string",
				"description": "The machine the token is for; a different machine presenting it is refused."},
			"relay_id": map[string]any{"type": "string", "description": "Confines the token to one site: it works only through this relay."},
			"owner":    map[string]any{"type": "string"},
			"tags":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			"max_uses": map[string]any{"type": "integer", "minimum": 1},
			"revoke_old_immediately": map[string]any{"type": "boolean",
				"description": "Cut the old key off now rather than when the host returns; for a suspected theft."},
			"ttl_seconds": map[string]any{"type": "integer", "minimum": 1},
		}),
	},
	"POST /api/v1/security/remediation":         fleetRemediationBodySchema(true),
	"POST /api/v1/security/remediation/preview": fleetRemediationBodySchema(false),
	"POST /api/v1/hosts/{id}/security/remediation": {
		"type": "object",
		"properties": map[string]any{
			"plan_hash": map[string]any{"type": "string",
				"description": "Binds the order to the state the operator viewed. A host whose findings moved since then needs a new plan."},
			"check_ids": map[string]any{"type": "array", "items": map[string]any{"type": "string"},
				"description": "The findings to fix. An empty list does not mean everything: there is no fix-all."},
			"reason": map[string]any{"type": "string", "description": "Kept in the audit trail."},
			"stop_on_failure": map[string]any{"type": []string{"boolean", "null"},
				"description": "Left out it holds: the later steps assume the earlier ones succeeded."},
		},
		"required": []string{"check_ids"},
	},
	"POST /api/v1/identity/changes/{id}/approve": {
		"type": "object",
		"properties": map[string]any{
			"payload_hash": map[string]any{"type": "string",
				"description": "The hash of the change as it was read, so the approval covers that change and not what it became."},
			"reason": map[string]any{"type": "string", "description": "Kept in the audit trail."},
		},
	},
	"POST /api/v1/identity/changes/{id}/cancel": reasonOnlyBody(
		"Why the change to the directory is abandoned; kept in the audit trail."),
	"POST /api/v1/identity/access/simulate": {
		"type":        "object",
		"description": "Asks what the rules would say, and changes nothing.",
		"properties": map[string]any{
			"user":    map[string]any{"type": "string", "description": "The identity to ask about."},
			"host":    map[string]any{"type": "string"},
			"service": map[string]any{"type": "string", "description": "The service on that host, as the access rules name it."},
		},
		"required": []string{"user", "host"},
	},
	"POST /api/v1/hosts/{id}/backups": {
		"type": "object",
		"description": "The whole definition, not a change to it: a field left out is a field cleared. " +
			"The panel checks it the way the host would, so a definition the host would refuse does not wait until the first copy.",
		"properties": map[string]any{
			"name":         map[string]any{"type": "string", "description": "Names the definition on the host; one host keeps one definition under one name."},
			"tool":         map[string]any{"type": "string", "enum": []string{backupmodule.ToolRestic, backupmodule.ToolBorg}},
			"repository":   map[string]any{"type": "string", "description": "Where the copies go, in the form the tool reads."},
			"paths":        map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "What is copied."},
			"excludes":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			"tags":         map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Carried into the repository, so a copy can be found by what made it."},
			"keep_last":    map[string]any{"type": "integer", "minimum": 0, "description": "Zero leaves this rule out of the retention."},
			"keep_daily":   map[string]any{"type": "integer", "minimum": 0},
			"keep_weekly":  map[string]any{"type": "integer", "minimum": 0},
			"keep_monthly": map[string]any{"type": "integer", "minimum": 0},
			"prune": map[string]any{"type": "boolean",
				"description": "Delete what the retention no longer keeps. Without it the retention only forgets the copies, and the repository keeps growing."},
			"runbook":    map[string]any{"type": "string", "description": "What to do when a restore is needed; shown beside the definition."},
			"initialize": map[string]any{"type": "boolean", "description": "Create the repository if it is not there yet."},
			"password_secret": map[string]any{"type": "string",
				"description": "The name of the secret holding the repository password. The value never travels in this body, and an empty field keeps the secret the definition already names."},
			"env_secrets": map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"},
				"description": "Environment variables of the tool, each naming a secret rather than carrying its value."},
			"note": map[string]any{"type": "string"},
		},
		"required": []string{"name", "tool"},
	},
	"POST /api/v1/reads": {
		"type": "object",
		"properties": map[string]any{
			"action":  map[string]any{"type": "string", "enum": fanOutActions(), "description": "A read, or one of the reads the registry opens to a fan-out. A change is never one of them."},
			"payload": map[string]any{"type": "object", "description": "The payload of that action, as the action's own contract describes it."},
			"selector": map[string]any{"type": "object",
				"description": "Which hosts to read, the way a campaign names them: the flat filters, an explicit list, or the typed expression, which decides alone when present. It may not be empty - a read of the whole fleet is never the intent - and the list is bounded by the action's own fan-out limit.",
				"properties": mergedProperties(bindingScope(), map[string]any{
					"host_ids":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"tags":       map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"groups":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"os_family":  map[string]any{"type": "string"},
					"owner":      map[string]any{"type": "string"},
					"expression": map[string]any{"type": "string"},
				})},
			"reason": map[string]any{"type": "string", "description": "Kept in the audit trail beside the order."},
		},
		"required": []string{"action", "selector"},
	},
	"POST /api/v1/pki/prepare": reasonOnlyBody(
		"Why a new fleet authority is being made. It joins the trust set without the right to sign, so the fleet learns it before anything is signed by it."),
	"POST /api/v1/pki/activate": reasonOnlyBody(
		"Why the prepared authority takes over the signing. Hosts that have not yet learned it will refuse what it signs, so the order follows the preparation rather than replacing it."),
	"POST /api/v1/relays/{id}/revoke": reasonOnlyBody(
		"Why the relay loses the right to mediate; kept in the audit trail."),
	"POST /api/v1/group-mappings": {
		"type": "object",
		"properties": mergedProperties(bindingScope(), map[string]any{
			"issuer":     map[string]any{"type": "string", "description": "The identity provider the group comes from."},
			"group_name": map[string]any{"type": "string", "description": "The group as that provider names it."},
			"role":       map[string]any{"type": "string", "enum": roleNames()},
			"reason":     map[string]any{"type": "string", "description": "Kept in the audit trail; the mapping grants the role to everyone the provider puts in that group."},
		}),
		"required": []string{"issuer", "group_name", "role"},
	},
	"POST /api/v1/host-groups":     groupBodySchema,
	"PUT /api/v1/host-groups/{id}": groupBodySchema,
	"PUT /api/v1/host-groups/{id}/members": {
		"type": "object",
		"properties": map[string]any{
			"host_ids": map[string]any{"type": "array", "items": map[string]any{"type": "string"},
				"description": "The whole member list, not a change to it: a host left out is a host removed."},
		},
		"required": []string{"host_ids"},
	},
	"PUT /api/v1/hosts/{id}/channel": {
		"type": "object",
		"properties": map[string]any{
			"channel": map[string]any{"type": "string", "enum": []string{hosts.ChannelStable, hosts.ChannelBeta},
				"description": "Which releases the host is offered. It decides what an upgrade order may name, not when one is placed."},
		},
		"required": []string{"channel"},
	},
	"POST /api/v1/secrets/{name}/rotate": {
		"type": "object",
		"properties": map[string]any{
			"value": map[string]any{"type": "string",
				"description": "The new value. The versions before it stay readable to the hosts holding a lease on them until they are destroyed."},
			"reason": map[string]any{"type": "string", "description": "Why the secret changes; kept in the audit trail."},
		},
		"required": []string{"value"},
	},
	"POST /api/v1/notifications/channels":     channelBodySchema,
	"PUT /api/v1/notifications/channels/{id}": channelBodySchema,
	"POST /api/v1/hosts/{id}/monitoring/silences": silenceBodySchema(
		"Empty means every alert of this host."),
	"POST /api/v1/monitoring/silences": silenceBodySchema(
		"Empty means every alert in the scope of the silence."),
	"PUT /api/v1/settings/monitoring": {
		"type":        "object",
		"description": "Durations are written the way Go reads them: 720h, 15m, 90s.",
		"properties": map[string]any{
			"raw_retention":    map[string]any{"type": "string", "description": "How long a single reading is kept."},
			"rollup_retention": map[string]any{"type": "string", "description": "How long the quarter-hour series is kept."},
			"max_lateness":     map[string]any{"type": "string", "description": "How late a reading may arrive and still be rolled up into its own quarter."},
			"raw_query_window": map[string]any{"type": "string", "description": "How far back a chart may ask for single readings before it is answered from the series."},
			"clock_skew_limit": map[string]any{"type": "string", "description": "How far a host's clock may run ahead of the panel before its readings are refused."},
			"partitions_ahead": map[string]any{"type": "integer", "minimum": 1, "description": "How many days of partitions are created in advance."},
			"acknowledge_data_loss": map[string]any{"type": "boolean",
				"description": "Required to shorten a retention: what falls outside it is deleted and does not come back, so the decision is made here and not by leaving a field at its default."},
			"reason": map[string]any{"type": "string", "description": "Kept on the audit trail beside the values."},
		},
	},
	"POST /api/v1/monitoring/rules":     alertRuleBodySchema,
	"PUT /api/v1/monitoring/rules/{id}": alertRuleBodySchema,
	"POST /api/v1/secrets": {
		"type": "object",
		"properties": map[string]any{
			"name": map[string]any{"type": "string", "pattern": `^[a-z0-9][a-z0-9._-]{1,62}$`,
				"description": "Lower-case letters, digits, a dot, a dash and an underscore, 2 to 63 characters."},
			"description": map[string]any{"type": "string"},
			"value": map[string]any{"type": "string",
				"description": "The only place the value appears in the API, and only in this direction: no route ever gives it back."},
			"reason": map[string]any{"type": "string", "description": "What the secret is for; kept in the audit trail."},
		},
		"required": []string{"name", "value"},
	},
	"POST /api/v1/principals": {
		"type": "object",
		"properties": map[string]any{
			"subject":      map[string]any{"type": "string", "description": "The identity as the directory or the token issuer names it."},
			"display_name": map[string]any{"type": "string"},
			"kind":         map[string]any{"type": "string", "enum": []string{"user", "service"}, "description": "Left out, the store's own default decides."},
			"roles": map[string]any{"type": "array", "description": "The bindings to grant at once.",
				"items": map[string]any{"type": "object", "properties": mergedProperties(bindingScope(), map[string]any{
					"role":        map[string]any{"type": "string", "enum": roleNames()},
					"valid_until": map[string]any{"type": "string", "format": "date-time", "description": "An RFC 3339 moment the binding ends at; empty means until revoked."},
				}), "required": []string{"role"}},
			},
			"issue_token": map[string]any{"type": "boolean",
				"description": "Issue an API token together with the identity. Its value is in that one answer and nowhere else."},
			"token_ttl_hours": map[string]any{"type": "integer", "minimum": 1, "maximum": int(maxTokenTTL / time.Hour),
				"description": "How long that token lives; left out it takes the panel's default."},
			"reason": map[string]any{"type": "string", "description": "What the access is granted for; the order moves the access rules of the whole fleet."},
		},
		"required": []string{"subject"},
	},
	// The key is the registered pattern, wildcard and all: the table is looked up
	// by it, and the document normalises it to {key} only for the reader.
	"PUT /api/v1/budgets/{key...}": {
		"type": "object",
		"properties": map[string]any{
			"capacity": map[string]any{"type": "integer", "minimum": 1,
				"description": "How many changes of this kind may run at once under this key."},
			"note": map[string]any{"type": "string", "description": "Why the budget is what it is."},
		},
		"required": []string{"capacity"},
	},
	"PUT /api/v1/me/preferences": {
		"type": "object",
		"properties": map[string]any{
			"time_zone": map[string]any{"type": "string", "maxLength": maxTimeZoneLength,
				"description": "An IANA zone name the panel reads times in; empty for the browser's own zone."},
			"page_size": map[string]any{"type": "integer", "minimum": 0, "maximum": maxPreferredPageSize,
				"description": "Rows per page in the lists; zero for the default."},
			"landing_page": map[string]any{"type": "string", "maxLength": maxLandingPageLength,
				"description": "A path of this panel, such as /hosts; empty for the dashboard."},
			"language": map[string]any{"type": "string", "enum": []string{"", "en", "pl"}, "description": "Empty leaves the choice to the browser."},
			"theme":    map[string]any{"type": "string", "enum": []string{"", "mocha-peach", "mocha-green", "latte"}},
		},
	},
	"POST /api/v1/hosts/{id}/quarantine": lifecycleBodySchema(
		"Why the host is cut off from the fleet; required."),
	"POST /api/v1/hosts/{id}/quarantine/release": lifecycleBodySchema(
		"Why the host is taken back into the fleet; required."),
	"POST /api/v1/hosts/{id}/decommission": {
		"type": "object",
		"properties": map[string]any{
			"reason": map[string]any{"type": "string", "description": "Why the panel stops trusting the host; required."},
			"typed_confirmation": map[string]any{"type": "string",
				"description": "The host's own hostname, retyped. It has to match exactly: this is the one place where the operator is made to look at which machine is being ended."},
			"revoke_certificates": map[string]any{"type": "boolean", "description": "Revoke the host's certificates as well."},
			"local_identity_wipe": map[string]any{"type": []string{"boolean", "null"},
				"description": "Ask the agent to remove its identity and journal and to disable its service, once the panel has revoked the certificates. Left out, the panel's own default decides."},
			"revoke_immediately_if_offline": map[string]any{"type": []string{"boolean", "null"},
				"description": "Revoke the certificates of a host that has no session instead of waiting for it to come back. Left out, the panel's own default decides."},
		},
		"required": []string{"reason", "typed_confirmation"},
	},
	"POST /api/v1/hosts/{id}/maintenance": {
		"type": "object",
		"properties": map[string]any{
			"until":            map[string]any{"type": "string", "format": "date-time", "description": "When the window closes, as an RFC 3339 moment. Send this or duration_minutes, not both."},
			"duration_minutes": map[string]any{"type": "integer", "minimum": 1, "description": "How long the window lasts from now. Send this or until."},
			"reason":           map[string]any{"type": "string", "description": "Kept with the window and shown wherever the host is silenced."},
			"clear":            map[string]any{"type": "boolean", "description": "Close the window early; the other fields are then ignored."},
		},
	},
	"PUT /api/v1/hosts/{id}/tags": {
		"type": "object",
		"properties": map[string]any{
			"tags": map[string]any{"type": "array", "items": map[string]any{"type": "string"},
				"description": "The whole list, not a change to it: a tag left out is a tag removed."},
		},
		"required": []string{"tags"},
	},
	"POST /api/v1/tags/rename": {
		"type": "object",
		"properties": map[string]any{
			"from":   map[string]any{"type": "string", "description": "The tag as it is now."},
			"to":     map[string]any{"type": "string", "description": "The tag it becomes, on every host the caller can see."},
			"reason": map[string]any{"type": "string", "description": "Required: a rename touches every host carrying the tag."},
		},
		"required": []string{"from", "to", "reason"},
	},
	// A transition of one job or one campaign: why, and what the approver saw.
	"POST /api/v1/jobs/{id}/approve": transitionBodySchema,
	"POST /api/v1/jobs/{id}/cancel":  transitionBodySchema,
	"POST /api/v1/campaigns/{id}/approve": {
		"type": "object",
		"properties": map[string]any{
			"approval_fingerprint": map[string]any{"type": "string",
				"description": "The fingerprint the campaign carries, as the listing gives it. It covers the operation, the payload, the host list and the rollout policy, and a mismatch means one of them changed between viewing and approving."},
			"reason":        map[string]any{"type": "string", "description": "Part of the evidence; a critical campaign requires it."},
			"change_ticket": map[string]any{"type": "string", "description": "The ticket the change is carried out under; recorded with the approval."},
		},
		"required": []string{"approval_fingerprint"},
	},
	"POST /api/v1/campaigns/{id}/pause":   reasonOnlyBody("Why the waves stop here; kept in the audit trail."),
	"POST /api/v1/campaigns/{id}/resume":  reasonOnlyBody("Why the waves go on; kept in the audit trail."),
	"POST /api/v1/campaigns/{id}/cancel":  reasonOnlyBody("Why the campaign ends early; kept in the audit trail."),
	"POST /api/v1/campaigns/{id}/advance": reasonOnlyBody("Why the campaign is let past the manual gate; kept in the audit trail."),
	"POST /api/v1/campaigns/{id}/retry": {
		"type": "object",
		"properties": map[string]any{
			"reason":          map[string]any{"type": "string", "description": "Why the change is tried again; a second go at a change that failed is a decision, and the record says why."},
			"include_unknown": map[string]any{"type": "boolean", "description": "Take the hosts that ended without a result as well, not only the ones that failed."},
		},
	},
	"POST /api/v1/campaigns/{id}/targets/{host}/skip": {
		"type": "object",
		"properties": map[string]any{
			"reason": map[string]any{"type": "string", "minLength": minimalStepUpReason,
				"description": "Why this host is left out of the campaign; required, because the host stays as it is and the trail has to say who decided that."},
		},
		"required": []string{"reason"},
	},
	"POST /api/v1/monitoring/alerts/{id}/acknowledge": alertNoteBodySchema(
		"What is being done about the alert; at least 8 characters, because an acknowledgement nobody explains is an alert nobody took."),
	"POST /api/v1/monitoring/alerts/{id}/annotate": alertNoteBodySchema(
		"What is worth recording against the alert."),
	// The orders whose whole body is the reason they were placed.
	"POST /api/v1/secrets/{name}/retire":           reasonOnlyBody("Why issuing this secret ends; kept in the audit trail."),
	"POST /api/v1/campaign-schedules/{id}/run-now": reasonOnlyBody("Why the schedule is run off its calendar; kept in the audit trail."),
	"POST /api/v1/support/bundles":                 reasonOnlyBody("Why the bundle is being taken; kept in the audit trail."),
	"POST /api/v1/support/bundles/{id}/download":   reasonOnlyBody("Why the bundle is being fetched; kept in the audit trail."),
	"POST /api/v1/principals/{id}/enable":          reasonOnlyBody("Why the identity gets its access back; kept in the audit trail."),

	"POST /api/v1/teams":     teamBodySchema,
	"PUT /api/v1/teams/{id}": teamBodySchema,
	"PUT /api/v1/hosts/{id}/team": {
		"type": "object",
		"properties": map[string]any{
			"team":   map[string]any{"type": "string", "description": "The identifier of the team the host joins; empty takes it out of the one it is in."},
			"reason": map[string]any{"type": "string", "description": "Kept in the audit trail; the move changes who may act on the machine, so the trail asks for one."},
		},
	},
	"POST /api/v1/principals/{id}/tokens": {
		"type": "object",
		"properties": map[string]any{
			"description":     map[string]any{"type": "string", "description": "What the token is for; it is the only thing that tells two tokens apart afterwards."},
			"token_ttl_hours": map[string]any{"type": "integer", "minimum": 1, "maximum": int(maxTokenTTL / time.Hour), "description": "How long the token lives; left out it takes the panel's default."},
			"reason":          map[string]any{"type": "string", "description": "Kept in the audit trail."},
		},
	},
	"POST /api/v1/principals/{id}/roles": {
		"type": "object",
		"properties": mergedProperties(bindingScope(), map[string]any{
			"role":        map[string]any{"type": "string", "enum": roleNames()},
			"valid_until": map[string]any{"type": "string", "format": "date-time", "description": "An RFC 3339 moment the binding ends at; empty means it holds until revoked."},
			"reason":      map[string]any{"type": "string", "description": "Kept in the audit trail."},
		}),
		"required": []string{"role"},
	},
	"POST /api/v1/principals/{id}/team-roles": {
		"type": "object",
		"properties": map[string]any{
			"role":        map[string]any{"type": "string", "enum": roleNames()},
			"team":        map[string]any{"type": "string", "description": "The identifier of the team the role is held over."},
			"valid_until": map[string]any{"type": "string", "format": "date-time", "description": "An RFC 3339 moment the binding ends at; empty means it holds until revoked."},
			"reason":      map[string]any{"type": "string", "description": "Kept in the audit trail."},
		},
		// A binding names a team or a site and an environment, never both, so
		// the site and the environment are not fields of this order at all.
		"required": []string{"role", "team"},
	},
	// The hand-recorded facts of a host.
	"PUT /api/v1/hosts/{id}/owner": {
		"type": "object",
		"properties": map[string]any{
			"owner":  map[string]any{"type": "string", "maxLength": hosts.MaxOwnerLength, "description": "Who answers for the host; empty clears it."},
			"reason": map[string]any{"type": "string", "description": "Kept in the audit trail."},
		},
		"required": []string{"owner"},
	},
	"PUT /api/v1/hosts/{id}/management-address": {
		"type": "object",
		"properties": map[string]any{
			"address": map[string]any{"type": "string",
				"description": "An IP address or a host name the operator reaches the host at; it is recorded with source 'manual' and observations no longer overwrite it. " +
					"Empty forgets the manual address, and the next session or agent report fills the field again."},
			"reason": map[string]any{"type": "string", "description": "Kept in the audit trail."},
		},
		"required": []string{"address"},
	},
	"POST /api/v1/campaign-schedules":     campaignScheduleSchema,
	"PUT /api/v1/campaign-schedules/{id}": campaignScheduleSchema,
	"PUT /api/v1/hosts/{id}/notes": {
		"type": "object",
		"properties": map[string]any{
			"notes":  map[string]any{"type": "string", "maxLength": hosts.MaxNotesLength, "description": "Free-form notes about the host; empty clears them."},
			"reason": map[string]any{"type": "string", "description": "Kept in the audit trail."},
		},
		"required": []string{"notes"},
	},
	"PUT /api/v1/hosts/{id}/placement": {
		"type": "object",
		"properties": map[string]any{
			"site":        map[string]any{"type": "string", "maxLength": hosts.MaxPlacementLength, "description": "The site the host stands in. Keys the site:* budgets, the scope of every role binding and the site leaf of group selectors; none of them is re-evaluated by the move."},
			"environment": map[string]any{"type": "string", "maxLength": hosts.MaxPlacementLength, "description": "The environment the host serves; decides who may change it and whether a change needs a second person, from the next order on."},
			"reason":      map[string]any{"type": "string", "description": "Required, at least 8 characters; kept in the audit trail."},
		},
		"required": []string{"site", "environment", "reason"},
	},
	"POST /api/v1/hosts/bulk-metadata": {
		"type": "object",
		"properties": map[string]any{
			"host_ids": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "maxItems": 1000},
			"reason":   map[string]any{"type": "string", "description": "Required, at least 8 characters; kept with every host's event."},
			"set": map[string]any{"type": "object", "description": "A field left out leaves that fact alone; an empty owner or failure_domain clears it; maintenance null closes the windows.",
				"properties": map[string]any{
					"tags_add":       map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"tags_remove":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"owner":          map[string]any{"type": "string"},
					"failure_domain": map[string]any{"type": "string"},
					"site":           map[string]any{"type": "string"},
					"environment":    map[string]any{"type": "string"},
					"maintenance": map[string]any{"type": []string{"object", "null"}, "properties": map[string]any{
						"until":            map[string]any{"type": "string", "format": "date-time"},
						"duration_minutes": map[string]any{"type": "integer"},
						"reason":           map[string]any{"type": "string"}}},
				}},
		},
		"required": []string{"host_ids", "reason", "set"},
	},
	"PUT /api/v1/hosts/{id}/failure-domain": {
		"type": "object",
		"properties": map[string]any{
			"failure_domain": map[string]any{"type": "string", "maxLength": hosts.MaxFailureDomainLength,
				"description": "What the host goes down with: a rack, an availability zone, a cluster. " +
					"A change on the host then asks for a token of the budget domain:<failure_domain>:<family> next to the site's; empty takes the host out from under it."},
			"reason": map[string]any{"type": "string", "description": "Kept in the audit trail."},
		},
		"required": []string{"failure_domain"},
	},
	// A directory change: the plan is computed at once, the execution waits for a
	// second person.
	"POST /api/v1/identity/changes": {
		"type": "object",
		"properties": map[string]any{
			"action": map[string]any{"type": "string", "enum": []string{
				"identity.user.create", "identity.user.disable", "identity.user.enable", "identity.sshkeys.set",
				"identity.user.expire", "identity.user.posix", "identity.user.preserve", "identity.user.password.reset",
				"identity.group.members", "identity.hostgroup.members",
				"identity.hbac.rule.ensure", "identity.hbac.rule.remove", "identity.sudo.rule.ensure", "identity.sudo.rule.remove",
				"dns.record.ensure", "dns.record.remove",
				"identity.keytab.rotate",
			}},
			"payload": map[string]any{"type": "object", "description": "One field named after the change: user, reference {uid}, " +
				"expiry {uid, principal_expires_at?, password_expires_at?: RFC 3339, \"\" clears}, posix {uid, uid_number?, gid_number?, shell?, home_directory?}, " +
				"ssh_keys {uid, keys}, group {group, add?, remove?}, host_group {group, add?, remove?: FQDNs}, hbac_rule, sudo_rule, dns, " +
				"or keytab {principal: service/host.fqdn[@REALM]} for identity.keytab.rotate (permission identity.keytab.rotate; the directory retires the keytab with service_disable " +
				"and the fleet host of that name gets an identity.keytab.renew task that reports the old and the new key version; the host's own host/ principal is refused)."},
			"reason": map[string]any{"type": "string", "description": "Required for a change of access: at least 8 characters, kept in the audit trail with the fresh authentication."},
		},
		"required": []string{"action", "payload"},
	},
	"POST /api/v1/identity/changes/{id}/reveal": {
		"type": "object",
		"properties": map[string]any{
			"reason": map[string]any{"type": "string", "description": "Reading a one-time password is a change of access: the reason and the fresh authentication are recorded. " +
				"The answer {uid, one_time_password, expires_on_first_login} comes once, to the person who ordered the reset; " +
				"afterwards 410 secret_consumed, and 404 no_secret when nothing waits - the change has not run, failed, or the value went away with its deadline or a restart."},
		},
	},
	"POST /api/v1/enrollment-requests/{id}/replace": {
		"type":        "object",
		"description": "Places an order like the one named (site, environment, kind, relay binding, owner, tags, uses); a pending order is revoked first. 201 with the token shown once; 400 purpose_not_allowed for a recovery order.",
		"properties": map[string]any{
			"description": map[string]any{"type": "string"},
			"ttl_minutes": map[string]any{"type": "integer"},
			"reason":      map[string]any{"type": "string", "description": "Required for production, a batch token or a relay."},
		},
	},
	"POST /api/v1/enrollment-requests": {
		"type": "object",
		"properties": map[string]any{
			"description":         map[string]any{"type": "string"},
			"site":                map[string]any{"type": "string", "description": "\"default\" when empty."},
			"environment":         map[string]any{"type": "string", "description": "\"unassigned\" when empty."},
			"kind":                map[string]any{"type": "string", "enum": []string{"agent", "relay"}},
			"purpose":             map[string]any{"type": "string", "enum": []string{"new", "relay"}, "description": "Identity recovery is ordered on the host itself."},
			"expected_machine_id": map[string]any{"type": "string"},
			"relay_id":            map[string]any{"type": "string", "description": "Binds the token to one relay; empty means any route."},
			"owner": map[string]any{"type": "string", "maxLength": hosts.MaxOwnerLength,
				"description": "Recorded on the host the moment it enrolls."},
			"tags": map[string]any{"type": "array", "items": map[string]any{"type": "string"},
				"description": "Added to the host's tags at enrollment; the same shape as PUT /hosts/{id}/tags accepts."},
			"max_uses": map[string]any{"type": "integer", "minimum": 1,
				"description": "How many machines the token admits; 1 when left out. More than one is a batch token: it needs host.enroll.batch on top of host.enroll.create (403 permission_denied names it) and fresh authentication with a reason."},
			"ttl_minutes": map[string]any{"type": "integer"},
			"reason":      map[string]any{"type": "string", "description": "Required for production, a batch token or a relay."},
		},
	},
	"POST /api/v1/hosts/{id}/operations": {
		"type": "object",
		"properties": map[string]any{
			"action":              map[string]any{"type": "string", "description": "The operation type from GET /api/v1/actions."},
			"payload":             ref("Payload"),
			"reason":              map[string]any{"type": "string"},
			"target_confirmation": map[string]any{"type": "string", "description": "The hostname, typed, for irreversible operations."},
			"idempotency_key":     map[string]any{"type": "string"},
			"class": map[string]any{"type": "string", "enum": []string{"incident", "interactive"},
				"description": "How urgently the job asks the budgets for capacity; left out, the class follows from the operation and its author."},
		},
		"required": []string{"action"},
	},
	"POST /api/v1/policies":     policySpecSchema,
	"PUT /api/v1/policies/{id}": policySpecSchema,
	"POST /api/v1/policies/{id}/publish": {
		"type": "object",
		"properties": map[string]any{
			"reason": map[string]any{"type": "string",
				"description": "Recorded with the version; required where the step-up policy of the installation asks for one."},
		},
	},
	"POST /api/v1/campaigns": {
		"type": "object",
		"properties": map[string]any{
			"name":   map[string]any{"type": "string"},
			"action": map[string]any{"type": "string"},
			"payload": map[string]any{"allOf": []any{ref("Payload")},
				"description": "For system.hostname.set the shared part carries no name: hostname.mapping {host_id: fqdn} names every host's new name, " +
					"a host it leaves out settles as ineligible with no_hostname_for_host, and a missing, duplicate or invalid entry is refused with invalid_mapping."},
			"reason":                     map[string]any{"type": "string"},
			"selector":                   map[string]any{"type": "object"},
			"canary_size":                map[string]any{"type": "integer"},
			"wave_size":                  map[string]any{"type": "integer"},
			"max_concurrent":             map[string]any{"type": "integer"},
			"failure_threshold_percent":  map[string]any{"type": "integer"},
			"failure_threshold_absolute": map[string]any{"type": "integer"},
			"reboot_policy":              map[string]any{"type": "string", "enum": []string{"never", "if_required", "always"}},
			"health_check_units": map[string]any{"type": "array", "items": map[string]any{"type": "string"},
				"description": "Units verified on every host after its change - after the reboot when there is one, " +
					"right after the change otherwise. A unit that is not active fails the host with health_check_failed."},
			"reboot_timeout_seconds": map[string]any{"type": "integer", "minimum": 60, "maximum": 7200,
				"description": "How long the campaign waits for a host to come back after the reboot it ordered " +
					"before the host fails with reboot_timeout; the default is 900. A host still rebooting when the " +
					"maintenance window ends fails with reboot_window_closed and pauses the campaign."},
			"compensates_campaign_id": map[string]any{"type": "string",
				"description": "A finished campaign this one undoes. The operation has to be the declared reverse of that campaign's " +
					"and the targets hosts it changed; an empty selector takes exactly those hosts. The original is linked, never rewritten. " +
					"Refusals: compensated_campaign_not_found, compensated_campaign_not_settled, not_reverse_operation, " +
					"nothing_to_compensate, compensation_target_unchanged."},
		},
		"required": []string{"name", "action", "selector"},
	},
}

// policySpecSchema is the draft a policy is created and rewritten with.
var policySpecSchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"name":        map[string]any{"type": "string", "maxLength": policy.MaxNameLength},
		"description": map[string]any{"type": "string"},
		"selector":    map[string]any{"type": "object", "description": "The same shape a campaign takes."},
		"rules":       map[string]any{"type": "array", "items": ref("PolicyRule"), "maxItems": policy.MaxRules},
		"remediation_mode": map[string]any{"type": "string", "enum": []string{policy.ModeReport, policy.ModeCampaign, policy.ModeAutomatic},
			"description": "report by default. automatic is accepted in a draft and held to policy.remediate.auto at the publication."},
		"enabled": map[string]any{"type": "boolean", "description": "A disabled policy keeps its results and is not judged."},
		"check_interval_seconds": map[string]any{"type": "integer", "minimum": 60, "maximum": 86400,
			"description": "How often the loop judges the fleet against the policy; 900 by default."},
	},
	"required": []string{"name"},
}

// summaryOf turns a handler name into words: ListHosts -> "List hosts".
func summaryOf(route apiRoute) string {
	if route.Handler == "" {
		// A closure: the path says what it reads.
		words := []string{}
		for _, part := range strings.Split(strings.TrimPrefix(route.Path, "/api/v1/"), "/") {
			if part != "" && !strings.HasPrefix(part, "{") {
				words = append(words, strings.ReplaceAll(part, "-", " "))
			}
		}
		summary := strings.Join(words, " ")
		if summary == "" {
			return route.Method + " " + route.Path
		}
		return strings.ToUpper(summary[:1]) + summary[1:]
	}
	// A word starts at a capital that follows a small letter, or at the
	// last capital of a run of capitals (the "S" of "PKIStatus").
	runes := []rune(route.Handler)
	var words []string
	current := ""
	for i, r := range runes {
		upper := r >= 'A' && r <= 'Z'
		previousLower := i > 0 && runes[i-1] >= 'a' && runes[i-1] <= 'z'
		nextLower := i+1 < len(runes) && runes[i+1] >= 'a' && runes[i+1] <= 'z'
		previousUpper := i > 0 && runes[i-1] >= 'A' && runes[i-1] <= 'Z'
		if i > 0 && upper && (previousLower || (previousUpper && nextLower)) {
			words = append(words, current)
			current = ""
		}
		current += string(r)
	}
	words = append(words, current)
	for i := range words {
		if strings.ToUpper(words[i]) != words[i] {
			words[i] = strings.ToLower(words[i])
		}
	}
	summary := strings.Join(words, " ")
	return strings.ToUpper(summary[:1]) + summary[1:]
}

func tagOf(path string) string {
	parts := strings.Split(strings.TrimPrefix(path, "/api/v1/"), "/")
	if len(parts) == 0 || parts[0] == "" || strings.HasPrefix(parts[0], "/") {
		return "system"
	}
	if parts[0] == "hosts" && len(parts) > 2 {
		return "host " + strings.TrimSuffix(parts[2], "s")
	}
	return parts[0]
}

// openAPIPath rewrites the mux wildcard syntax: "{key...}" is a path
// segment in OpenAPI terms.
func openAPIPath(path string) string {
	return strings.ReplaceAll(path, "...}", "}")
}

// goTypeName is the component name a recursive type is published under: the name
// it has in the source, which is what a reader of the document recognises.
func goTypeName(t reflect.Type) string {
	if name := t.Name(); name != "" {
		return name
	}
	return "Nested"
}

// schemaOf describes a Go type as a JSON schema, following the json tags the way
// the encoder does.
func schemaOf(t reflect.Type, schemas map[string]any) map[string]any {
	return describeType(t, schemas, map[reflect.Type]bool{}, map[reflect.Type]bool{})
}

// describeType is schemaOf with the two things a recursive type needs: which
// types are being expanded right now, and which of them turned out to contain
// themselves. A selector expression is a tree of selector expressions, so
// expanding it in place never ends; it becomes a component that refers to itself,
// which is what a recursive shape looks like in a contract.
func describeType(t reflect.Type, schemas map[string]any,
	expanding, recursive map[reflect.Type]bool) map[string]any {
	switch {
	case t == reflect.TypeOf(time.Time{}):
		return map[string]any{"type": "string", "format": "date-time"}
	case t == reflect.TypeOf(json.RawMessage{}):
		return map[string]any{"description": "Free-form JSON."}
	}
	switch t.Kind() {
	case reflect.Pointer:
		return describeType(t.Elem(), schemas, expanding, recursive)
	case reflect.String:
		return map[string]any{"type": "string"}
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return map[string]any{"type": "integer"}
	case reflect.Float32, reflect.Float64:
		return map[string]any{"type": "number"}
	case reflect.Slice, reflect.Array:
		if t.Elem().Kind() == reflect.Uint8 {
			return map[string]any{"type": "string", "description": "Base64."}
		}
		return map[string]any{"type": "array", "items": describeType(t.Elem(), schemas, expanding, recursive)}
	case reflect.Map:
		return map[string]any{"type": "object", "additionalProperties": describeType(t.Elem(), schemas, expanding, recursive)}
	case reflect.Struct:
		// A type already being expanded is a type that contains itself. It is
		// published under its own name and referred to, and the expansion that
		// started it stores that name.
		if expanding[t] {
			recursive[t] = true
			return ref(goTypeName(t))
		}
		expanding[t] = true
		properties := map[string]any{}
		var required []string
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			if !field.IsExported() {
				continue
			}
			tag := field.Tag.Get("json")
			if tag == "-" {
				continue
			}
			name, options, _ := strings.Cut(tag, ",")
			if name == "" {
				if field.Anonymous {
					for k, v := range describeType(field.Type, schemas, expanding, recursive)["properties"].(map[string]any) {
						properties[k] = v
					}
					continue
				}
				name = field.Name
			}
			properties[name] = describeType(field.Type, schemas, expanding, recursive)
			if !strings.Contains(options, "omitempty") && field.Type.Kind() != reflect.Pointer {
				required = append(required, name)
			}
		}
		schema := map[string]any{"type": "object", "properties": properties}
		if len(required) > 0 {
			sort.Strings(required)
			schema["required"] = required
		}
		delete(expanding, t)
		if recursive[t] {
			name := goTypeName(t)
			if _, published := schemas[name]; !published {
				schemas[name] = schema
			}
			return ref(name)
		}
		return schema
	case reflect.Interface:
		return map[string]any{}
	}
	return map[string]any{}
}

// isProbePath names the endpoints a container runtime asks, which are not
// part of the API document.
func isProbePath(path string) bool {
	return path == "/healthz" || path == "/livez" || path == "/readyz"
}
