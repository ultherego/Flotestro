//go:build integration

// Package integration tests the control plane against a running fleet.
package integration

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	defaultAPI      = "http://192.168.56.10:8080"
	defaultDatabase = "postgres://flotestro:flotestro@192.168.56.20:5432/flotestro?sslmode=disable"
	// The package repository of the test fleet. It stands next to the panel,
	// because in the lab the panel is also the release machine.
	defaultRepo = "http://192.168.56.10:8090"
)

// harness gathers the API and database access of the test fleet.
type harness struct {
	t      *testing.T
	api    string
	token  string
	client *http.Client
	pool   *pgxpool.Pool
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	token := os.Getenv("FLOTESTRO_TEST_TOKEN")
	if token == "" {
		absent(t, "FLOTESTRO_TEST_TOKEN is not set; the suite has no identity to talk to the panel with")
	}
	h := &harness{
		t:      t,
		api:    envOr("FLOTESTRO_TEST_API", defaultAPI),
		token:  token,
		client: &http.Client{Timeout: 30 * time.Second},
	}
	h.requireHealthy()
	return h
}

// withToken returns a copy of the harness acting as a different identity.
func (h *harness) withToken(token string) *harness {
	copied := *h
	copied.token = token
	return &copied
}

func (h *harness) requireHealthy() {
	h.t.Helper()
	var health struct {
		Status string `json:"status"`
	}
	h.get("/healthz", &health)
	if health.Status != "ok" {
		h.t.Fatalf("the control plane is not healthy: %s", health.Status)
	}
}

// database opens a connection to the fleet database.
func (h *harness) database(ctx context.Context) *pgxpool.Pool {
	h.t.Helper()
	if h.pool != nil {
		return h.pool
	}
	pool, err := pgxpool.New(ctx, envOr("FLOTESTRO_TEST_DATABASE_URL", defaultDatabase))
	if err != nil {
		absent(h.t, "no access to the fleet database: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		absent(h.t, "the fleet database does not answer: %v", err)
	}
	h.pool = pool
	h.t.Cleanup(pool.Close)
	return pool
}

// createPrincipal creates an identity with roles and returns its token.
func (h *harness) createPrincipal(subject string, bindings []map[string]string) string {
	h.t.Helper()
	var response struct {
		Token string `json:"token"`
	}
	h.do(http.MethodPost, "/api/v1/principals", map[string]any{
		"subject":     subject,
		"roles":       anyTeam(bindings),
		"issue_token": true,
		// Granting access requires a reason; in a test the reason is the test
		// itself.
		"reason": "identity prepared for an integration test",
	}, &response, http.StatusCreated)
	if response.Token == "" {
		h.t.Fatalf("no token was issued for %s", subject)
	}
	return response.Token
}

// anyTeam says of every binding what the panel refuses to guess: that it is not
// narrowed by team. A test that means one team passes team_scope itself.
func anyTeam(bindings []map[string]string) []map[string]any {
	out := make([]map[string]any, 0, len(bindings))
	for _, binding := range bindings {
		role := map[string]any{"team_scope": map[string]string{"mode": "any"}}
		for key, value := range binding {
			role[key] = value
		}
		out = append(out, role)
	}
	return out
}

func (h *harness) get(path string, out any) {
	h.t.Helper()
	h.do(http.MethodGet, path, nil, out, http.StatusOK)
}

// text fetches a response that is not JSON.
func (h *harness) text(path string) string {
	h.t.Helper()
	request, err := http.NewRequest(http.MethodGet, h.api+path, nil)
	if err != nil {
		h.t.Fatalf("building the request: %v", err)
	}
	if h.token != "" {
		request.Header.Set("Authorization", "Bearer "+h.token)
	}
	response, err := h.client.Do(request)
	if err != nil {
		h.t.Fatalf("GET %s: %v", path, err)
	}
	defer response.Body.Close()

	raw, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK {
		h.t.Fatalf("GET %s: status %d; body: %s", path, response.StatusCode, truncate(raw, 300))
	}
	return string(raw)
}

// do performs a request and checks the response status.
func (h *harness) do(method, path string, body any, out any, wantStatus int) {
	h.t.Helper()
	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			h.t.Fatalf("encoding the request: %v", err)
		}
		payload = bytes.NewReader(encoded)
	}

	request, err := http.NewRequest(method, h.api+path, payload)
	if err != nil {
		h.t.Fatalf("building the request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	if h.token != "" {
		request.Header.Set("Authorization", "Bearer "+h.token)
	}

	response, err := h.client.Do(request)
	if err != nil {
		h.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer response.Body.Close()

	raw, _ := io.ReadAll(response.Body)
	if wantStatus == 0 {
		return
	}
	if response.StatusCode != wantStatus {
		h.t.Fatalf("%s %s: status %d, expected %d; body: %s",
			method, path, response.StatusCode, wantStatus, truncate(raw, 300))
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			h.t.Fatalf("response of %s %s: %v; body: %s", method, path, err, truncate(raw, 300))
		}
	}
}

type hostView struct {
	ID              string `json:"id"`
	Hostname        string `json:"hostname"`
	Site            string `json:"site"`
	Environment     string `json:"environment"`
	OSFamily        string `json:"os_family"`
	OSVersion       string `json:"os_version"`
	ConnectionState string `json:"connection_state"`
	LifecycleState  string `json:"lifecycle_state"`
	BootID          string `json:"boot_id"`
	FailedUnits     *int   `json:"failed_units"`
	PendingUpdates  *int   `json:"pending_updates"`
	RebootRequired  *bool  `json:"reboot_required"`
	// Maintenance is empty when the host is not in a maintenance window.
	Maintenance  *maintenanceWindowView `json:"maintenance"`
	Capabilities []hostCapability       `json:"capabilities"`
}

// maintenanceWindowView mirrors the maintenance window of a host.
type maintenanceWindowView struct {
	Until  time.Time `json:"until"`
	Reason string    `json:"reason"`
	SetBy  string    `json:"set_by"`
}

// inventoryFragment mirrors the state of one inventory module.
type inventoryFragment struct {
	HostID            string          `json:"host_id"`
	Module            string          `json:"module"`
	Revision          string          `json:"revision"`
	Source            string          `json:"source"`
	Payload           json.RawMessage `json:"payload"`
	UnavailableReason string          `json:"unavailable_reason"`
	ObservedAt        time.Time       `json:"observed_at"`
}

// hostAdapterFeature reads one feature of one adapter out of the host's
// registry. The second result is false when the adapter or the feature is not
// reported at all, which the panel reads as unknown and not as a no.
func hostAdapterFeature(host hostView, adapter, feature string) (value, known bool) {
	for _, capability := range host.Capabilities {
		if capability.Name != adapter {
			continue
		}
		value, known = capability.Features[feature]
		return value, known
	}
	return false, false
}

// hostWritesResolver mirrors the panel's own rule for the dns.write
// requirement, so a target is chosen by the capability the operation declares
// rather than by a neighbouring one.
func hostWritesResolver(host hostView) bool {
	value, known := hostAdapterFeature(host, "dns", "write")
	if value {
		return true
	}
	// An agent silent about the feature leaves the decision to execution time,
	// exactly as the panel's requirement does.
	return !known && hasCapability(host, "dns")
}

// hostCapability mirrors the adapter registry of a host.
type hostCapability struct {
	Name      string          `json:"name"`
	Version   uint32          `json:"version"`
	Available bool            `json:"available"`
	ReadOnly  bool            `json:"read_only"`
	Reason    string          `json:"reason"`
	Features  map[string]bool `json:"features"`
}

type jobView struct {
	// Approvals: a destructive operation requires two people, so the
	// requires_approval flag alone is not enough.
	RequiredApprovals  int    `json:"required_approvals"`
	CollectedApprovals int    `json:"collected_approvals"`
	ID                 string `json:"id"`
	HostID             string `json:"host_id"`
	ActionType         string `json:"action_type"`
	State              string `json:"state"`
	PayloadHash        string `json:"payload_hash"`
	RequiresApproval   bool   `json:"requires_approval"`
	CreatedBy          string `json:"created_by"`
	CreatedByKind      string `json:"created_by_kind"`
	ApprovedBy         string `json:"approved_by"`
	ResultStatus       string `json:"result_status"`
	ResultErrorCode    string `json:"result_error_code"`
	ResultMessage      string `json:"result_message"`
}

type attemptView struct {
	Number    int    `json:"attempt_number"`
	Status    string `json:"status"`
	ExitCode  *int   `json:"exit_code"`
	ErrorCode string `json:"error_code"`
	// Message carries the refusal reason. A refusal without a reason forces the
	// operator to guess whether the file is missing or outside the allowed scope.
	Message         string `json:"message"`
	Stdout          string `json:"stdout"`
	Stderr          string `json:"stderr"`
	Replayed        bool   `json:"replayed"`
	UnitStateBefore *struct {
		ActiveState string `json:"active_state"`
		MainPID     uint32 `json:"main_pid"`
	} `json:"unit_state_before"`
	UnitStateAfter *struct {
		ActiveState string `json:"active_state"`
		MainPID     uint32 `json:"main_pid"`
	} `json:"unit_state_after"`
	Detail *packageDetail `json:"detail"`
}

// packageChange is one element of a package plan. Action is part of the
// identity of the element, not decoration: a removal carries the version that
// goes away and no candidate, so a test reading versions has to know which
// direction it holds.
type packageChange struct {
	Name             string `json:"name"`
	CurrentVersion   string `json:"current_version"`
	CandidateVersion string `json:"candidate_version"`
	Architecture     string `json:"architecture"`
	Action           string `json:"action"`
	Security         bool   `json:"security"`
}

// packageDetail is the typed result of a package operation.
type packageDetail struct {
	Kind    string          `json:"kind"`
	Manager string          `json:"manager"`
	Changes []packageChange `json:"changes"`
	Applied []struct {
		Name             string `json:"name"`
		CurrentVersion   string `json:"current_version"`
		CandidateVersion string `json:"candidate_version"`
	} `json:"applied"`
	// Removals and Protected are the content of a removal plan: what goes away
	// together with the package and what the panel will not remove despite the
	// request.
	Removals              []string `json:"removals"`
	Protected             []string `json:"protected"`
	PlanHash              string   `json:"plan_hash"`
	RebootPredicted       bool     `json:"reboot_predicted"`
	MetadataRefreshed     bool     `json:"metadata_refreshed"`
	RebootRequired        bool     `json:"reboot_required"`
	PackageDatabaseBroken bool     `json:"package_database_broken"`
}

func (h *harness) hosts() []hostView {
	h.t.Helper()
	var result struct {
		Items []hostView `json:"items"`
	}
	h.get("/api/v1/hosts", &result)
	return result.Items
}

// hostByFamily returns the first online host of the given OS family.
func (h *harness) hostByFamily(family string) hostView {
	h.t.Helper()
	for _, host := range h.hosts() {
		if host.OSFamily == family && host.ConnectionState == "online" {
			return host
		}
	}
	absent(h.t, "no connected host of the %s family", family)
	return hostView{}
}

// hostByName returns the connected host of that name; the lab's Ubuntu
// host is of the debian family, so a family is not enough to pick it.
// hostByName waits for the named host to be connected, within a bound.
//
// It used to look once. A host whose session had just been cut - by a relay that
// another scenario restarted, by an agent the laboratory had restarted a second
// earlier - was then reported absent, and the scenario that needed it was skipped
// over a gap that closes by itself. On 02.10 two relay scenarios were skipped
// that way in a run where the agent of that very host was finishing tasks
// throughout, which is how the gap was found at all.
//
// The bound matters more than the wait: a host that is really gone still ends the
// scenario as absent, and it does so with the same words.
func (h *harness) hostByName(hostname string) hostView {
	h.t.Helper()
	deadline := time.Now().Add(hostOnlineBound)
	for {
		for _, host := range h.hosts() {
			if host.Hostname == hostname && host.ConnectionState == "online" {
				return host
			}
		}
		if time.Now().After(deadline) {
			absent(h.t, "no connected host named %s within %s", hostname, hostOnlineBound)
			return hostView{}
		}
		time.Sleep(3 * time.Second)
	}
}

// hostOnlineBound is how long a host may take to come back into the fleet. The
// agent reconnects with full jitter from two seconds, and the panel marks a
// session live on the first heartbeat.
const hostOnlineBound = 90 * time.Second

// createOperation orders an operation and returns the resulting job.
func (h *harness) createOperation(hostID string, body map[string]any) jobView {
	h.t.Helper()
	var job jobView
	h.do(http.MethodPost, "/api/v1/hosts/"+hostID+"/operations", body, &job, http.StatusCreated)
	return job
}

// approve consents to a payload the way an operator does. A critical or
// destructive operation needs a reason with the approval, and the suite is not
// exempt from the rule it exists to exercise, so every approval carries one.
func (h *harness) approve(jobID, payloadHash string) jobView {
	h.t.Helper()
	return h.approveWithReason(jobID, payloadHash, "approved by the integration suite")
}

// approveWithReason is the same consent with the reason spelled out, for the
// tests that are about the reason.
func (h *harness) approveWithReason(jobID, payloadHash, reason string) jobView {
	h.t.Helper()
	var job jobView
	body := map[string]any{"payload_hash": payloadHash}
	if reason != "" {
		body["reason"] = reason
	}
	h.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/approve", body, &job, http.StatusOK)
	return job
}

func (h *harness) job(jobID string) jobView {
	h.t.Helper()
	var job jobView
	h.get("/api/v1/jobs/"+jobID, &job)
	return job
}

func (h *harness) attempts(jobID string) []attemptView {
	h.t.Helper()
	var result struct {
		Items []attemptView `json:"items"`
	}
	h.get("/api/v1/jobs/"+jobID+"/attempts", &result)
	return result.Items
}

// awaitTerminal waits until the job reaches a terminal state.
func (h *harness) awaitTerminal(jobID string, timeout time.Duration) jobView {
	h.t.Helper()
	deadline := time.Now().Add(timeout)
	var last jobView
	for time.Now().Before(deadline) {
		last = h.job(jobID)
		switch last.State {
		case "succeeded", "failed", "timed_out", "canceled", "expired":
			return last
		}
		time.Sleep(time.Second)
	}
	h.t.Fatalf("job %s did not finish within %s (state: %s)", jobID, timeout, last.State)
	return last
}

// runOperation orders an operation, approves it when needed and waits for
// the result.
func (h *harness) runOperation(hostID string, body map[string]any, timeout time.Duration) (jobView, []attemptView) {
	h.t.Helper()
	job := h.createOperation(hostID, body)
	if job.RequiresApproval {
		job = h.approve(job.ID, job.PayloadHash)
	}
	final := h.awaitTerminal(job.ID, timeout)
	return final, h.attempts(job.ID)
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

// skipSentinel opens the one line the gate reads out of a skipped test.
// Everything around it is prose for a person; the runner takes the fields.
const skipSentinel = "FLOTESTRO-SKIP"

// absent says that something this suite needs is not in the environment, and
// what to do about it.
//
// A developer without a relay should be able to run the rest of the suite, so
// the ordinary answer is a skip. The gate is a different reader: it is the
// evidence a release stands on, and this class is the one it refuses the run
// on, by name, so the report says which condition was missing.
func absent(t *testing.T, format string, args ...any) {
	t.Helper()
	t.Skipf("%s class=absent reason=%q", skipSentinel, reasonLine(format, args...))
}

// notApplicable says the scenario does not apply to this host and names the
// host of the matrix that does execute it. Without that name the scenario has
// left the run entirely, which is the thing the class exists to prevent.
func notApplicable(t *testing.T, runsOn, format string, args ...any) {
	t.Helper()
	reason := reasonLine(format, args...)
	if bad := unusableField("runs_on", runsOn); bad != "" {
		t.Fatalf("not_applicable: %s (the reason was: %s)", bad, reason)
	}
	t.Skipf("%s class=not_applicable runs_on=%s reason=%q", skipSentinel, runsOn, reason)
}

// waived says the limitation is named, dated and covered by substitute
// evidence. It never yields a pass: the gate reports such a run as limited.
func waived(t *testing.T, waiver, until, evidence, format string, args ...any) {
	t.Helper()
	reason := reasonLine(format, args...)
	for _, bad := range []string{
		unusableField("waiver", waiver),
		unusableField("until", until),
		unusableField("evidence", evidence),
	} {
		if bad != "" {
			t.Fatalf("waived: %s (the reason was: %s)", bad, reason)
		}
	}
	if _, err := time.Parse(time.DateOnly, until); err != nil {
		t.Fatalf("waived: until=%q is not an ISO 8601 date (the reason was: %s)", until, reason)
	}
	t.Skipf("%s class=waived waiver=%s until=%s evidence=%s reason=%q",
		skipSentinel, waiver, until, evidence, reason)
}

// unusableField refuses what the gate's parser would silently mangle. An empty
// value leaves the field out of the line and a value with a space or a quote
// ends the field early, and either turns an honest skip into an unexplained
// gate failure a long way from the test that wrote it.
// reasonLine builds the prose the report will carry. The gate reads the reason
// as everything between the first pair of quotes, so a quote inside it would cut
// the sentence short in the report and leave the operator half an explanation.
func reasonLine(format string, args ...any) string {
	reason := fmt.Sprintf(format, args...)
	return strings.Join(strings.Fields(strings.ReplaceAll(reason, `"`, "'")), " ")
}

func unusableField(name, value string) string {
	if value == "" {
		return name + " is empty"
	}
	if strings.ContainsAny(value, " \t\r\n\"") {
		return fmt.Sprintf("%s=%q carries whitespace or a quote, which the gate's parser cuts on", name, value)
	}
	return ""
}

func truncate(data []byte, limit int) string {
	if len(data) <= limit {
		return string(data)
	}
	return string(data[:limit]) + "..."
}

func unitPayload(unit string) map[string]any {
	return map[string]any{"unit": map[string]any{"unit": unit}}
}

// awaitConnection waits until the host comes back to the fleet.
func (h *harness) awaitConnection(hostID string, limit time.Duration) {
	h.t.Helper()
	deadline := time.Now().Add(limit)
	for {
		for _, host := range h.hosts() {
			if host.ID == hostID && host.ConnectionState == "online" {
				return
			}
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("host %s did not come back to the fleet within %s", hostID, limit)
		}
		time.Sleep(2 * time.Second)
	}
}

// defaultEnrollment points at the public enrollment endpoint of the test
// fleet.
const defaultEnrollment = "https://192.168.56.10:8444"

// enrollSyntheticHost brings a machine that does not exist into the fleet.
func (h *harness) enrollSyntheticHost(t *testing.T) hostView {
	t.Helper()
	var order struct {
		Token string `json:"token"`
	}
	h.do(http.MethodPost, "/api/v1/enrollment-requests", map[string]any{
		"description": "synthetic test host", "site": "lab", "environment": "test",
	}, &order, http.StatusCreated)
	return h.enrollSyntheticHostWithToken(t, order.Token)
}

// enrollSyntheticHostWithToken uses a token that already exists.
func (h *harness) enrollSyntheticHostWithToken(t *testing.T, token string) hostView {
	t.Helper()

	machine := uniqueSubject("test-machine")
	status, raw := h.enrollAttempt(t, token, machine, testCSR(t, machine))
	if status != http.StatusOK {
		t.Fatalf("enrollment rejected: %d %s", status, raw)
	}
	var result struct {
		HostID string `json:"hostId"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}

	// The synthetic machine disappears together with the test.
	t.Cleanup(func() {
		ctx := context.Background()
		if _, err := h.database(ctx).Exec(ctx,
			`delete from hosts where id = $1::uuid`, result.HostID); err != nil {
			t.Logf("the synthetic host %s was not cleaned up: %v", result.HostID, err)
		}
	})

	for _, host := range h.hosts() {
		if host.ID == result.HostID {
			return host
		}
	}
	t.Fatalf("host %s did not appear on the fleet list", result.HostID)
	return hostView{}
}

// enrollAttempt knocks on the public enrollment door once and returns the
// status and the body, whatever they are.
func (h *harness) enrollAttempt(t *testing.T, token, machine string, csrPEM []byte) (int, []byte) {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"enrollmentToken": token,
		"machineId":       machine,
		"hostname":        machine,
		"csrPem":          csrPEM,
		"clientRequestId": uuid.NewString(),
		"build":           map[string]any{"agentVersion": "test"},
	})
	if err != nil {
		t.Fatal(err)
	}

	address := envOr("FLOTESTRO_TEST_ENROLLMENT", defaultEnrollment) +
		"/flotestro.agent.v1.EnrollmentService/Enroll"
	// Trust in the panel comes from the same bundle the agents use: a test
	// that disables verification would not check that path.
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if bundle, err := os.ReadFile(envOr("FLOTESTRO_TEST_CA", "/var/lib/flotestro/ca.pem")); err == nil {
		pool.AppendCertsFromPEM(bundle)
	}
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs: pool, MinVersion: tls.VersionTLS12,
		}},
	}
	request, err := http.NewRequest(http.MethodPost, address, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("calling the enrollment endpoint: %v", err)
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(response.Body, 1<<16))
	return response.StatusCode, raw
}

// testCSR builds a certificate request with a fresh P-256 key, the kind the
// agents generate.
func testCSR(t *testing.T, commonName string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: commonName}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
}

// awaitJobState waits until the job is in one of the wanted states.
func (h *harness) awaitJobState(jobID string, timeout time.Duration, states ...string) jobView {
	h.t.Helper()
	wanted := map[string]bool{}
	for _, state := range states {
		wanted[state] = true
	}
	deadline := time.Now().Add(timeout)
	var last jobView
	for time.Now().Before(deadline) {
		last = h.job(jobID)
		if wanted[last.State] {
			return last
		}
		switch last.State {
		case "succeeded", "failed", "timed_out", "canceled", "expired":
			h.t.Fatalf("job %s ended in state %s before reaching %v (code: %s)",
				jobID, last.State, states, last.ResultErrorCode)
		}
		time.Sleep(500 * time.Millisecond)
	}
	h.t.Fatalf("job %s did not reach %v within %s (state: %s)", jobID, states, timeout, last.State)
	return last
}

// awaitHealthy waits until the control plane answers on /healthz again.
func (h *harness) awaitHealthy(limit time.Duration) {
	h.t.Helper()
	client := &http.Client{Timeout: 3 * time.Second}
	deadline := time.Now().Add(limit)
	for {
		response, err := client.Get(h.api + "/healthz")
		if err == nil {
			var health struct {
				Status string `json:"status"`
			}
			_ = json.NewDecoder(response.Body).Decode(&health)
			response.Body.Close()
			if health.Status == "ok" {
				return
			}
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("the control plane did not come back within %s (last error: %v)", limit, err)
		}
		time.Sleep(time.Second)
	}
}

// cancelJob ends a job that a test leaves behind.
func (h *harness) cancelJob(jobID string) {
	h.t.Helper()
	h.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/cancel",
		map[string]any{"reason": "end of the test"}, nil, 0)
}
