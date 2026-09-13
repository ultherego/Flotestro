//go:build integration

// Package integration tests the control plane against a running fleet.
// The tests need a provisioned environment: the panel, the database and
// hosts with the agent.
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
	"io"
	"net/http"
	"os"
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
		t.Skip("FLOTESTRO_TEST_TOKEN is not set; run through Vagrant/test-integration.sh")
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

// database opens a connection to the fleet database. It serves only to
// simulate events that cannot be triggered through the API, such as a lease
// expiring.
func (h *harness) database(ctx context.Context) *pgxpool.Pool {
	h.t.Helper()
	if h.pool != nil {
		return h.pool
	}
	pool, err := pgxpool.New(ctx, envOr("FLOTESTRO_TEST_DATABASE_URL", defaultDatabase))
	if err != nil {
		h.t.Skipf("no access to the fleet database: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		h.t.Skipf("the fleet database does not answer: %v", err)
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
		"roles":       bindings,
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

func (h *harness) get(path string, out any) {
	h.t.Helper()
	h.do(http.MethodGet, path, nil, out, http.StatusOK)
}

// text fetches a response that is not JSON.
//
// The metrics exposition is text in the Prometheus format and is to stay
// that way: passing it through JSON just for the test's convenience would
// check something other than what Prometheus reads.
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
	// Message carries the refusal reason. A refusal without a reason forces
	// the operator to guess whether the file is missing or outside the
	// allowed scope.
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

// packageDetail is the typed result of a package operation.
type packageDetail struct {
	Kind    string `json:"kind"`
	Manager string `json:"manager"`
	Changes []struct {
		Name             string `json:"name"`
		CurrentVersion   string `json:"current_version"`
		CandidateVersion string `json:"candidate_version"`
		Security         bool   `json:"security"`
	} `json:"changes"`
	Applied []struct {
		Name             string `json:"name"`
		CurrentVersion   string `json:"current_version"`
		CandidateVersion string `json:"candidate_version"`
	} `json:"applied"`
	// Removals and Protected are the content of a removal plan: what goes
	// away together with the package and what the panel will not remove
	// despite the request.
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
	h.t.Skipf("no connected host of the %s family", family)
	return hostView{}
}

// createOperation orders an operation and returns the resulting job.
func (h *harness) createOperation(hostID string, body map[string]any) jobView {
	h.t.Helper()
	var job jobView
	h.do(http.MethodPost, "/api/v1/hosts/"+hostID+"/operations", body, &job, http.StatusCreated)
	return job
}

func (h *harness) approve(jobID, payloadHash string) jobView {
	h.t.Helper()
	var job jobView
	h.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/approve",
		map[string]any{"payload_hash": payloadHash}, &job, http.StatusOK)
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
//
// The agent connects with its own backoff, so after the panel closes the
// session there is a moment when the host is offline and that is not a
// failure.
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
//
// The lifecycle tests have to really retire something, and a test fleet host
// must not be: retirement is irreversible and would take the machine away
// from the remaining tests.
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

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	machine := uniqueSubject("test-machine")
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: machine}}, key)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

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
		t.Fatalf("enrolling the synthetic host: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(response.Body, 1<<12))
		t.Fatalf("enrollment rejected: %s %s", response.Status, raw)
	}
	var result struct {
		HostID string `json:"hostId"`
	}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}

	// The synthetic machine disappears together with the test. A retired
	// host stays in the fleet forever - and after a few runs the fleet screen
	// would show nothing but test leftovers. It is deleted straight in the
	// database, because the product has no such operation and should not.
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
