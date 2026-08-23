//go:build integration

// Package integration testuje control plane wobec dzialajacej floty.
// Testy wymagaja postawionego srodowiska: panel, baza i hosty z agentem.
package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	defaultAPI      = "http://192.168.56.10:8080"
	defaultDatabase = "postgres://flotestro:flotestro@192.168.56.20:5432/flotestro?sslmode=disable"
)

// harness zbiera dostep do API i bazy floty testowej.
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
		t.Skip("brak FLOTESTRO_TEST_TOKEN; uruchom przez Vagrant/test-integration.sh")
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

// withToken zwraca kopie harnessu dzialajaca jako inna tozsamosc.
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
		h.t.Fatalf("control plane nie jest zdrowy: %s", health.Status)
	}
}

// database otwiera polaczenie do bazy floty. Sluzy wylacznie do symulacji
// zdarzen, ktorych nie da sie wywolac przez API, jak wygasniecie lease.
func (h *harness) database(ctx context.Context) *pgxpool.Pool {
	h.t.Helper()
	if h.pool != nil {
		return h.pool
	}
	pool, err := pgxpool.New(ctx, envOr("FLOTESTRO_TEST_DATABASE_URL", defaultDatabase))
	if err != nil {
		h.t.Skipf("brak dostepu do bazy floty: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		h.t.Skipf("baza floty nie odpowiada: %v", err)
	}
	h.pool = pool
	h.t.Cleanup(pool.Close)
	return pool
}

// createPrincipal tworzy tozsamosc z rolami i zwraca jej token.
func (h *harness) createPrincipal(subject string, bindings []map[string]string) string {
	h.t.Helper()
	var response struct {
		Token string `json:"token"`
	}
	h.do(http.MethodPost, "/api/v1/principals", map[string]any{
		"subject":     subject,
		"roles":       bindings,
		"issue_token": true,
		// Nadanie dostepu wymaga powodu; w tescie powodem jest sam test.
		"reason": "przygotowanie tozsamosci na potrzeby testu integracyjnego",
	}, &response, http.StatusCreated)
	if response.Token == "" {
		h.t.Fatalf("nie wystawiono tokenu dla %s", subject)
	}
	return response.Token
}

func (h *harness) get(path string, out any) {
	h.t.Helper()
	h.do(http.MethodGet, path, nil, out, http.StatusOK)
}

// do wykonuje zadanie i sprawdza kod odpowiedzi.
func (h *harness) do(method, path string, body any, out any, wantStatus int) {
	h.t.Helper()
	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			h.t.Fatalf("serializacja zadania: %v", err)
		}
		payload = bytes.NewReader(encoded)
	}

	request, err := http.NewRequest(method, h.api+path, payload)
	if err != nil {
		h.t.Fatalf("budowa zadania: %v", err)
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
		h.t.Fatalf("%s %s: kod %d, oczekiwano %d; tresc: %s",
			method, path, response.StatusCode, wantStatus, truncate(raw, 300))
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			h.t.Fatalf("odpowiedz %s %s: %v; tresc: %s", method, path, err, truncate(raw, 300))
		}
	}
}

type hostView struct {
	ID              string           `json:"id"`
	Hostname        string           `json:"hostname"`
	Site            string           `json:"site"`
	Environment     string           `json:"environment"`
	OSFamily        string           `json:"os_family"`
	OSVersion       string           `json:"os_version"`
	ConnectionState string           `json:"connection_state"`
	LifecycleState  string           `json:"lifecycle_state"`
	BootID          string           `json:"boot_id"`
	FailedUnits     *int             `json:"failed_units"`
	PendingUpdates  *int             `json:"pending_updates"`
	RebootRequired  *bool            `json:"reboot_required"`
	Capabilities    []hostCapability `json:"capabilities"`
}

// inventoryFragment odwzorowuje stan jednego modulu inventory.
type inventoryFragment struct {
	HostID            string          `json:"host_id"`
	Module            string          `json:"module"`
	Revision          string          `json:"revision"`
	Source            string          `json:"source"`
	Payload           json.RawMessage `json:"payload"`
	UnavailableReason string          `json:"unavailable_reason"`
	ObservedAt        time.Time       `json:"observed_at"`
}

// hostCapability odwzorowuje rejestr adapterow hosta.
type hostCapability struct {
	Name      string          `json:"name"`
	Version   uint32          `json:"version"`
	Available bool            `json:"available"`
	ReadOnly  bool            `json:"read_only"`
	Reason    string          `json:"reason"`
	Features  map[string]bool `json:"features"`
}

type jobView struct {
	ID              string `json:"id"`
	HostID          string `json:"host_id"`
	ActionType      string `json:"action_type"`
	State           string `json:"state"`
	PayloadHash     string `json:"payload_hash"`
	RequiresApprova bool   `json:"requires_approval"`
	CreatedBy       string `json:"created_by"`
	ApprovedBy      string `json:"approved_by"`
	ResultStatus    string `json:"result_status"`
	ResultErrorCode string `json:"result_error_code"`
}

type attemptView struct {
	Number    int    `json:"attempt_number"`
	Status    string `json:"status"`
	ExitCode  *int   `json:"exit_code"`
	ErrorCode string `json:"error_code"`
	// Message niesie powod odmowy. Odmowa bez powodu zmusza operatora do
	// zgadywania, czy pliku nie ma, czy jest poza dozwolonym zakresem.
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

// packageDetail jest typowanym wynikiem operacji pakietowej.
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
	PlanHash              string `json:"plan_hash"`
	RebootPredicted       bool   `json:"reboot_predicted"`
	MetadataRefreshed     bool   `json:"metadata_refreshed"`
	RebootRequired        bool   `json:"reboot_required"`
	PackageDatabaseBroken bool   `json:"package_database_broken"`
}

func (h *harness) hosts() []hostView {
	h.t.Helper()
	var result struct {
		Items []hostView `json:"items"`
	}
	h.get("/api/v1/hosts", &result)
	return result.Items
}

// hostByFamily zwraca pierwszy online host danej rodziny systemow.
func (h *harness) hostByFamily(family string) hostView {
	h.t.Helper()
	for _, host := range h.hosts() {
		if host.OSFamily == family && host.ConnectionState == "online" {
			return host
		}
	}
	h.t.Skipf("brak podlaczonego hosta rodziny %s", family)
	return hostView{}
}

// createOperation zleca operacje i zwraca powstale zadanie.
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

// awaitTerminal czeka, az zadanie osiagnie stan koncowy.
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
	h.t.Fatalf("zadanie %s nie zakonczylo sie w %s (stan: %s)", jobID, timeout, last.State)
	return last
}

// runOperation zleca operacje, zatwierdza ja w razie potrzeby i czeka na wynik.
func (h *harness) runOperation(hostID string, body map[string]any, timeout time.Duration) (jobView, []attemptView) {
	h.t.Helper()
	job := h.createOperation(hostID, body)
	if job.RequiresApprova {
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
