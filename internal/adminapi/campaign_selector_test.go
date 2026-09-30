package adminapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/campaigns"
	"github.com/ultherego/flotestro/internal/selector"
)

// An empty selector is the whole fleet, and a campaign is the one order whose
// effect reaches all of it at once. The refusal is checked on the door, not on
// the resolver: every test below stops before any store is touched, which is
// itself the proof that nothing was resolved.

// operatorPrincipal is somebody who may order campaigns in one placement.
func operatorPrincipal() authz.Principal {
	return authz.Principal{
		ID: "11111111-0000-4000-8000-000000000001", Subject: "jsmith", Kind: "user",
		Bindings: []authz.Binding{{Role: authz.RoleOperator, Scope: authz.Placement("lab", "test")}},
	}
}

// refusalOf reads the code and the sentence of a problem answer.
func refusalOf(t *testing.T, recorder *httptest.ResponseRecorder) (int, string, string) {
	t.Helper()
	var answer struct {
		Code   string `json:"code"`
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &answer); err != nil {
		t.Fatalf("the answer does not read as a problem: %v (body %q)", err, recorder.Body.String())
	}
	return recorder.Code, answer.Code, answer.Detail
}

// asOperator is a request under an identity that may order campaigns.
func asOperator(method, target, body string) *http.Request {
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	return request.WithContext(authz.ContextWithPrincipal(request.Context(), operatorPrincipal()))
}

func TestCampaignOrderRefusesAnEmptySelector(t *testing.T) {
	server := &Server{}
	recorder := httptest.NewRecorder()
	server.handleCreateCampaign(recorder, asOperator(http.MethodPost, "/api/v1/campaigns", `{
		"name": "restart the world", "action": "unit.restart",
		"payload": {"unit": {"unit": "cron.service"}},
		"reason": "CHG-1000: an order that names nobody",
		"selector": {}
	}`))

	status, code, detail := refusalOf(t, recorder)
	if status != http.StatusBadRequest || code != "selector_required" {
		t.Fatalf("an order with an empty selector answered %d %s: %s", status, code, detail)
	}
	if !strings.Contains(detail, "a site, an environment, an expression or a host list") {
		t.Errorf("the refusal does not say what to do: %q", detail)
	}
}

func TestCampaignScheduleRefusesAnEmptySelector(t *testing.T) {
	server := &Server{}
	recorder := httptest.NewRecorder()
	body := `{
		"name": "nightly restart", "start_at": "2099-01-01T02:00:00Z",
		"timezone": "UTC", "reason": "CHG-1001: a schedule that names nobody",
		"order": {"name": "restart the world", "action": "unit.restart",
			"payload": {"unit": {"unit": "cron.service"}}, "selector": {}}
	}`
	if _, ok := server.readScheduleSpec(recorder, asOperator(http.MethodPost, "/api/v1/campaign-schedules", body)); ok {
		t.Fatal("a schedule whose order names nobody was accepted")
	}

	status, code, detail := refusalOf(t, recorder)
	if status != http.StatusBadRequest || code != "selector_required" {
		t.Fatalf("the schedule answered %d %s: %s", status, code, detail)
	}
}

// The preview is the one place an empty selector stays a fair question: it
// changes nothing, it is how the panel asks "how many hosts would this
// operation be ready on", and the order refuses that selector whatever the
// preview showed. So the guard must not reach it.
func TestCampaignPreviewDoesNotRefuseAnEmptySelector(t *testing.T) {
	server := &Server{}
	recorder := httptest.NewRecorder()
	// A unit test has no fleet store, so the count itself cannot be made here;
	// only what the preview must not answer is asserted.
	func() {
		defer func() { _ = recover() }()
		server.handleCampaignPreview(recorder, asOperator(http.MethodGet, "/api/v1/campaigns/preview", ""))
	}()
	if strings.Contains(recorder.Body.String(), "selector_required") {
		t.Errorf("the preview refused the count it exists to answer: %s", recorder.Body.String())
	}
}

// A selector that narrows something passes, so the refusal did not become a
// ban on ordering campaigns.
func TestRequireSelectorPassesEverySelectorThatNarrowsSomething(t *testing.T) {
	for name, chosen := range map[string]campaigns.Selector{
		"a site":         {Site: "lab"},
		"an environment": {Environment: "test"},
		"an OS family":   {OSFamily: "debian"},
		"a host list":    {HostIDs: []string{"11111111-0000-4000-8000-00000000000a"}},
		"an expression":  {Expression: &selector.Expression{Tag: "role=web"}},
	} {
		t.Run(name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			if !requireSelector(recorder, chosen) {
				t.Fatalf("a selector naming %s was refused: %s", name, recorder.Body.String())
			}
			if recorder.Body.Len() != 0 {
				t.Errorf("an accepted selector wrote an answer: %s", recorder.Body.String())
			}
		})
	}
}

// The refusal is honest about which case it caught: an expression that is
// present and names no condition is a malformed expression, not an absent one,
// and it keeps its own code.
func TestAPresentExpressionThatNamesNoConditionIsNotTheEmptySelector(t *testing.T) {
	server := &Server{}
	recorder := httptest.NewRecorder()
	chosen := campaigns.Selector{Expression: &selector.Expression{}}
	if chosen.Empty() {
		t.Fatal("a selector carrying an expression reads as empty")
	}
	if _, ok := server.checkSelector(recorder, chosen); ok {
		t.Fatal("an expression naming no condition passed the selector check")
	}
	status, code, detail := refusalOf(t, recorder)
	if status != http.StatusBadRequest || code != "invalid_selector" {
		t.Fatalf("an expression naming no condition answered %d %s: %s", status, code, detail)
	}
}

// A campaign ordered over a selector that resolves to nobody keeps its own
// refusal too: the guard above does not swallow it.
func TestRequireSelectorRefusesOnlyTheAbsentSelector(t *testing.T) {
	recorder := httptest.NewRecorder()
	// An exclusion list is not a selector: it says who stays out of a set
	// nobody named.
	if requireSelector(recorder, campaigns.Selector{
		Exclude: []string{"11111111-0000-4000-8000-00000000000a"}, ExcludeReason: "the primary",
	}) {
		t.Fatal("exclusions alone were taken for a selector")
	}
	if _, code, _ := refusalOf(t, recorder); code != "selector_required" {
		t.Errorf("exclusions alone answered %s", code)
	}
}
