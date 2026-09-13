package adminapi

import (
	"encoding/json"
	"net/http"
	"reflect"
	"testing"

	"github.com/ultherego/flotestro/internal/jobs"
)

// The contract is generated from the route table, so a route cannot exist
// outside it. What can go wrong is the shape: the document must be valid
// JSON with a path for every recorded API route, parameters for every path
// placeholder and a schema for every resource the responses point at.
func TestOpenAPICoversEveryRoute(t *testing.T) {
	s := &Server{}
	mux := http.NewServeMux()
	handler := func(http.ResponseWriter, *http.Request) {}
	for _, pattern := range []string{
		"GET /api/v1/hosts", "GET /api/v1/hosts/{id}", "POST /api/v1/hosts/{id}/operations",
		"GET /api/v1/campaigns/{id}/targets", "PUT /api/v1/budgets/{key...}", "GET /auth/login",
	} {
		s.route(mux, pattern, handler)
	}
	document := s.openAPI()
	if _, err := json.Marshal(document); err != nil {
		t.Fatalf("the document is not JSON: %v", err)
	}
	paths := document["paths"].(map[string]map[string]any)
	for _, path := range []string{"/api/v1/hosts", "/api/v1/hosts/{id}", "/api/v1/budgets/{key}"} {
		if paths[path] == nil {
			t.Errorf("the contract lacks %s", path)
		}
	}
	if paths["/auth/login"] != nil {
		t.Error("the browser login flow leaked into the contract")
	}
	op := paths["/api/v1/hosts/{id}/operations"]["post"].(map[string]any)
	if params := op["parameters"].([]map[string]any); len(params) != 2 || params[0]["name"] != "Idempotency-Key" || params[1]["name"] != "id" {
		t.Errorf("the operation has parameters %+v", params)
	}
	if op["requestBody"] == nil {
		t.Error("creating an operation has no request body")
	}
	responses := op["responses"].(map[string]any)
	if responses["201"] == nil || responses["default"] == nil {
		t.Errorf("the operation has responses %v", responses)
	}

	// Every $ref points at a schema the document carries.
	schemas := document["components"].(map[string]any)["schemas"].(map[string]any)
	var walk func(value any)
	walk = func(value any) {
		switch v := value.(type) {
		case map[string]any:
			if ref, ok := v["$ref"].(string); ok {
				if schemas[ref[len("#/components/schemas/"):]] == nil {
					t.Errorf("dangling reference %s", ref)
				}
			}
			for _, child := range v {
				walk(child)
			}
		case map[string]map[string]any:
			for _, child := range v {
				walk(child)
			}
		case []map[string]any:
			for _, child := range v {
				walk(child)
			}
		case []any:
			for _, child := range v {
				walk(child)
			}
		}
	}
	walk(document)
}

// The schema of a resource follows its json tags: the field names are the
// wire names, and time and raw JSON are described as what they are on the
// wire rather than as Go structs.
func TestSchemaFollowsTheJSONTags(t *testing.T) {
	schema := schemaOf(reflect.TypeOf(jobs.Job{}), map[string]any{})
	properties := schema["properties"].(map[string]any)
	for _, name := range []string{"id", "host_id", "action_type", "state", "created_at"} {
		if properties[name] == nil {
			t.Errorf("the Job schema lacks %s: %v", name, properties)
		}
	}
	if properties["created_at"].(map[string]any)["format"] != "date-time" {
		t.Errorf("created_at is %v", properties["created_at"])
	}
	if summary := summaryOf(apiRoute{Handler: "ListHosts"}); summary != "List hosts" {
		t.Errorf("summary = %q", summary)
	}
	if summary := summaryOf(apiRoute{Handler: "PKIStatus"}); summary != "PKI status" {
		t.Errorf("summary = %q", summary)
	}
}
