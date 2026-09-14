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
	"github.com/ultherego/flotestro/internal/campaigns"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/jobs"
	"github.com/ultherego/flotestro/internal/opspec"
)

// The contract of the public API.
//
// The document requires a REST/JSON API with an OpenAPI contract, so that
// a CMDB, a ticketing system or a pipeline can be built against it without
// reading the panel's source. The contract is generated from the same
// table the router is built from: a route that exists is in the contract,
// and a route in the contract exists. The schemas of the main resources
// come from the Go types by reflection, for the same reason - a schema
// written by hand next to the type would drift from it.

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
	register("Job", jobs.Job{})
	register("Attempt", jobs.Attempt{})
	register("Campaign", campaigns.Campaign{})
	register("CampaignTarget", campaigns.Target{})
	register("TimelineEntry", campaigns.Event{})
	register("CampaignStep", campaigns.Step{})
	register("AuditEvent", audit.Event{})
	register("Payload", opspec.Payload{})
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
		if !strings.HasPrefix(route.Path, "/api/") && route.Path != "/healthz" && route.Path != "/metrics" {
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
	if route.Method == http.MethodGet && route.Path == "/api/v1/campaigns/{id}/report" {
		params = append(params, map[string]any{
			"name": "format", "in": "query", "required": false,
			"schema":      map[string]any{"type": "string", "enum": []string{"json", "csv"}},
			"description": "The shape of the report: the JSON summary by default, or a CSV file with one row per target.",
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
	} else if route.Path == "/api/v1/campaigns/{id}/report" {
		responses[status] = map[string]any{"description": "The report: a JSON summary, or with format=csv a file with one row per target.",
			"content": map[string]any{
				"application/json": map[string]any{"schema": map[string]any{"type": "object"}},
				"text/csv":         map[string]any{"schema": map[string]any{"type": "string"}},
			}}
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
	op["responses"] = responses
	if route.Method == http.MethodPost || route.Method == http.MethodPut {
		body := map[string]any{"type": "object"}
		if schema, ok := requestSchemas[route.Method+" "+route.Path]; ok {
			body = schema
		}
		op["requestBody"] = map[string]any{"content": map[string]any{"application/json": map[string]any{"schema": body}}}
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

// The query parameters of the lists. A list filters on the server, so its
// filters are part of the contract: a CMDB asking for the hosts of one
// owner must not have to fetch the fleet and filter it itself.
var queryParameters = map[string][]queryParameter{
	"GET /api/v1/hosts": append([]queryParameter{
		{"q", "string", "A fragment of the hostname, the management address, the machine identifier or the owner; case-insensitive."},
		{"site", "string", ""},
		{"environment", "string", ""},
		{"os_family", "string", ""},
		{"connection_state", "string", "online, offline, stale or unknown."},
		{"lifecycle_state", "string", "active, quarantined, recovery, retiring or retired."},
		{"owner", "string", ""},
		{"maintenance", "boolean", "true keeps the hosts inside a maintenance window now, false those outside one."},
		{"capability", "string", "An adapter the host must have available, such as packages.apt."},
	}, pagingParameters...),
	"GET /api/v1/jobs": append([]queryParameter{
		{"host_id", "string", ""},
		{"state", "string", ""},
		{"action", "string", "The operation type."},
		{"actor", "string", "The identity that ordered the task."},
		{"campaign_id", "string", ""},
		{"error_code", "string", "The result error code the task ended with."},
		{"since", "string", "RFC 3339; tasks created at or after this moment."},
		{"until", "string", "RFC 3339; tasks created before this moment."},
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
	"GET /api/v1/campaigns/preview": {
		{"action", "string", "The operation type; without it the preview counts hosts and qualifies none."},
		{"site", "string", ""},
		{"environment", "string", ""},
		{"os_family", "string", ""},
		{"expression", "string", "The typed selector as JSON; when present it decides alone."},
		{"exclude", "string", "A host identifier to leave out; may repeat."},
		{"exclude_reason", "string", ""},
		{"compensates", "string", "The campaign the order would undo; an empty selector then names the hosts that campaign changed, and the answer carries the original under compensates."},
	},
	"GET /api/v1/campaigns/{id}/steps": {
		{"host_id", "string", "Only the steps of this host."},
		{"limit", "integer", "How many hosts one page covers: 200 by default, 1000 at most; a page is cut between hosts, never inside one."},
		{"cursor", "string", "The next_cursor of the previous page; empty for the first page."},
	},
	"GET /api/v1/monitoring/alerts": {
		{"state", "string", "pending, firing or resolved."},
		{"severity", "string", "critical, warning or info."},
		{"host_id", "string", ""},
		{"limit", "integer", "The most alerts to return: 100 by default, 500 at most."},
	},
	"GET /api/v1/audit": append([]queryParameter{
		{"target_id", "string", ""},
		{"target_type", "string", ""},
		{"actor", "string", "The identity that acted."},
		{"action", "string", ""},
		{"outcome", "string", "success, failure or denied."},
		{"since", "string", "RFC 3339; events at or after this moment."},
		{"until", "string", "RFC 3339; events before this moment."},
	}, pagingParameters...),
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
	"GET /api/v1/hosts":                   pagedCollection("Host"),
	"GET /api/v1/hosts/{id}":              ref("Host"),
	"GET /api/v1/jobs":                    cursorCollection("Job"),
	"GET /api/v1/jobs/{id}":               ref("Job"),
	"POST /api/v1/jobs/{id}/approve":      ref("Job"),
	"POST /api/v1/jobs/{id}/cancel":       ref("Job"),
	"GET /api/v1/jobs/{id}/attempts":      collection("Attempt"),
	"POST /api/v1/hosts/{id}/operations":  ref("Job"),
	"GET /api/v1/campaigns":               collection("Campaign"),
	"POST /api/v1/campaigns":              ref("Campaign"),
	"GET /api/v1/campaigns/{id}":          ref("Campaign"),
	"POST /api/v1/campaigns/{id}/approve": ref("Campaign"),
	"POST /api/v1/campaigns/{id}/pause":   ref("Campaign"),
	"POST /api/v1/campaigns/{id}/resume":  ref("Campaign"),
	"POST /api/v1/campaigns/{id}/cancel":  ref("Campaign"),
	"GET /api/v1/campaigns/{id}/targets":  pagedCollection("CampaignTarget"),
	"GET /api/v1/campaigns/{id}/timeline": collection("TimelineEntry"),
	"GET /api/v1/campaigns/{id}/steps":    cursorCollection("CampaignStep"),
	"GET /api/v1/audit":                   cursorCollection("AuditEvent"),
	"GET /api/v1/hosts/{id}/audit":        collection("AuditEvent"),
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

var requestSchemas = map[string]map[string]any{
	"POST /api/v1/hosts/{id}/operations": {
		"type": "object",
		"properties": map[string]any{
			"action":              map[string]any{"type": "string", "description": "The operation type from GET /api/v1/actions."},
			"payload":             ref("Payload"),
			"reason":              map[string]any{"type": "string"},
			"target_confirmation": map[string]any{"type": "string", "description": "The hostname, typed, for irreversible operations."},
			"idempotency_key":     map[string]any{"type": "string"},
		},
		"required": []string{"action"},
	},
	"POST /api/v1/campaigns": {
		"type": "object",
		"properties": map[string]any{
			"name":                       map[string]any{"type": "string"},
			"action":                     map[string]any{"type": "string"},
			"payload":                    ref("Payload"),
			"reason":                     map[string]any{"type": "string"},
			"selector":                   map[string]any{"type": "object"},
			"canary_size":                map[string]any{"type": "integer"},
			"wave_size":                  map[string]any{"type": "integer"},
			"max_concurrent":             map[string]any{"type": "integer"},
			"failure_threshold_percent":  map[string]any{"type": "integer"},
			"failure_threshold_absolute": map[string]any{"type": "integer"},
			"reboot_policy":              map[string]any{"type": "string", "enum": []string{"never", "if_required", "always"}},
			"compensates_campaign_id": map[string]any{"type": "string",
				"description": "A finished campaign this one undoes. The operation has to be the declared reverse of that campaign's " +
					"and the targets hosts it changed; an empty selector takes exactly those hosts. The original is linked, never rewritten. " +
					"Refusals: compensated_campaign_not_found, compensated_campaign_not_settled, not_reverse_operation, " +
					"nothing_to_compensate, compensation_target_unchanged."},
		},
		"required": []string{"name", "action", "selector"},
	},
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

// schemaOf describes a Go type as a JSON schema, following the json tags
// the way the encoder does.
func schemaOf(t reflect.Type, schemas map[string]any) map[string]any {
	switch {
	case t == reflect.TypeOf(time.Time{}):
		return map[string]any{"type": "string", "format": "date-time"}
	case t == reflect.TypeOf(json.RawMessage{}):
		return map[string]any{"description": "Free-form JSON."}
	}
	switch t.Kind() {
	case reflect.Pointer:
		return schemaOf(t.Elem(), schemas)
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
		return map[string]any{"type": "array", "items": schemaOf(t.Elem(), schemas)}
	case reflect.Map:
		return map[string]any{"type": "object", "additionalProperties": schemaOf(t.Elem(), schemas)}
	case reflect.Struct:
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
					for k, v := range schemaOf(field.Type, schemas)["properties"].(map[string]any) {
						properties[k] = v
					}
					continue
				}
				name = field.Name
			}
			properties[name] = schemaOf(field.Type, schemas)
			if !strings.Contains(options, "omitempty") && field.Type.Kind() != reflect.Pointer {
				required = append(required, name)
			}
		}
		schema := map[string]any{"type": "object", "properties": properties}
		if len(required) > 0 {
			sort.Strings(required)
			schema["required"] = required
		}
		return schema
	case reflect.Interface:
		return map[string]any{}
	}
	return map[string]any{}
}
