package adminapi

import (
	"encoding/json"
	"strings"
	"testing"
)

// An operation's payload is grouped by name: {"unit":{"unit":"cron.service"}}.
// A caller who sends the fields unwrapped - {"unit":"cron.service"} - has
// written valid JSON of the wrong shape, and all three endpoints that take a
// payload answered "the payload is not valid JSON". That sends them hunting for
// a missing quote in a body that has none, and it is the one answer on the way
// to the validator that pointed at the wrong thing: the validator itself says
// "the operation unit.restart requires a unit payload".
func TestAPayloadOfTheWrongShapeIsNotCalledInvalidJSON(t *testing.T) {
	_, err := decodePayload(json.RawMessage(`{"unit":"cron.service"}`))
	if err == nil {
		t.Fatal("a payload whose group is a string was accepted")
	}
	said := err.Error()
	if strings.Contains(said, "not valid JSON") {
		t.Errorf("valid JSON of the wrong shape was called invalid JSON:\n%s", said)
	}
	// And it says enough to act on: which field, and that the groups are
	// discoverable without reading the source.
	for _, want := range []string{`"unit"`, "grouped by name", "components.schemas.Payload"} {
		if !strings.Contains(said, want) {
			t.Errorf("the refusal does not mention %s:\n%s", want, said)
		}
	}

	// Broken JSON is still broken JSON, and still says so.
	_, err = decodePayload(json.RawMessage(`{"unit":{`))
	if err == nil || !strings.Contains(err.Error(), "not valid JSON") {
		t.Errorf("a truncated body was not reported as invalid JSON: %v", err)
	}

	// A payload that fits is returned, and an absent one is not an error: an
	// operation whose payload is empty is ordinary.
	payload, err := decodePayload(json.RawMessage(`{"unit":{"unit":"cron.service"}}`))
	if err != nil {
		t.Fatalf("the grouped payload was refused: %v", err)
	}
	if payload.Unit == nil || payload.Unit.Unit != "cron.service" {
		t.Errorf("the payload did not survive the decode: %+v", payload.Unit)
	}
	if _, err := decodePayload(nil); err != nil {
		t.Errorf("an order with no payload was refused: %v", err)
	}
}

// The group named in the refusal is the group to wrap, including when the
// decoder reports a nested path.
func TestTheRefusalNamesTheGroupToWrap(t *testing.T) {
	for field, want := range map[string]string{
		"unit":              "unit",
		"package_plan.only": "package_plan",
		"":                  "",
	} {
		if got := payloadGroup(field); got != want {
			t.Errorf("payloadGroup(%q) = %q, want %q", field, got, want)
		}
	}
}
