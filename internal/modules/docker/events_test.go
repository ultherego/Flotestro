package docker

import (
	"testing"
	"time"
)

// TestReadWindowIsBounded guards the property that lets this operation
// exist at all: an order outside the bounds is trimmed, so the task always
// ends. A read without an end would stay on the host forever.
func TestReadWindowIsBounded(t *testing.T) {
	options := boundOptions(EventsOptions{
		Since:  7 * 24 * time.Hour,
		Follow: time.Hour,
		Max:    100000,
	})
	if options.Since != MaxEventsWindow {
		t.Errorf("look back window = %s", options.Since)
	}
	if options.Follow != MaxEventsFollow {
		t.Errorf("follow = %s", options.Follow)
	}
	if options.Max != MaxEvents {
		t.Errorf("event limit = %d", options.Max)
	}
}

// TestNoOrderGivesDefaultWindow guards that the most common path - "show
// what happened here" - requires nothing from the operator, and is bounded
// nevertheless.
func TestNoOrderGivesDefaultWindow(t *testing.T) {
	options := boundOptions(EventsOptions{})
	if options.Since != defaultEventsWindow {
		t.Errorf("default window = %s", options.Since)
	}
	if options.Follow != 0 {
		t.Errorf("default follow = %s, and the task is meant to end at once", options.Follow)
	}
	if options.Max != defaultEvents {
		t.Errorf("default limit = %d", options.Max)
	}
	if len(options.Types) != len(EventTypes) {
		t.Errorf("default kinds = %v", options.Types)
	}
}

// TestUnknownKindsAreSkipped guards the filter boundary: the kind goes to
// the Engine API, so the list is closed. Daemon and plugin events answer no
// question of this tab.
func TestUnknownKindsAreSkipped(t *testing.T) {
	options := boundOptions(EventsOptions{Types: []string{"daemon", "plugin", "Container", "container"}})
	if len(options.Types) != 1 || options.Types[0] != "container" {
		t.Fatalf("kinds = %v", options.Types)
	}
}

// TestEventCarriesOnlySelectedAttributes guards that the event log does not
// become a leak path: the engine attaches all the object's labels to the
// event, and a label sometimes holds a token.
func TestEventCarriesOnlySelectedAttributes(t *testing.T) {
	line := []byte(`{"Type":"container","Action":"die","Actor":{"ID":"abc123",
		"Attributes":{"name":"shop-web-1","image":"nginx:alpine","exitCode":"137",
		"api_token":"secret-that-must-not-leave",
		"com.docker.compose.project":"shop"}},"timeNano":1700000000000000000}`)

	event, ok := eventFromLine(line)
	if !ok {
		t.Fatal("event not read")
	}
	if event.Type != "container" || event.Action != "die" {
		t.Fatalf("event = %+v", event)
	}
	if event.ActorName != "shop-web-1" {
		t.Errorf("actor name = %q", event.ActorName)
	}
	if event.Attributes["exitCode"] != "137" {
		t.Errorf("exit code = %q", event.Attributes["exitCode"])
	}
	if _, present := event.Attributes["api_token"]; present {
		t.Error("the event would carry out a label outside the list")
	}
	if event.Time.IsZero() {
		t.Error("event without a time")
	}
}

// TestEventWithoutKindIsSkipped guards that a line that cannot be
// understood does not become an empty entry in the log.
func TestEventWithoutKindIsSkipped(t *testing.T) {
	for _, line := range []string{"", "{}", "not-json", `{"Action":"die"}`} {
		if _, ok := eventFromLine([]byte(line)); ok {
			t.Errorf("line %q taken for an event", line)
		}
	}
}
