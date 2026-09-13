package docker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Event is one event of the container engine log.
//
// An event answers the question "what happened here", it is not the host
// state: it does not go into the inventory and does not replace a state
// read. A container killed by the OOM killer looks in the inventory the
// same as a container stopped by hand - the difference is only here.
type Event struct {
	Time time.Time `json:"time"`
	// Type is the object kind: container, image, network, volume.
	Type string `json:"type"`
	// Action is what happened to it: start, die, destroy, pull.
	Action    string `json:"action"`
	ActorID   string `json:"actor_id,omitempty"`
	ActorName string `json:"actor_name,omitempty"`
	// Attributes carries selected event attributes. The engine also puts
	// all the container labels there, so the list is narrowed: the event
	// log is not a place for a secret to leak from a label.
	Attributes map[string]string `json:"attributes,omitempty"`
}

// EventsSnapshot is the result of one log read.
type EventsSnapshot struct {
	Events []Event `json:"events"`
	// Since and Until describe the window that was really read. Without
	// them an empty list says nothing: silence in the window and no read
	// look the same.
	Since time.Time `json:"since"`
	Until time.Time `json:"until"`
	Types []string  `json:"types,omitempty"`
	// Truncated marks a read cut off by a limit. A cut-off list without
	// this marker would look complete - and the operator would draw
	// conclusions from a log they did not see in full.
	Truncated bool   `json:"truncated"`
	Reason    string `json:"truncated_reason,omitempty"`
}

// EventsOptions describes a closed read window.
type EventsOptions struct {
	Since  time.Duration
	Follow time.Duration
	Types  []string
	Max    int
}

// Log read bounds. They are here, not only in the panel, because it is the
// host that pays for the read: a request without an end would stay on it
// forever.
const (
	// MaxEventsWindow bounds the look back.
	MaxEventsWindow = 24 * time.Hour
	// MaxEventsFollow bounds the wait for future events.
	MaxEventsFollow = 60 * time.Second
	// MaxEvents bounds the number of returned events.
	MaxEvents = 1000
	// MaxEventsSize bounds the read size. A host on which something comes
	// up in a loop can produce thousands of events a minute.
	MaxEventsSize       = 256 << 10
	defaultEvents       = 200
	defaultEventsWindow = time.Hour
)

// EventTypes lists the object kinds that may be asked about.
//
// The list is closed, because the filter goes to the Engine API. The
// engine also knows daemon and plugin events - those answer no question of
// the operator of this tab.
var EventTypes = []string{"container", "image", "network", "volume"}

// KnownEventType says whether the name is a known kind.
func KnownEventType(name string) bool {
	for _, kind := range EventTypes {
		if kind == name {
			return true
		}
	}
	return false
}

// eventAttributes lists the attributes that make it into the result.
//
// The engine puts all the object's labels into the event. Labels are at
// times the place somebody wrote a token into - the event log is not a
// place for it to leak, so the list is closed.
var eventAttributes = []string{
	"image", "exitCode", "signal", "container", "name",
	"com.docker.compose.project", "com.docker.compose.service",
}

// Events reads the engine event log in a closed time window.
//
// The window is closed on both sides: until is computed at the start, not
// left open. Thanks to that the read ends on its own, also when the panel
// stopped listening.
func Events(ctx context.Context, client *Client, opts EventsOptions) (EventsSnapshot, error) {
	if client == nil {
		return EventsSnapshot{}, fmt.Errorf("%w: no engine adapter", ErrUnavailable)
	}
	opts = boundOptions(opts)

	now := time.Now()
	snapshot := EventsSnapshot{
		Since: now.Add(-opts.Since).UTC(),
		Until: now.Add(opts.Follow).UTC(),
		Types: opts.Types,
	}

	query := url.Values{}
	query.Set("since", strconv.FormatInt(snapshot.Since.Unix(), 10))
	query.Set("until", strconv.FormatInt(snapshot.Until.Unix(), 10))
	if len(opts.Types) > 0 {
		filter := map[string][]string{"type": opts.Types}
		encoded, err := json.Marshal(filter)
		if err != nil {
			return snapshot, err
		}
		query.Set("filters", string(encoded))
	}

	// The read has its own time limit, independent of the task context: an
	// engine that does not close the stream must not stop the agent.
	limit := opts.Follow + 30*time.Second
	readCtx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()

	err := client.stream(readCtx, "/events", query, func(line []byte) bool {
		event, ok := eventFromLine(line)
		if !ok {
			return true
		}
		snapshot.Events = append(snapshot.Events, event)
		if len(snapshot.Events) >= opts.Max {
			snapshot.Truncated = true
			snapshot.Reason = fmt.Sprintf("the limit of %d events was reached", opts.Max)
			return false
		}
		return true
	}, MaxEventsSize)
	switch {
	case err == nil:
	case errors.Is(err, errSizeLimit):
		// A cut-off by the size limit is not a read error: the operator
		// gets what fit within the limit and knows the rest was left.
		snapshot.Truncated = true
		snapshot.Reason = fmt.Sprintf("the read limit of %d bytes was reached",
			MaxEventsSize)
	case errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil:
		// The end of the window is a normal end of the read, not a failure:
		// the engine keeps the stream open until until and sometimes does
		// not close it itself.
	default:
		return snapshot, err
	}

	sort.SliceStable(snapshot.Events, func(i, j int) bool {
		return snapshot.Events[i].Time.Before(snapshot.Events[j].Time)
	})
	return snapshot, nil
}

// boundOptions brings the order within the limits the host can carry.
func boundOptions(opts EventsOptions) EventsOptions {
	if opts.Since <= 0 {
		opts.Since = defaultEventsWindow
	}
	if opts.Since > MaxEventsWindow {
		opts.Since = MaxEventsWindow
	}
	if opts.Follow < 0 {
		opts.Follow = 0
	}
	if opts.Follow > MaxEventsFollow {
		opts.Follow = MaxEventsFollow
	}
	if opts.Max <= 0 {
		opts.Max = defaultEvents
	}
	if opts.Max > MaxEvents {
		opts.Max = MaxEvents
	}
	selected := make([]string, 0, len(opts.Types))
	for _, kind := range opts.Types {
		kind = strings.ToLower(strings.TrimSpace(kind))
		if KnownEventType(kind) && !contains(selected, kind) {
			selected = append(selected, kind)
		}
	}
	if len(selected) == 0 {
		// No filter means the four kinds, not "everything the engine has":
		// daemon and plugin events answer no question of the operator.
		selected = append(selected, EventTypes...)
	}
	sort.Strings(selected)
	opts.Types = selected
	return opts
}

// eventFromLine translates one stream line into an event.
func eventFromLine(line []byte) (Event, bool) {
	var raw struct {
		Type   string `json:"Type"`
		Action string `json:"Action"`
		Actor  struct {
			ID         string            `json:"ID"`
			Attributes map[string]string `json:"Attributes"`
		} `json:"Actor"`
		Time     int64 `json:"time"`
		TimeNano int64 `json:"timeNano"`
	}
	if err := json.Unmarshal(line, &raw); err != nil || raw.Type == "" {
		return Event{}, false
	}
	event := Event{
		Type: raw.Type, Action: raw.Action, ActorID: raw.Actor.ID,
		ActorName: raw.Actor.Attributes["name"],
	}
	switch {
	case raw.TimeNano > 0:
		event.Time = time.Unix(0, raw.TimeNano).UTC()
	case raw.Time > 0:
		event.Time = time.Unix(raw.Time, 0).UTC()
	}
	for _, name := range eventAttributes {
		if value, ok := raw.Actor.Attributes[name]; ok && value != "" {
			if event.Attributes == nil {
				event.Attributes = map[string]string{}
			}
			event.Attributes[name] = value
		}
	}
	return event, true
}
