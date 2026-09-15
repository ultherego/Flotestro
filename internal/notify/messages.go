package notify

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/outbox"
)

// payload is the union of what the triggers put in an event: every field
// a message may read, each empty when the event does not carry it.
type payload struct {
	RuleName        string   `json:"rule_name"`
	Metric          string   `json:"metric"`
	Severity        string   `json:"severity"`
	HostID          string   `json:"host_id"`
	Hostname        string   `json:"hostname"`
	Value           *float64 `json:"value"`
	Detail          string   `json:"detail"`
	Name            string   `json:"name"`
	ActionType      string   `json:"action_type"`
	PauseReason     string   `json:"pause_reason"`
	CampaignID      string   `json:"campaign_id"`
	CreatedBy       string   `json:"created_by"`
	Site            string   `json:"site"`
	Environment     string   `json:"environment"`
	OSFamily        string   `json:"os_family"`
	ConnectionState string   `json:"connection_state"`
	PolicyName      string   `json:"policy_name"`
	Version         *int     `json:"version"`
	RuleIndex       *int     `json:"rule_index"`
	Reason          string   `json:"reason"`
}

// Compose turns an event of the trail into the words a channel carries.
// The scope is what the event says about where it happened; the router
// fills the site and the environment of a host the payload does not name
// before matching the filters. The second result is false for an event
// no channel carries.
func Compose(event outbox.Event, publicURL string) (Message, bool) {
	subject, ok := SubjectOf(event.Type)
	if !ok {
		return Message{}, false
	}
	var fields payload
	_ = json.Unmarshal(event.Payload, &fields)
	message := Message{
		Subject: subject, EventID: event.ID, EventType: event.Type,
		Aggregate: event.Aggregate, AggregateID: event.AggregateID,
		Payload: event.Payload, OccurredAt: event.OccurredAt,
	}
	host := fields.Hostname
	if host == "" && fields.HostID != "" {
		host = fields.HostID
	}
	link := func(path string) string {
		if publicURL == "" {
			return ""
		}
		return strings.TrimRight(publicURL, "/") + path
	}
	switch subject {
	case "alert.fired":
		message.Severity = fields.Severity
		message.Title = fmt.Sprintf("[%s] %s on %s", fields.Severity, fields.RuleName, host)
		message.Text = alertText(fields)
		message.Link = link("/hosts/" + fields.HostID + "/monitoring")
	case "alert.resolved":
		message.Severity = fields.Severity
		message.Title = fmt.Sprintf("Resolved: %s on %s", fields.RuleName, host)
		message.Text = alertText(fields)
		message.Link = link("/hosts/" + fields.HostID + "/monitoring")
	case "campaign.finished":
		state := strings.TrimPrefix(event.Type, "campaign.")
		message.Title = fmt.Sprintf("Campaign %s %s", fields.Name, strings.ReplaceAll(state, "_", " "))
		message.Text = fmt.Sprintf("operation: %s", fields.ActionType)
		if fields.PauseReason != "" {
			message.Text += "\n" + fields.PauseReason
		}
		message.Link = link("/campaigns/" + event.AggregateID)
	case "campaign.awaiting_approval":
		message.Title = fmt.Sprintf("Campaign %s waits for approval", fields.Name)
		message.Text = fmt.Sprintf("operation: %s", fields.ActionType)
		message.Link = link("/campaigns/" + event.AggregateID)
	case "job.awaiting_approval":
		message.Title = fmt.Sprintf("Task %s on %s waits for approval", fields.ActionType, host)
		message.Text = fmt.Sprintf("ordered by %s", fields.CreatedBy)
		message.Link = link("/jobs/" + event.AggregateID)
	case "enrollment.completed":
		message.Title = fmt.Sprintf("Host %s enrolled", host)
		message.Text = fmt.Sprintf("site %s, environment %s", fields.Site, fields.Environment)
		if fields.OSFamily != "" {
			message.Text += ", " + fields.OSFamily
		}
		message.Link = link("/hosts/" + event.AggregateID)
	case "host.offline":
		message.Title = fmt.Sprintf("Host %s stopped answering", host)
		message.Text = fmt.Sprintf("connection %s; site %s, environment %s", fields.ConnectionState, fields.Site, fields.Environment)
		message.Link = link("/hosts/" + event.AggregateID)
	case "policy.drift":
		message.Title = fmt.Sprintf("Policy %s: drift on %s", fields.PolicyName, host)
		if fields.RuleIndex != nil {
			message.Text = fmt.Sprintf("rule %d", *fields.RuleIndex+1)
		}
		if fields.Reason != "" {
			if message.Text != "" {
				message.Text += ": "
			}
			message.Text += fields.Reason
		}
		message.Link = link("/policies/" + event.AggregateID)
	}
	return message, true
}

func alertText(fields payload) string {
	text := fields.Metric
	if fields.Value != nil {
		text += fmt.Sprintf(" = %g", *fields.Value)
	}
	if fields.Detail != "" {
		text += "\n" + fields.Detail
	}
	return text
}

// ScopeHint is what the payload alone says about the scope: the site and
// the environment when the trigger wrote them, the host to look up when
// it did not, and the severity of an alert.
func ScopeHint(event outbox.Event) (scope Scope, hostID string) {
	var fields payload
	_ = json.Unmarshal(event.Payload, &fields)
	scope = Scope{Site: fields.Site, Environment: fields.Environment, Severity: fields.Severity}
	hostID = fields.HostID
	if hostID == "" && event.Aggregate == "host" {
		hostID = event.AggregateID
	}
	return scope, hostID
}

// TestMessage is what the test button sends: a sentence that says which
// channel it is and when it was pressed, so a receiver that shows it is
// known to be the right one.
func TestMessage(channel Channel, now time.Time) Message {
	return Message{
		Subject:    "test",
		EventType:  "test",
		Title:      fmt.Sprintf("Test message from Flotestro for the channel %s", channel.Name),
		Text:       "If you read this, the channel reaches its receiver. Sent " + now.UTC().Format(time.RFC3339) + ".",
		OccurredAt: now,
	}
}
