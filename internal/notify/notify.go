// Package notify carries what the fleet says to the people who are not
// looking at the panel.
//
// The durable trail already records every state change; the outbox
// delivers it to one webhook set in the environment. A channel is the
// same idea made a record of the panel: an address, the subjects it
// carries and the part of the fleet it speaks for, written by an
// administrator with a reason. The router is one more consumer of the
// trail, with a cursor of its own, so the legacy webhook and the channels
// move independently and neither holds the other back.
//
// Two rules hold throughout. A mail password never lies in a channel: the
// configuration names a secret of the secret store and the sender reads
// it when it sends. And a receiver that is down is a fact the panel
// records in the delivery log, never a reason to stop the trail: the
// router moves on after its attempts, and the log says what did not
// arrive.
package notify

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// The kinds of channel.
const (
	KindWebhook      = "webhook"
	KindEmail        = "email"
	KindSlackWebhook = "slack_webhook"
)

// Kinds lists the kinds a channel can be of.
var Kinds = []string{KindWebhook, KindEmail, KindSlackWebhook}

// Subject is one thing a channel can be told about. It is coarser than
// an event of the trail: campaign.finished stands for every terminal
// state of a campaign, so an operator subscribes to "the campaign ended"
// without listing six states.
type Subject struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// Subjects is the catalogue of what a channel can carry.
var Subjects = []Subject{
	{Name: "alert.fired", Description: "an alert rule fired on a host"},
	{Name: "alert.resolved", Description: "a firing alert ended"},
	{Name: "campaign.finished", Description: "a campaign reached its end: completed, with issues, failed, expired or canceled"},
	{Name: "campaign.awaiting_approval", Description: "a campaign waits for its approval"},
	{Name: "job.awaiting_approval", Description: "a task on one host waits for its approval"},
	{Name: "enrollment.completed", Description: "a host completed its enrollment"},
	{Name: "host.offline", Description: "a host that was online stopped answering"},
	{Name: "policy.drift", Description: "a policy found a rule out of its declared state on a host"},
}

// subjectOfEvent maps a type of the trail to the subject it belongs to.
// The terminal campaign states are the ones campaigns_state_check names
// as ends; the rest of the campaign states are phases, not news.
var subjectOfEvent = map[string]string{
	"alert.fired":                    "alert.fired",
	"alert.resolved":                 "alert.resolved",
	"campaign.completed":             "campaign.finished",
	"campaign.completed_with_issues": "campaign.finished",
	"campaign.failed":                "campaign.finished",
	"campaign.plan_failed":           "campaign.finished",
	"campaign.expired":               "campaign.finished",
	"campaign.canceled":              "campaign.finished",
	"campaign.awaiting_approval":     "campaign.awaiting_approval",
	"job.awaiting_approval":          "job.awaiting_approval",
	"enrollment.completed":           "enrollment.completed",
	"host.offline":                   "host.offline",
	"policy.drift":                   "policy.drift",
}

// SubjectOf returns the subject an event of the trail belongs to, and
// false for an event no channel can carry.
func SubjectOf(eventType string) (string, bool) {
	subject, ok := subjectOfEvent[eventType]
	return subject, ok
}

// KnownSubject says whether a channel may subscribe to the name.
func KnownSubject(name string) bool {
	for _, subject := range Subjects {
		if subject.Name == name {
			return true
		}
	}
	return false
}

// Severities orders the alert severities from the least to the most
// serious, for the "at least" filter.
var Severities = []string{"info", "warning", "critical"}

func severityRank(severity string) int {
	for i, name := range Severities {
		if name == severity {
			return i
		}
	}
	return -1
}

// Filter narrows what a channel carries. Every set field holds at once.
type Filter struct {
	// SeverityMin is the least severity of an alert the channel carries;
	// events that are not alerts have no severity and pass.
	SeverityMin string `json:"severity_min,omitempty"`
	// Site and Environment narrow to the events of one part of the fleet.
	// An event that names no host - a campaign's end - passes: it is news
	// of the whole fleet, and a channel of one site is told of it rather
	// than left to find out.
	Site        string `json:"site,omitempty"`
	Environment string `json:"environment,omitempty"`
}

// Scope is what an event says about where it happened and how serious it
// is; empty fields are unknown.
type Scope struct {
	Site        string
	Environment string
	Severity    string
}

// Matches says whether an event of the scope passes the filter.
func (f Filter) Matches(scope Scope) bool {
	if f.SeverityMin != "" && scope.Severity != "" &&
		severityRank(scope.Severity) < severityRank(f.SeverityMin) {
		return false
	}
	if f.Site != "" && scope.Site != "" && scope.Site != f.Site {
		return false
	}
	if f.Environment != "" && scope.Environment != "" && scope.Environment != f.Environment {
		return false
	}
	return true
}

func (f Filter) validate() error {
	if f.SeverityMin != "" && severityRank(f.SeverityMin) < 0 {
		return Error{Code: "invalid_filter", Message: fmt.Sprintf("severity_min %q is not one of %s", f.SeverityMin, strings.Join(Severities, ", "))}
	}
	return nil
}

// Channel is one address the fleet reports to.
type Channel struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind"`
	// Config is the configuration of the kind with the secrets reduced to
	// "set": what the API shows. The store keeps the whole one.
	Config    json.RawMessage `json:"config"`
	Events    []string        `json:"events"`
	Filter    Filter          `json:"filter"`
	Enabled   bool            `json:"enabled"`
	CreatedBy string          `json:"created_by"`
	Reason    string          `json:"reason"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
	// LastDelivery is the newest row of the log, so the list says at a
	// glance whether the channel works.
	LastDelivery *Delivery `json:"last_delivery,omitempty"`
}

// Subscribes says whether the channel carries the subject.
func (c Channel) Subscribes(subject string) bool {
	for _, name := range c.Events {
		if name == subject {
			return true
		}
	}
	return false
}

// WebhookConfig is the address of a webhook of the installation's own.
// The deliveries are signed the way the legacy webhook signs them, so a
// receiver written for one reads the other.
type WebhookConfig struct {
	URL string `json:"url"`
	// Secret signs the deliveries; empty means unsigned, and the API says
	// so on the channel.
	Secret string `json:"secret,omitempty"`
	// SecretSet is what the API shows in place of the secret.
	SecretSet bool `json:"secret_set,omitempty"`
}

// EmailConfig is a mailbox reached over SMTP.
type EmailConfig struct {
	Host     string   `json:"host"`
	Port     int      `json:"port"`
	StartTLS bool     `json:"starttls"`
	From     string   `json:"from"`
	To       []string `json:"to"`
	Username string   `json:"username,omitempty"`
	// PasswordSecret names the secret of the store that holds the
	// password; the row never holds the password.
	PasswordSecret string `json:"password_secret,omitempty"`
}

// SlackConfig is an incoming webhook of Slack or of a service that reads
// its shape - Mattermost, Rocket.Chat, Discord's Slack endpoint.
type SlackConfig struct {
	URL string `json:"url"`
}

// Error is a refusal with a code the API answers with.
type Error struct {
	Code    string
	Message string
}

func (e Error) Error() string { return e.Message }

// ErrNotFound means there is no such channel.
var ErrNotFound = errors.New("there is no such notification channel")

// The bounds of a channel.
const (
	MaxName   = 120
	MaxReason = 2000
	// MaxRecipients bounds the mailbox list: a channel is a mailbox or a
	// small list, not a mailing tool.
	MaxRecipients = 20
)

var secretName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,62}$`)

// Validate checks a channel as it comes from the API and normalises it:
// trimmed strings, the event list without duplicates. It returns the
// configuration decoded for the kind.
func (c *Channel) Validate() (any, error) {
	c.Name = strings.TrimSpace(c.Name)
	if c.Name == "" {
		return nil, Error{Code: "invalid_channel", Message: "the channel needs a name"}
	}
	if len([]rune(c.Name)) > MaxName {
		return nil, Error{Code: "invalid_channel", Message: fmt.Sprintf("the name is longer than %d characters", MaxName)}
	}
	if len([]rune(c.Reason)) > MaxReason {
		return nil, Error{Code: "invalid_channel", Message: fmt.Sprintf("the reason is longer than %d characters", MaxReason)}
	}
	seen := map[string]bool{}
	events := make([]string, 0, len(c.Events))
	for _, name := range c.Events {
		name = strings.TrimSpace(name)
		if !KnownSubject(name) {
			return nil, Error{Code: "unknown_event", Message: fmt.Sprintf("%q is not an event a channel can carry", name)}
		}
		if !seen[name] {
			seen[name] = true
			events = append(events, name)
		}
	}
	c.Events = events
	c.Filter.Site = strings.TrimSpace(c.Filter.Site)
	c.Filter.Environment = strings.TrimSpace(c.Filter.Environment)
	if err := c.Filter.validate(); err != nil {
		return nil, err
	}
	return decodeConfig(c.Kind, c.Config)
}

// decodeConfig reads the configuration of the kind and checks what can
// be checked without sending: an address that parses, a port, a mailbox
// list that reads as addresses.
func decodeConfig(kind string, raw json.RawMessage) (any, error) {
	if len(raw) == 0 {
		raw = json.RawMessage("{}")
	}
	switch kind {
	case KindWebhook:
		var config WebhookConfig
		if err := json.Unmarshal(raw, &config); err != nil {
			return nil, Error{Code: "invalid_config", Message: "the configuration does not read as a webhook: " + err.Error()}
		}
		config.URL = strings.TrimSpace(config.URL)
		if err := checkHTTPURL(config.URL); err != nil {
			return nil, err
		}
		config.SecretSet = false
		return config, nil
	case KindSlackWebhook:
		var config SlackConfig
		if err := json.Unmarshal(raw, &config); err != nil {
			return nil, Error{Code: "invalid_config", Message: "the configuration does not read as an incoming webhook: " + err.Error()}
		}
		config.URL = strings.TrimSpace(config.URL)
		if err := checkHTTPURL(config.URL); err != nil {
			return nil, err
		}
		return config, nil
	case KindEmail:
		var config EmailConfig
		if err := json.Unmarshal(raw, &config); err != nil {
			return nil, Error{Code: "invalid_config", Message: "the configuration does not read as a mailbox: " + err.Error()}
		}
		config.Host = strings.TrimSpace(config.Host)
		if config.Host == "" {
			return nil, Error{Code: "invalid_config", Message: "the mail relay needs a host"}
		}
		if config.Port == 0 {
			config.Port = 587
		}
		if config.Port < 1 || config.Port > 65535 {
			return nil, Error{Code: "invalid_config", Message: "the port has to lie between 1 and 65535"}
		}
		config.From = strings.TrimSpace(config.From)
		if _, err := mail.ParseAddress(config.From); err != nil {
			return nil, Error{Code: "invalid_config", Message: "the sender does not read as a mail address"}
		}
		recipients := make([]string, 0, len(config.To))
		for _, to := range config.To {
			to = strings.TrimSpace(to)
			if to == "" {
				continue
			}
			if _, err := mail.ParseAddress(to); err != nil {
				return nil, Error{Code: "invalid_config", Message: fmt.Sprintf("the recipient %q does not read as a mail address", to)}
			}
			recipients = append(recipients, to)
		}
		if len(recipients) == 0 {
			return nil, Error{Code: "invalid_config", Message: "the mailbox needs at least one recipient"}
		}
		if len(recipients) > MaxRecipients {
			return nil, Error{Code: "invalid_config", Message: fmt.Sprintf("at most %d recipients; a longer list is a mailing list's job", MaxRecipients)}
		}
		config.To = recipients
		config.Username = strings.TrimSpace(config.Username)
		config.PasswordSecret = strings.TrimSpace(config.PasswordSecret)
		if config.PasswordSecret != "" && !secretName.MatchString(config.PasswordSecret) {
			return nil, Error{Code: "invalid_config", Message: "password_secret has to be the name of a secret of the store"}
		}
		if config.Username != "" && config.PasswordSecret == "" {
			return nil, Error{Code: "invalid_config", Message: "a username needs the name of the secret that holds its password"}
		}
		if config.Username != "" && !config.StartTLS {
			return nil, Error{Code: "invalid_config", Message: "a password is sent only over STARTTLS; enable it or drop the username"}
		}
		return config, nil
	default:
		return nil, Error{Code: "unknown_kind", Message: fmt.Sprintf("%q is not a kind of channel; one of %s", kind, strings.Join(Kinds, ", "))}
	}
}

func checkHTTPURL(address string) error {
	parsed, err := url.Parse(address)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return Error{Code: "invalid_config", Message: "the address has to be an http or https URL"}
	}
	return nil
}

// Delivery is one attempt of one channel.
type Delivery struct {
	ID          int64  `json:"id"`
	ChannelID   string `json:"channel_id"`
	ChannelName string `json:"channel_name,omitempty"`
	// EventID is the row of the trail; zero for a test message.
	EventID   int64     `json:"event_id"`
	EventType string    `json:"event_type"`
	Attempt   int       `json:"attempt"`
	Status    string    `json:"status"`
	ErrorCode string    `json:"error_code"`
	Error     string    `json:"error"`
	SentAt    time.Time `json:"sent_at"`
}

// The statuses of a delivery.
const (
	StatusSent   = "sent"
	StatusFailed = "failed"
)

// DeliveryRetention is how long the log keeps a row.
const DeliveryRetention = 30 * 24 * time.Hour
