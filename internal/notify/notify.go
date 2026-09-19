// Package notify carries what the fleet says to the people who are not looking
// at the panel.
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

// Subject is one thing a channel can be told about. It is coarser than an
// event of the trail: campaign.
type Subject struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// SubjectSecurity is the subject of the security alerts of the whole
// installation: a duplicate identity, a helper that refused a signature, a
const SubjectSecurity = "security.alert"

// Subjects is the catalogue of what a channel can carry.
var Subjects = []Subject{
	{Name: "alert.fired", Description: "an alert rule fired on a host"},
	{Name: "alert.resolved", Description: "a firing alert ended"},
	{Name: "alert.no_data", Description: "a host stopped reporting the metric a rule watches"},
	{Name: "campaign.finished", Description: "a campaign reached its end: completed, with issues, failed, expired or canceled"},
	{Name: "campaign.awaiting_approval", Description: "a campaign waits for its approval"},
	{Name: "job.awaiting_approval", Description: "a task on one host waits for its approval"},
	{Name: "enrollment.completed", Description: "a host completed its enrollment"},
	{Name: "host.offline", Description: "a host that was online stopped answering"},
	{Name: "policy.drift", Description: "a policy found a rule out of its declared state on a host"},
	{Name: SubjectSecurity, Description: "a security alert of the installation; a silence of one host never keeps it back"},
}

// subjectOfEvent maps a type of the trail to the subject it belongs to.
var subjectOfEvent = map[string]string{
	"alert.fired":                    "alert.fired",
	"alert.resolved":                 "alert.resolved",
	"alert.no_data":                  "alert.no_data",
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

// securityEventPrefix marks the events of the trail that are security
// alerts of the installation, whatever their exact type.
const securityEventPrefix = "security."

// SubjectOf returns the subject an event of the trail belongs to, and
// false for an event no channel can carry.
func SubjectOf(eventType string) (string, bool) {
	if strings.HasPrefix(eventType, securityEventPrefix) {
		return SubjectSecurity, true
	}
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
	Site        string `json:"site,omitempty"`
	Environment string `json:"environment,omitempty"`
}

// Global says whether the filter names no part of the fleet: the channel of
// the whole installation, the only kind an event of unknown place reaches.
func (f Filter) Global() bool {
	return f.Site == "" && f.Environment == ""
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
	if f.Site != "" && scope.Site != f.Site {
		return false
	}
	if f.Environment != "" && scope.Environment != f.Environment {
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
	// Config is the configuration of the kind without its credential: what the
	// API shows and takes.
	Config json.RawMessage `json:"config"`
	// PublicConfig is the summary of the address the API shows beside the
	// configuration: the host of an incoming webhook, the relay of a mailbox.
	PublicConfig json.RawMessage `json:"public_config"`
	// SecretConfigured says the channel has its credential in the secret
	// store; SecretRotatedAt is when it was last set or replaced.
	SecretConfigured bool       `json:"secret_configured"`
	SecretRotatedAt  *time.Time `json:"secret_last_rotated_at,omitempty"`
	// Revision is raised on every write of the channel.
	Revision  int64     `json:"revision"`
	Events    []string  `json:"events"`
	Filter    Filter    `json:"filter"`
	Enabled   bool      `json:"enabled"`
	CreatedBy string    `json:"created_by"`
	Reason    string    `json:"reason"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	// LastDelivery is the newest row of the queue, so the list says at a
	// glance whether the channel works.
	LastDelivery *DeliverySummary `json:"last_delivery,omitempty"`

	// secret is the credential read from the store for one send; it is never
	// encoded and never kept past the send.
	secret    string
	secretRef string
}

// DeliverySummary is what a channel says about its newest delivery.
type DeliverySummary struct {
	ID        string    `json:"id"`
	State     string    `json:"state"`
	At        time.Time `json:"at"`
	ErrorCode string    `json:"error_code,omitempty"`
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

// WithSecret returns the channel with its credential in hand, for a
// sender. Tests build channels this way; the worker reads the store.
func (c Channel) WithSecret(secret string) Channel {
	c.secret = secret
	return c
}

// ChannelSecretPrefix starts the name of every secret the panel holds for a
// channel.
const ChannelSecretPrefix = "panel.notification."

// ChannelSecretName is the name of the secret that holds a channel's
// credential.
func ChannelSecretName(channelID string) string {
	return ChannelSecretPrefix + channelID
}

// WebhookConfig is the address of a webhook of the installation's own.
type WebhookConfig struct {
	URL string `json:"url"`
	// Secret signs the deliveries; empty means unsigned, and the API says
	// so on the channel. It is in the configuration only on the way in.
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
	// PasswordSecret names the secret of the store that holds the password; the
	// row never holds the password.
	PasswordSecret string `json:"password_secret,omitempty"`
}

// SlackConfig is an incoming webhook of Slack or of a service that reads
// its shape - Mattermost, Rocket.Chat, Discord's Slack endpoint.
type SlackConfig struct {
	// URL is the incoming webhook.
	URL string `json:"url,omitempty"`
	// URLSet is what the API shows in place of the address.
	URLSet bool `json:"url_set,omitempty"`
}

// Error is a refusal with a code the API answers with.
type Error struct {
	Code    string
	Message string
}

func (e Error) Error() string { return e.Message }

// ErrNotFound means there is no such channel.
var ErrNotFound = errors.New("there is no such notification channel")

// ErrDeliveryNotFound means there is no such row of the queue.
var ErrDeliveryNotFound = errors.New("there is no such notification delivery")

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
// trimmed strings, the event list without duplicates.
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

// decodeConfig reads the configuration of the kind and checks what can be
// checked without sending: an address that parses, a port, a mailbox list that
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
		// A typed secret replaces the stored one; "the secret is set" with none
		// typed keeps it; neither clears it.
		if config.Secret != "" {
			config.SecretSet = false
		}
		return config, nil
	case KindSlackWebhook:
		var config SlackConfig
		if err := json.Unmarshal(raw, &config); err != nil {
			return nil, Error{Code: "invalid_config", Message: "the configuration does not read as an incoming webhook: " + err.Error()}
		}
		config.URL = strings.TrimSpace(config.URL)
		// An edit that says "the address is set" and types none keeps the stored
		// address; the store checks that one is stored and refuses a channel that
		if config.URL == "" && config.URLSet {
			return config, nil
		}
		if err := checkHTTPURL(config.URL); err != nil {
			return nil, err
		}
		config.URLSet = false
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
		if strings.HasPrefix(config.PasswordSecret, ChannelSecretPrefix) {
			return nil, Error{Code: "invalid_config", Message: "password_secret cannot name a secret the panel holds for a channel"}
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

// displayHost is the host of an address, for the public summary of a channel:
// enough to tell hooks.
func displayHost(address string) string {
	parsed, err := url.Parse(address)
	if err != nil {
		return ""
	}
	return parsed.Host
}

// publicConfigOf is the summary of an address the API shows beside the
// configuration.
func publicConfigOf(kind string, config any, secretAddress string) json.RawMessage {
	summary := map[string]any{}
	switch c := config.(type) {
	case WebhookConfig:
		summary["display_host"] = displayHost(c.URL)
		summary["url"] = c.URL
		summary["signed"] = c.Secret != "" || c.SecretSet
	case SlackConfig:
		address := c.URL
		if address == "" {
			address = secretAddress
		}
		summary["display_host"] = displayHost(address)
	case EmailConfig:
		summary["display_host"] = fmt.Sprintf("%s:%d", c.Host, c.Port)
		summary["from"] = c.From
		summary["recipients"] = len(c.To)
		summary["starttls"] = c.StartTLS
		summary["authenticated"] = c.Username != ""
	}
	encoded, err := json.Marshal(summary)
	if err != nil {
		return json.RawMessage("{}")
	}
	return encoded
}

// The states of a row of the queue, as the schema names them.
const (
	StatePending    = "pending"
	StateLeased     = "leased"
	StateDelivered  = "delivered"
	StateRetryWait  = "retry_wait"
	StateDeadLetter = "dead_letter"
	StateSuppressed = "suppressed"
)

// States lists the states of a row of the queue.
var States = []string{StatePending, StateLeased, StateDelivered, StateRetryWait, StateDeadLetter, StateSuppressed}

// KnownState says whether the name is a state of the queue.
func KnownState(name string) bool {
	for _, state := range States {
		if state == name {
			return true
		}
	}
	return false
}

// The typed reasons of a suppressed row.
const (
	// SuppressedBySilence: a silence of the host, the rule or both kept
	// the row; policy_id names it.
	SuppressedBySilence = "silence"
	// SuppressedByMaintenance: the host is inside a maintenance window.
	SuppressedByMaintenance = "maintenance_window"
	// SuppressedFireKept: the resolve of an alert whose fire the channel never
	// got, because a silence kept it; a resolve of nothing said is nothing to
	SuppressedFireKept = "fired_suppressed"
)

// The codes a dead letter carries, as the document names them, beside
// the transport codes of a failed attempt.
const (
	// CodeCredentialsRejected: the receiver answered 401 or 403, or the mail
	// relay refused the login.
	CodeCredentialsRejected = "channel_credentials_rejected"
	// CodePermanentHTTP: the receiver answered a status that is neither a success
	// nor a failure that passes - a 404, a 400 - so the address or the body is
	CodePermanentHTTP = "permanent_http_error"
	// CodePermanentSMTP: the mail relay refused the message with a
	// permanent reply.
	CodePermanentSMTP = "permanent_smtp_error"
	// CodeAttemptsExhausted named a delivery the queue stopped retrying.
	CodeAttemptsExhausted = "delivery_attempts_exhausted"
	// CodeChannelMisconfigured: the channel cannot send as it is - no
	// sender for its kind, a configuration that does not read.
	CodeChannelMisconfigured = "channel_misconfigured"
)

// Delivery is one row of the queue: one event for one channel, with the
// attempts counted on it and the outcome so far.
type Delivery struct {
	ID          string `json:"id"`
	ChannelID   string `json:"channel_id"`
	ChannelName string `json:"channel_name,omitempty"`
	// EventID is the row of the trail; zero for a test message and for a
	// summary after a silence.
	EventID   int64  `json:"event_id"`
	EventType string `json:"event_type"`
	// Title is the first line of the message, so the log reads without
	// the trail.
	Title   string `json:"title,omitempty"`
	State   string `json:"state"`
	Attempt int    `json:"attempt"`
	// NextAttemptAt is when the worker takes the row again; it means
	// something for pending and retry_wait.
	NextAttemptAt time.Time  `json:"next_attempt_at"`
	LeaseOwner    string     `json:"lease_owner,omitempty"`
	LeaseUntil    *time.Time `json:"lease_until,omitempty"`
	LastErrorCode string     `json:"last_error_code"`
	LastError     string     `json:"last_error"`
	// PolicyID and SuppressionReason say what kept a suppressed row.
	PolicyID          string     `json:"policy_id,omitempty"`
	SuppressionReason string     `json:"suppression_reason,omitempty"`
	DeliveredAt       *time.Time `json:"delivered_at,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`

	// The fields below are the names of the previous release, kept for the
	// readers that know them: status sent or failed, the code and the sentence of
	Status    string    `json:"status"`
	ErrorCode string    `json:"error_code"`
	Error     string    `json:"error"`
	SentAt    time.Time `json:"sent_at"`

	// aggregateID, message and channelRevision are the row's own: what the event
	// is about, the composed message as JSON, and the revision of the channel the
	aggregateID     string
	message         []byte
	channelRevision int64
}

// WithMessage returns the row with its composed message; the queue keeps
// it with the row and the worker sends it as it is.
func (d Delivery) WithMessage(message Message) (Delivery, error) {
	encoded, err := json.Marshal(message)
	if err != nil {
		return d, err
	}
	d.message = encoded
	d.aggregateID = message.AggregateID
	d.Title = message.Title
	return d, nil
}

// Message decodes the composed message of the row.
func (d Delivery) Message() (Message, error) {
	var message Message
	if len(d.message) == 0 {
		return message, errors.New("the row carries no message")
	}
	err := json.Unmarshal(d.message, &message)
	return message, err
}

// The statuses of the previous release's log, derived from the state.
const (
	StatusSent   = "sent"
	StatusFailed = "failed"
)

// legacyStatus reads a state as the previous release's status: delivered is
// sent, a dead letter or a wait for the next attempt is failed, and the rest -
func legacyStatus(state string) string {
	switch state {
	case StateDelivered:
		return StatusSent
	case StateDeadLetter, StateRetryWait:
		return StatusFailed
	}
	return state
}

// Summary is what a channel shows of the delivery.
func (d Delivery) Summary() *DeliverySummary {
	return &DeliverySummary{ID: d.ID, State: d.State, At: d.UpdatedAt, ErrorCode: d.LastErrorCode}
}

// DeliveryRetention is how long the queue keeps a settled row.
const DeliveryRetention = 30 * 24 * time.Hour
