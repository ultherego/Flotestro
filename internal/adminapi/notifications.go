package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/notify"
)

// Notification channels. A channel is where the fleet reports to when nobody
// is looking at the panel.

// SetNotifications attaches the channel store and the router that sends
// through them.
func (s *Server) SetNotifications(store *notify.Store, router *notify.Router) {
	s.notifications = store
	s.notifier = router
}

// SetNotificationQueue attaches the worker of this instance, so a row an
// operator put back in the queue is taken at once rather than at the next
// round.
func (s *Server) SetNotificationQueue(worker *notify.Worker) {
	s.notificationQueue = worker
}

// notificationRoutes registers the channel endpoints.
func (s *Server) notificationRoutes(mux *http.ServeMux) {
	s.route(mux, "GET /api/v1/notifications/channels", s.handleListNotificationChannels)
	s.route(mux, "POST /api/v1/notifications/channels", s.handleCreateNotificationChannel)
	s.route(mux, "GET /api/v1/notifications/channels/{id}", s.handleGetNotificationChannel)
	s.route(mux, "PUT /api/v1/notifications/channels/{id}", s.handleUpdateNotificationChannel)
	s.route(mux, "DELETE /api/v1/notifications/channels/{id}", s.handleDeleteNotificationChannel)
	s.route(mux, "POST /api/v1/notifications/channels/{id}/test", s.handleTestNotificationChannel)
	s.route(mux, "POST /api/v1/notifications/deliveries/{id}/retry", s.handleRetryNotificationDelivery)
	s.route(mux, "GET /api/v1/notifications/deliveries", s.handleListNotificationDeliveries)
}

// notificationsEnabled refuses the request when the installation runs
// without the channels; the answer has been written when it says false.
func (s *Server) notificationsEnabled(w http.ResponseWriter) bool {
	if s.notifications == nil || s.notifier == nil {
		problem(w, http.StatusServiceUnavailable, "notifications_disabled",
			"this installation runs without notification channels")
		return false
	}
	return true
}

// channelRequest is the body of a channel to create or to replace.
type channelRequest struct {
	Name   string          `json:"name"`
	Kind   string          `json:"kind"`
	Config json.RawMessage `json:"config"`
	Events []string        `json:"events"`
	Filter notify.Filter   `json:"filter"`
	// Enabled defaults to true: a channel written down is meant to carry.
	Enabled *bool `json:"enabled"`
	// Reason says what the channel is for, or why it changed; the trail
	// keeps it with the change.
	Reason string `json:"reason"`
}

// readChannel decodes and checks the body; the answer has been written
// when the second result is false.
func (s *Server) readChannel(w http.ResponseWriter, r *http.Request) (notify.Channel, bool) {
	var request channelRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&request); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return notify.Channel{}, false
	}
	request.Reason = strings.TrimSpace(request.Reason)
	if len([]rune(request.Reason)) < minimalStepUpReason {
		problem(w, http.StatusBadRequest, "reason_required",
			"a channel needs a reason (field reason, min. 8 characters): what it is for, or why it changed")
		return notify.Channel{}, false
	}
	enabled := true
	if request.Enabled != nil {
		enabled = *request.Enabled
	}
	if request.Events == nil {
		request.Events = []string{}
	}
	return notify.Channel{
		Name: request.Name, Kind: request.Kind, Config: request.Config, Events: request.Events,
		Filter: request.Filter, Enabled: enabled, Reason: request.Reason,
	}, true
}

// channelProblem answers a store error of the channels; true when it
// did.
func (s *Server) channelProblem(w http.ResponseWriter, err error) bool {
	var refusal notify.Error
	switch {
	case err == nil:
		return false
	case errors.Is(err, notify.ErrNotFound):
		problem(w, http.StatusNotFound, "channel_not_found", "no such notification channel")
	case errors.As(err, &refusal):
		status := http.StatusBadRequest
		if refusal.Code == "name_taken" {
			status = http.StatusConflict
		}
		problem(w, status, refusal.Code, refusal.Message)
	default:
		s.fail(w, err)
	}
	return true
}

// channelDetail is what the trail records about a channel: the address without
// its secret, the subjects and the filter.
func channelDetail(channel notify.Channel) map[string]any {
	var config map[string]any
	_ = json.Unmarshal(channel.Config, &config)
	delete(config, "secret")
	if channel.Kind == notify.KindSlackWebhook {
		delete(config, "url")
	}
	return map[string]any{
		"name": channel.Name, "kind": channel.Kind, "config": config, "events": channel.Events,
		"filter": channel.Filter, "enabled": channel.Enabled, "reason": channel.Reason,
	}
}

// channelScope is where a channel's news comes from, as a scope: the site and
// the environment its filter names, and the whole fleet where it names none.
func channelScope(channel notify.Channel) authz.Scope {
	scope := authz.GlobalScope
	if channel.Filter.Site != "" {
		scope.Site = channel.Filter.Site
	}
	if channel.Filter.Environment != "" {
		scope.Environment = channel.Filter.Environment
	}
	return scope
}

func (s *Server) handleListNotificationChannels(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermNotificationRead, "notification_channel")
	if !ok {
		return
	}
	if !s.notificationsEnabled(w) {
		return
	}
	channels, err := s.notifications.List(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	// The list is narrowed to the channels of the caller's scope, the way a
	// direct read of each would be answered: a channel of another site tells
	// where its alerts go, which is not the caller's to know.
	visible := make([]notify.Channel, 0, len(channels))
	for _, channel := range channels {
		if principal.Can(authz.PermNotificationRead, channelScope(channel)) {
			visible = append(visible, channel)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items": visible, "count": len(visible),
		// The vocabulary of a channel, so the form does not carry a copy.
		"kinds": notify.Kinds, "subjects": notify.Subjects, "severities": notify.Severities,
		"states": notify.States,
	})
}

func (s *Server) handleGetNotificationChannel(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorizeCollection(w, r, authz.PermNotificationRead, "notification_channel"); !ok {
		return
	}
	if !s.notificationsEnabled(w) {
		return
	}
	channel, err := s.notifications.Get(r.Context(), r.PathValue("id"))
	if s.channelProblem(w, err) {
		return
	}
	// The channel is read in its own scope, after it is known: the refusal is a
	// 403 with the scope on the trail, not a 404 that would say there is no such
	// channel.
	if _, ok := s.authorize(w, r, authz.PermNotificationRead, channelScope(*channel),
		"notification_channel", channel.ID); !ok {
		return
	}
	writeJSON(w, http.StatusOK, channel)
}

func (s *Server) handleCreateNotificationChannel(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorize(w, r, authz.PermNotificationManage, authz.GlobalScope, "notification_channel", "")
	if !ok {
		return
	}
	if !s.notificationsEnabled(w) {
		return
	}
	channel, ok := s.readChannel(w, r)
	if !ok {
		return
	}
	channel.CreatedBy = principal.Subject
	created, err := s.notifications.Create(r.Context(), channel)
	if s.channelProblem(w, err) {
		return
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "notification.channel.create", TargetType: "notification_channel", TargetID: created.ID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: channelDetail(*created),
	})
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handleUpdateNotificationChannel(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	principal, ok := s.authorize(w, r, authz.PermNotificationManage, authz.GlobalScope, "notification_channel", id)
	if !ok {
		return
	}
	if !s.notificationsEnabled(w) {
		return
	}
	channel, ok := s.readChannel(w, r)
	if !ok {
		return
	}
	updated, err := s.notifications.Update(r.Context(), id, channel)
	if s.channelProblem(w, err) {
		return
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "notification.channel.update", TargetType: "notification_channel", TargetID: id,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: channelDetail(*updated),
	})
	writeJSON(w, http.StatusOK, updated)
}

// handleDeleteNotificationChannel removes a channel with its log. The
// reason travels in the body or the query, as it does for a schedule.
func (s *Server) handleDeleteNotificationChannel(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	principal, ok := s.authorize(w, r, authz.PermNotificationManage, authz.GlobalScope, "notification_channel", id)
	if !ok {
		return
	}
	if !s.notificationsEnabled(w) {
		return
	}
	reason, ok := requestReason(w, r, nil)
	if !ok {
		return
	}
	reason = strings.TrimSpace(reason)
	if len([]rune(reason)) < minimalStepUpReason {
		problem(w, http.StatusBadRequest, "reason_required",
			"removing a channel needs a reason (field reason, min. 8 characters)")
		return
	}
	channel, err := s.notifications.Get(r.Context(), id)
	if s.channelProblem(w, err) {
		return
	}
	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	retire, err := s.notifications.DeleteTx(r.Context(), tx, id)
	if s.channelProblem(w, err) {
		return
	}
	detail := channelDetail(*channel)
	detail["delete_reason"] = reason
	if err := s.audit.RecordTx(r.Context(), tx, audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "notification.channel.delete", TargetType: "notification_channel", TargetID: id,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: detail,
	}); err != nil {
		s.fail(w, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		s.fail(w, err)
		return
	}
	// The secret store joins no transaction, so the retirement follows the
	// commit: a failure here leaves a secret nobody issues, not a channel
	// nobody recorded.
	if retire {
		if err := s.notifications.RetireChannelSecret(r.Context(), id); err != nil {
			s.fail(w, err)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleTestNotificationChannel sends the test message once and answers with
// the row of the log: sent, or failed with the typed reason.
func (s *Server) handleTestNotificationChannel(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	principal, ok := s.authorize(w, r, authz.PermNotificationManage, authz.GlobalScope, "notification_channel", id)
	if !ok {
		return
	}
	if !s.notificationsEnabled(w) {
		return
	}
	delivery, err := s.notifier.Test(r.Context(), id)
	if s.channelProblem(w, err) {
		return
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "notification.channel.test", TargetType: "notification_channel", TargetID: id,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"status": delivery.Status, "error_code": delivery.ErrorCode, "error": delivery.Error,
		},
	})
	writeJSON(w, http.StatusOK, delivery)
}

// handleRetryNotificationDelivery puts a dead letter back in the queue.
func (s *Server) handleRetryNotificationDelivery(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	principal, ok := s.authorize(w, r, authz.PermNotificationManage, authz.GlobalScope, "notification_delivery", id)
	if !ok {
		return
	}
	if !s.notificationsEnabled(w) {
		return
	}
	delivery, err := s.notifications.Retry(r.Context(), id)
	if errors.Is(err, notify.ErrDeliveryNotFound) {
		problem(w, http.StatusNotFound, "delivery_not_found", "no such notification delivery")
		return
	}
	if s.channelProblem(w, err) {
		return
	}
	// The worker of this instance is asked for a round now; without one
	// the row waits for the next round of any instance.
	if s.notificationQueue != nil {
		s.notificationQueue.Wake()
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "notification.delivery.retry", TargetType: "notification_delivery", TargetID: id,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"channel_id": delivery.ChannelID, "event_type": delivery.EventType,
			"last_error_code": delivery.LastErrorCode,
		},
	})
	writeJSON(w, http.StatusOK, delivery)
}

// deliveryFilterOf reads the query of the delivery list.
func deliveryFilterOf(query url.Values) (notify.DeliveryFilter, string, string) {
	filter := notify.DeliveryFilter{
		ChannelID: query.Get("channel_id"),
		Status:    query.Get("status"),
		State:     query.Get("state"),
	}
	switch filter.Status {
	case "", notify.StatusSent, notify.StatusFailed:
	default:
		return filter, "invalid_status", "status must be sent or failed"
	}
	if filter.State != "" && !notify.KnownState(filter.State) {
		return filter, "invalid_state", "state must be one of " + strings.Join(notify.States, ", ")
	}
	if since := query.Get("since"); since != "" {
		at, err := time.Parse(time.RFC3339, since)
		if err != nil {
			return filter, "invalid_since", "since must be an RFC 3339 timestamp"
		}
		filter.Since = at
	}
	filter.Limit, _ = strconv.Atoi(query.Get("limit"))
	return filter, "", ""
}

// deliveriesCSVColumns is the header of the log export.
var deliveriesCSVColumns = []string{
	"id", "channel_name", "channel_id", "event_id", "event_type", "attempt", "status", "error_code", "error", "sent_at",
}

// handleListNotificationDeliveries returns the queue, newest first, narrowed
// by channel, state and a moment; as CSV on request.
func (s *Server) handleListNotificationDeliveries(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorizeCollection(w, r, authz.PermNotificationRead, "notification_delivery"); !ok {
		return
	}
	if !s.notificationsEnabled(w) {
		return
	}
	asCSV, ok := exportFormat(w, r)
	if !ok {
		return
	}
	filter, code, message := deliveryFilterOf(r.URL.Query())
	if code != "" {
		problem(w, http.StatusBadRequest, code, message)
		return
	}
	if asCSV {
		filter.Limit = notify.MaxDeliveries
	}
	deliveries, err := s.notifications.Deliveries(r.Context(), filter)
	if err != nil {
		s.fail(w, err)
		return
	}
	if asCSV {
		s.writeCSV(w, r, exportFileName("notification-deliveries", time.Now()), deliveriesCSVColumns,
			func(yield func([]string) bool) error {
				for _, delivery := range deliveries {
					eventID := ""
					if delivery.EventID > 0 {
						eventID = strconv.FormatInt(delivery.EventID, 10)
					}
					if !yield([]string{
						delivery.ID, delivery.ChannelName, delivery.ChannelID, eventID,
						delivery.EventType, strconv.Itoa(delivery.Attempt), delivery.Status, delivery.ErrorCode,
						delivery.Error, csvInstant(delivery.SentAt),
					}) {
						return nil
					}
				}
				return nil
			})
		return
	}
	deadLetters, err := s.notifications.DeadLetterCount(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items": deliveries, "count": len(deliveries), "dead_letters": deadLetters,
	})
}
