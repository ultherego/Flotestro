package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store keeps the channels and the delivery log.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore creates the store.
func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

const channelColumns = `
	c.id, c.name, c.kind, c.config, c.events, c.filter, c.enabled,
	c.created_by, c.reason, c.created_at, c.updated_at`

// List returns every channel by name, each with its newest delivery.
func (s *Store) List(ctx context.Context) ([]Channel, error) {
	channels, err := s.query(ctx, "order by c.name")
	if err != nil {
		return nil, err
	}
	for i := range channels {
		channels[i].Config = redact(channels[i].Kind, channels[i].Config)
		last, err := s.lastDelivery(ctx, channels[i].ID)
		if err != nil {
			return nil, err
		}
		channels[i].LastDelivery = last
	}
	return channels, nil
}

// Get returns one channel as the API shows it.
func (s *Store) Get(ctx context.Context, id string) (*Channel, error) {
	channel, err := s.get(ctx, id)
	if err != nil {
		return nil, err
	}
	channel.Config = redact(channel.Kind, channel.Config)
	if channel.LastDelivery, err = s.lastDelivery(ctx, id); err != nil {
		return nil, err
	}
	return channel, nil
}

// get returns a channel with its whole configuration, for the senders.
func (s *Store) get(ctx context.Context, id string) (*Channel, error) {
	if _, err := uuid.Parse(id); err != nil {
		return nil, ErrNotFound
	}
	channels, err := s.query(ctx, "where c.id = $1", id)
	if err != nil {
		return nil, err
	}
	if len(channels) == 0 {
		return nil, ErrNotFound
	}
	return &channels[0], nil
}

// Enabled returns the enabled channels with their whole configuration:
// what the router matches events against.
func (s *Store) Enabled(ctx context.Context) ([]Channel, error) {
	return s.query(ctx, "where c.enabled order by c.name")
}

func (s *Store) query(ctx context.Context, clause string, args ...any) ([]Channel, error) {
	rows, err := s.pool.Query(ctx, `select `+channelColumns+` from notification_channels c `+clause, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	channels := []Channel{}
	for rows.Next() {
		var channel Channel
		var config, filter []byte
		if err := rows.Scan(&channel.ID, &channel.Name, &channel.Kind, &config, &channel.Events, &filter,
			&channel.Enabled, &channel.CreatedBy, &channel.Reason, &channel.CreatedAt, &channel.UpdatedAt); err != nil {
			return nil, err
		}
		channel.Config = json.RawMessage(config)
		if err := json.Unmarshal(filter, &channel.Filter); err != nil {
			return nil, fmt.Errorf("the filter of channel %s: %w", channel.ID, err)
		}
		if channel.Events == nil {
			channel.Events = []string{}
		}
		channels = append(channels, channel)
	}
	return channels, rows.Err()
}

// redact replaces the secret of a configuration with the fact that it is
// set: what leaves the store towards the API.
func redact(kind string, raw json.RawMessage) json.RawMessage {
	if kind != KindWebhook {
		return raw
	}
	var config WebhookConfig
	if err := json.Unmarshal(raw, &config); err != nil {
		return raw
	}
	config.SecretSet = config.Secret != ""
	config.Secret = ""
	encoded, err := json.Marshal(config)
	if err != nil {
		return raw
	}
	return encoded
}

// Create records a channel. The configuration is checked for its kind
// and a mail password has to name a secret that exists and can be
// issued: a channel that could never send is refused now rather than
// found in the log later.
func (s *Store) Create(ctx context.Context, channel Channel) (*Channel, error) {
	config, err := channel.Validate()
	if err != nil {
		return nil, err
	}
	if err := s.checkSecret(ctx, config); err != nil {
		return nil, err
	}
	encodedConfig, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	encodedFilter, err := json.Marshal(channel.Filter)
	if err != nil {
		return nil, err
	}
	id := uuid.NewString()
	_, err = s.pool.Exec(ctx, `
		insert into notification_channels (id, name, kind, config, events, filter, enabled, created_by, reason)
		values ($1, $2, $3, $4::jsonb, $5, $6::jsonb, $7, $8, $9)`,
		id, channel.Name, channel.Kind, encodedConfig, channel.Events, encodedFilter,
		channel.Enabled, channel.CreatedBy, channel.Reason)
	if isUniqueViolation(err) {
		return nil, Error{Code: "name_taken", Message: fmt.Sprintf("a channel named %q exists already", channel.Name)}
	}
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, id)
}

// Update replaces a channel. A webhook edited without retyping its
// secret keeps the one it has: the API never showed it, so the editor
// cannot send it back. secret_set false with no secret clears it.
func (s *Store) Update(ctx context.Context, id string, channel Channel) (*Channel, error) {
	existing, err := s.get(ctx, id)
	if err != nil {
		return nil, err
	}
	config, err := channel.Validate()
	if err != nil {
		return nil, err
	}
	if webhook, ok := config.(WebhookConfig); ok && webhook.Secret == "" && existing.Kind == KindWebhook {
		var incoming WebhookConfig
		_ = json.Unmarshal(channel.Config, &incoming)
		var kept WebhookConfig
		_ = json.Unmarshal(existing.Config, &kept)
		if incoming.SecretSet {
			webhook.Secret = kept.Secret
		}
		config = webhook
	}
	if err := s.checkSecret(ctx, config); err != nil {
		return nil, err
	}
	encodedConfig, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	encodedFilter, err := json.Marshal(channel.Filter)
	if err != nil {
		return nil, err
	}
	_, err = s.pool.Exec(ctx, `
		update notification_channels
		   set name = $2, kind = $3, config = $4::jsonb, events = $5, filter = $6::jsonb,
		       enabled = $7, reason = $8, updated_at = now()
		 where id = $1`,
		id, channel.Name, channel.Kind, encodedConfig, channel.Events, encodedFilter,
		channel.Enabled, channel.Reason)
	if isUniqueViolation(err) {
		return nil, Error{Code: "name_taken", Message: fmt.Sprintf("a channel named %q exists already", channel.Name)}
	}
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, id)
}

// Delete removes a channel and, through the schema, its log.
func (s *Store) Delete(ctx context.Context, id string) error {
	if _, err := uuid.Parse(id); err != nil {
		return ErrNotFound
	}
	tag, err := s.pool.Exec(ctx, `delete from notification_channels where id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// checkSecret refuses a mail configuration whose password names a secret
// the store does not have or cannot issue. The check reads the metadata
// of the secret alone: the value is read by the sender, at the moment of
// sending.
func (s *Store) checkSecret(ctx context.Context, config any) error {
	email, ok := config.(EmailConfig)
	if !ok || email.PasswordSecret == "" {
		return nil
	}
	var retired *time.Time
	var version int
	err := s.pool.QueryRow(ctx, `select retired_at, current_version from secrets where name = $1`,
		email.PasswordSecret).Scan(&retired, &version)
	if errors.Is(err, pgx.ErrNoRows) {
		return Error{Code: "secret_not_found", Message: fmt.Sprintf("there is no secret named %q in the store", email.PasswordSecret)}
	}
	if err != nil {
		return err
	}
	if retired != nil || version == 0 {
		return Error{Code: "secret_retired", Message: fmt.Sprintf("the secret %q cannot be issued any more", email.PasswordSecret)}
	}
	return nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// Record writes one attempt to the log.
func (s *Store) Record(ctx context.Context, delivery Delivery) error {
	var eventID *int64
	if delivery.EventID > 0 {
		eventID = &delivery.EventID
	}
	_, err := s.pool.Exec(ctx, `
		insert into notification_deliveries (channel_id, event_id, event_type, attempt, status, error_code, error)
		values ($1, $2, $3, $4, $5, $6, $7)`,
		delivery.ChannelID, eventID, delivery.EventType, delivery.Attempt, delivery.Status,
		delivery.ErrorCode, delivery.Error)
	return err
}

// DeliveryFilter narrows the log.
type DeliveryFilter struct {
	ChannelID string
	Status    string
	Since     time.Time
	Limit     int
}

// MaxDeliveries bounds one page of the log.
const MaxDeliveries = 500

// Deliveries reads the log, newest first.
func (s *Store) Deliveries(ctx context.Context, filter DeliveryFilter) ([]Delivery, error) {
	var conditions []string
	var args []any
	if filter.ChannelID != "" {
		if _, err := uuid.Parse(filter.ChannelID); err != nil {
			return []Delivery{}, nil
		}
		args = append(args, filter.ChannelID)
		conditions = append(conditions, fmt.Sprintf("d.channel_id = $%d", len(args)))
	}
	if filter.Status != "" {
		args = append(args, filter.Status)
		conditions = append(conditions, fmt.Sprintf("d.status = $%d", len(args)))
	}
	if !filter.Since.IsZero() {
		args = append(args, filter.Since)
		conditions = append(conditions, fmt.Sprintf("d.sent_at >= $%d", len(args)))
	}
	where := ""
	if len(conditions) > 0 {
		where = "where " + strings.Join(conditions, " and ")
	}
	limit := filter.Limit
	if limit <= 0 || limit > MaxDeliveries {
		limit = 100
	}
	args = append(args, limit)
	rows, err := s.pool.Query(ctx, `
		select d.id, d.channel_id, c.name, coalesce(d.event_id, 0), d.event_type, d.attempt,
		       d.status, d.error_code, d.error, d.sent_at
		  from notification_deliveries d join notification_channels c on c.id = d.channel_id
		`+where+`
		 order by d.sent_at desc, d.id desc
		 limit $`+fmt.Sprint(len(args)), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	deliveries := []Delivery{}
	for rows.Next() {
		var delivery Delivery
		if err := rows.Scan(&delivery.ID, &delivery.ChannelID, &delivery.ChannelName, &delivery.EventID,
			&delivery.EventType, &delivery.Attempt, &delivery.Status, &delivery.ErrorCode,
			&delivery.Error, &delivery.SentAt); err != nil {
			return nil, err
		}
		deliveries = append(deliveries, delivery)
	}
	return deliveries, rows.Err()
}

func (s *Store) lastDelivery(ctx context.Context, channelID string) (*Delivery, error) {
	deliveries, err := s.Deliveries(ctx, DeliveryFilter{ChannelID: channelID, Limit: 1})
	if err != nil {
		return nil, err
	}
	if len(deliveries) == 0 {
		return nil, nil
	}
	return &deliveries[0], nil
}

// SweepDeliveries deletes the rows of the log older than the retention.
func (s *Store) SweepDeliveries(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `
		delete from notification_deliveries
		 where sent_at < now() - make_interval(secs => $1)`, DeliveryRetention.Seconds())
	if err != nil {
		return fmt.Errorf("sweeping the delivery log: %w", err)
	}
	return nil
}
