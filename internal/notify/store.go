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

	"github.com/ultherego/flotestro/internal/secrets"
)

// SecretStore is the part of the secret store the channels use: a credential
// goes in as a secret of the panel's own, is replaced as a new version of it,
// is retired with the channel, and is read at the moment of sending.
type SecretStore interface {
	SecretReader
	Create(ctx context.Context, name, description string, value []byte, author string) (*secrets.Secret, error)
	Rotate(ctx context.Context, name string, value []byte, author string) (*secrets.Secret, error)
	Retire(ctx context.Context, name string) error
}

// Store keeps the channels and the queue.
type Store struct {
	pool    *pgxpool.Pool
	secrets SecretStore
}

// NewStore creates the store over the pool and the secret store the
// credentials live in.
func NewStore(pool *pgxpool.Pool, secretStore SecretStore) *Store {
	return &Store{pool: pool, secrets: secretStore}
}

const channelColumns = `
	c.id, c.name, c.kind, c.config, c.public_config, c.secret_ref, c.secret_rotated_at, c.revision,
	c.events, c.filter, c.enabled, c.created_by, c.reason, c.created_at, c.updated_at`

// List returns every channel by name, each with its newest delivery.
func (s *Store) List(ctx context.Context) ([]Channel, error) {
	channels, err := s.query(ctx, "order by c.name")
	if err != nil {
		return nil, err
	}
	for i := range channels {
		channels[i].Config = redact(channels[i].Kind, channels[i].Config, channels[i].SecretConfigured)
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
	channel.Config = redact(channel.Kind, channel.Config, channel.SecretConfigured)
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
		var config, public, filter []byte
		var secretRef *string
		if err := rows.Scan(&channel.ID, &channel.Name, &channel.Kind, &config, &public, &secretRef,
			&channel.SecretRotatedAt, &channel.Revision, &channel.Events, &filter, &channel.Enabled,
			&channel.CreatedBy, &channel.Reason, &channel.CreatedAt, &channel.UpdatedAt); err != nil {
			return nil, err
		}
		channel.Config = json.RawMessage(config)
		channel.PublicConfig = json.RawMessage(public)
		if len(channel.PublicConfig) == 0 {
			channel.PublicConfig = json.RawMessage("{}")
		}
		if secretRef != nil {
			channel.secretRef = *secretRef
			channel.SecretConfigured = true
		}
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

// withSecret returns the channel with its credential read from the store, for
// one send.
func (s *Store) withSecret(ctx context.Context, channel Channel) (Channel, error) {
	if channel.secretRef == "" {
		return channel, nil
	}
	if s.secrets == nil {
		return channel, SendError{Code: CodeSecretUnavailable, Err: errors.New("this installation has no secret store")}
	}
	var name string
	err := s.pool.QueryRow(ctx, `select name from secrets where id = $1`, channel.secretRef).Scan(&name)
	if errors.Is(err, pgx.ErrNoRows) {
		return channel, SendError{Code: CodeSecretUnavailable, Err: errors.New("the secret of the channel is gone from the store")}
	}
	if err != nil {
		return channel, err
	}
	value, err := s.secrets.ReadCurrent(ctx, name)
	if err != nil {
		return channel, SendError{Code: CodeSecretUnavailable, Err: fmt.Errorf("the secret of the channel: %w", err)}
	}
	channel.secret = string(value)
	return channel, nil
}

// redact replaces the credential of a configuration with the fact that it is
// set: what leaves the store towards the API.
func redact(kind string, raw json.RawMessage, configured bool) json.RawMessage {
	switch kind {
	case KindWebhook:
		var config WebhookConfig
		if err := json.Unmarshal(raw, &config); err != nil {
			return raw
		}
		config.SecretSet = configured || config.Secret != ""
		config.Secret = ""
		encoded, err := json.Marshal(config)
		if err != nil {
			return raw
		}
		return encoded
	case KindSlackWebhook:
		var config SlackConfig
		if err := json.Unmarshal(raw, &config); err != nil {
			return raw
		}
		config.URLSet = configured || config.URL != ""
		config.URL = ""
		encoded, err := json.Marshal(config)
		if err != nil {
			return raw
		}
		return encoded
	default:
		return raw
	}
}

// credentialOf is the credential a configuration carries on the way in, and
// the configuration without it: what the secret store gets and what the row
// gets.
func credentialOf(config any) (credential string, stored any) {
	switch c := config.(type) {
	case WebhookConfig:
		credential = c.Secret
		c.Secret = ""
		c.SecretSet = false
		return credential, c
	case SlackConfig:
		credential = c.URL
		c.URL = ""
		c.URLSet = false
		return credential, c
	}
	return "", config
}

// Create records a channel.
func (s *Store) Create(ctx context.Context, channel Channel) (*Channel, error) {
	config, err := channel.Validate()
	if err != nil {
		return nil, err
	}
	passwordRef, err := s.checkSecret(ctx, config)
	if err != nil {
		return nil, err
	}
	// "The address is set" is a statement about a stored channel; a new
	// one has nothing stored to keep.
	if slack, ok := config.(SlackConfig); ok && slack.URL == "" {
		return nil, Error{Code: "invalid_config", Message: "the incoming webhook needs its address"}
	}
	credential, stored := credentialOf(config)
	if credential != "" && s.secrets == nil {
		return nil, Error{Code: "secret_store_unavailable", Message: "this installation has no secret store to hold the credential of the channel"}
	}
	encodedConfig, err := json.Marshal(stored)
	if err != nil {
		return nil, err
	}
	encodedFilter, err := json.Marshal(channel.Filter)
	if err != nil {
		return nil, err
	}
	id := uuid.NewString()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var rotated *time.Time
	if passwordRef != "" {
		now := time.Now().UTC()
		rotated = &now
	}
	_, err = tx.Exec(ctx, `
		insert into notification_channels
		    (id, name, kind, config, public_config, secret_ref, secret_rotated_at, events, filter, enabled, created_by, reason)
		values ($1, $2, $3, $4::jsonb, $5::jsonb, $6, $7, $8, $9::jsonb, $10, $11, $12)`,
		id, channel.Name, channel.Kind, encodedConfig, publicConfigOf(channel.Kind, config, ""),
		nullableID(passwordRef), rotated, channel.Events, encodedFilter,
		channel.Enabled, channel.CreatedBy, channel.Reason)
	if isUniqueViolation(err) {
		return nil, Error{Code: "name_taken", Message: fmt.Sprintf("a channel named %q exists already", channel.Name)}
	}
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	if credential != "" {
		if err := s.putCredential(ctx, id, credential, channel.CreatedBy); err != nil {
			// A channel whose credential could not be sealed is not a
			// channel: the row goes, and the refusal names the store.
			_, _ = s.pool.Exec(ctx, `delete from notification_channels where id = $1`, id)
			return nil, err
		}
	}
	return s.Get(ctx, id)
}

// putCredential seals the credential as a version of the channel's own secret
// - a new secret for a channel without one, a new version for a channel that
// has one - and points the row at it.
func (s *Store) putCredential(ctx context.Context, channelID, credential, author string) error {
	name := ChannelSecretName(channelID)
	if author == "" {
		author = "panel"
	}
	secret, err := s.secrets.Rotate(ctx, name, []byte(credential), author)
	if errors.Is(err, secrets.ErrNotFound) {
		secret, err = s.secrets.Create(ctx, name,
			"the credential of the notification channel "+channelID+"; held by the panel, never issued to a host",
			[]byte(credential), author)
	}
	if err != nil {
		return Error{Code: "secret_store_unavailable", Message: "the credential could not be sealed: " + err.Error()}
	}
	_, err = s.pool.Exec(ctx, `
		update notification_channels
		   set secret_ref = $2, secret_rotated_at = now(), revision = revision + 1, updated_at = now()
		 where id = $1`, channelID, secret.ID)
	return err
}

// dropCredential retires the channel's own secret and clears the reference:
// what "the secret is not set" on an edit means, and what a deleted channel
// leaves behind.
func (s *Store) dropCredential(ctx context.Context, channelID string) error {
	if s.secrets != nil {
		if err := s.secrets.Retire(ctx, ChannelSecretName(channelID)); err != nil && !errors.Is(err, secrets.ErrNotFound) {
			return err
		}
	}
	_, err := s.pool.Exec(ctx, `
		update notification_channels
		   set secret_ref = null, secret_rotated_at = now(), revision = revision + 1, updated_at = now()
		 where id = $1`, channelID)
	return err
}

// Update replaces a channel.
func (s *Store) Update(ctx context.Context, id string, channel Channel) (*Channel, error) {
	existing, err := s.get(ctx, id)
	if err != nil {
		return nil, err
	}
	config, err := channel.Validate()
	if err != nil {
		return nil, err
	}
	keep, clear := false, false
	if webhook, ok := config.(WebhookConfig); ok && webhook.Secret == "" {
		var incoming WebhookConfig
		_ = json.Unmarshal(channel.Config, &incoming)
		switch {
		case incoming.SecretSet && existing.Kind == KindWebhook:
			keep = true
		case existing.Kind == KindWebhook && existing.SecretConfigured:
			clear = true
		}
	}
	if slack, ok := config.(SlackConfig); ok && slack.URL == "" {
		if existing.Kind != KindSlackWebhook || !existing.SecretConfigured {
			// A row from before the move may still carry the address in its
			// configuration; the move takes it to the store, and until then the row
			// keeps it.
			var kept SlackConfig
			_ = json.Unmarshal(existing.Config, &kept)
			if existing.Kind != KindSlackWebhook || kept.URL == "" {
				return nil, Error{Code: "invalid_config", Message: "the incoming webhook needs its address"}
			}
			slack.URL = kept.URL
			slack.URLSet = false
			config = slack
		} else {
			keep = true
		}
	}
	passwordRef, err := s.checkSecret(ctx, config)
	if err != nil {
		return nil, err
	}
	credential, stored := credentialOf(config)
	if credential != "" && s.secrets == nil {
		return nil, Error{Code: "secret_store_unavailable", Message: "this installation has no secret store to hold the credential of the channel"}
	}
	encodedConfig, err := json.Marshal(stored)
	if err != nil {
		return nil, err
	}
	encodedFilter, err := json.Marshal(channel.Filter)
	if err != nil {
		return nil, err
	}
	// The public summary of an incoming webhook whose address is kept
	// stays as it was: the address is not read back for it.
	public := publicConfigOf(channel.Kind, config, "")
	if _, ok := config.(SlackConfig); ok && keep {
		public = existing.PublicConfig
	}
	// A channel that changes kind or clears its credential drops the
	// secret it had; a mailbox points at its named password secret.
	secretRef := existing.secretRef
	if existing.Kind != channel.Kind || clear {
		secretRef = ""
	}
	if _, ok := config.(EmailConfig); ok {
		secretRef = passwordRef
	}
	_, err = s.pool.Exec(ctx, `
		update notification_channels
		   set name = $2, kind = $3, config = $4::jsonb, public_config = $5::jsonb, events = $6, filter = $7::jsonb,
		       enabled = $8, reason = $9, secret_ref = $10,
		       secret_rotated_at = case when $10::uuid is distinct from secret_ref then now() else secret_rotated_at end,
		       revision = revision + 1, updated_at = now()
		 where id = $1`,
		id, channel.Name, channel.Kind, encodedConfig, public, channel.Events, encodedFilter,
		channel.Enabled, channel.Reason, nullableID(secretRef))
	if isUniqueViolation(err) {
		return nil, Error{Code: "name_taken", Message: fmt.Sprintf("a channel named %q exists already", channel.Name)}
	}
	if err != nil {
		return nil, err
	}
	// The channel's own secret - never a mailbox's named one - is retired
	// when the credential is cleared or the kind no longer has one.
	if existing.Kind != KindEmail && existing.secretRef != "" && (existing.Kind != channel.Kind || clear) {
		if err := s.dropCredential(ctx, id); err != nil {
			return nil, err
		}
		if _, ok := config.(EmailConfig); ok && passwordRef != "" {
			if _, err := s.pool.Exec(ctx, `update notification_channels set secret_ref = $2 where id = $1`,
				id, passwordRef); err != nil {
				return nil, err
			}
		}
	}
	if credential != "" {
		if err := s.putCredential(ctx, id, credential, channel.CreatedBy); err != nil {
			return nil, err
		}
	}
	return s.Get(ctx, id)
}

// Delete removes a channel and, through the schema, its queue; the
// secret it held is retired.
func (s *Store) Delete(ctx context.Context, id string) error {
	if _, err := uuid.Parse(id); err != nil {
		return ErrNotFound
	}
	existing, err := s.get(ctx, id)
	if err != nil {
		return err
	}
	tag, err := s.pool.Exec(ctx, `delete from notification_channels where id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if existing.Kind != KindEmail && existing.secretRef != "" && s.secrets != nil {
		if err := s.secrets.Retire(ctx, ChannelSecretName(id)); err != nil && !errors.Is(err, secrets.ErrNotFound) {
			return err
		}
	}
	return nil
}

// checkSecret refuses a mail configuration whose password names a secret the
// store does not have or cannot issue, and returns the identifier of the
// secret for the channel's reference.
func (s *Store) checkSecret(ctx context.Context, config any) (string, error) {
	email, ok := config.(EmailConfig)
	if !ok || email.PasswordSecret == "" {
		return "", nil
	}
	var id string
	var retired *time.Time
	var version int
	err := s.pool.QueryRow(ctx, `select id, retired_at, current_version from secrets where name = $1`,
		email.PasswordSecret).Scan(&id, &retired, &version)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", Error{Code: "secret_not_found", Message: fmt.Sprintf("there is no secret named %q in the store", email.PasswordSecret)}
	}
	if err != nil {
		return "", err
	}
	if retired != nil || version == 0 {
		return "", Error{Code: "secret_retired", Message: fmt.Sprintf("the secret %q cannot be issued any more", email.PasswordSecret)}
	}
	return id, nil
}

func nullableID(id string) any {
	if id == "" {
		return nil
	}
	return id
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// SecretMigrationName is the name the one-off move of the credentials
// is recorded under.
const SecretMigrationName = "channel_secrets_to_store"

// MigrateSecrets moves the credentials the previous release wrote in plain
// into the secret store: webhook addresses, signing keys and mail passwords.
func (s *Store) MigrateSecrets(ctx context.Context) (moved int, err error) {
	if s.secrets == nil {
		return 0, errors.New("the credentials of the channels cannot be moved without a secret store")
	}
	rows, err := s.pool.Query(ctx, `
		select id, kind, config, created_by from notification_channels
		 where (kind = $1 and config ? 'url')
		    or (kind = $2 and config ? 'secret')
		    or (kind = $3 and secret_ref is null and coalesce(config->>'password_secret', '') <> '')
		 order by created_at`, KindSlackWebhook, KindWebhook, KindEmail)
	if err != nil {
		return 0, err
	}
	type pending struct {
		id, kind, author string
		config           []byte
	}
	var work []pending
	for rows.Next() {
		var p pending
		if err := rows.Scan(&p.id, &p.kind, &p.config, &p.author); err != nil {
			rows.Close()
			return 0, err
		}
		work = append(work, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for _, p := range work {
		switch p.kind {
		case KindSlackWebhook:
			var config SlackConfig
			if err := json.Unmarshal(p.config, &config); err != nil {
				return moved, fmt.Errorf("channel %s: %w", p.id, err)
			}
			if config.URL != "" {
				if err := s.putCredential(ctx, p.id, config.URL, p.author); err != nil {
					return moved, fmt.Errorf("channel %s: %w", p.id, err)
				}
			}
			public := publicConfigOf(p.kind, config, config.URL)
			config.URL, config.URLSet = "", false
			encoded, _ := json.Marshal(config)
			if _, err := s.pool.Exec(ctx, `
				update notification_channels set config = $2::jsonb, public_config = $3::jsonb where id = $1`,
				p.id, encoded, public); err != nil {
				return moved, err
			}
		case KindWebhook:
			var config WebhookConfig
			if err := json.Unmarshal(p.config, &config); err != nil {
				return moved, fmt.Errorf("channel %s: %w", p.id, err)
			}
			if config.Secret != "" {
				if err := s.putCredential(ctx, p.id, config.Secret, p.author); err != nil {
					return moved, fmt.Errorf("channel %s: %w", p.id, err)
				}
			}
			signed := config.Secret != ""
			config.Secret, config.SecretSet = "", false
			encoded, _ := json.Marshal(config)
			public := publicConfigOf(p.kind, WebhookConfig{URL: config.URL, SecretSet: signed}, "")
			if _, err := s.pool.Exec(ctx, `
				update notification_channels set config = $2::jsonb, public_config = $3::jsonb where id = $1`,
				p.id, encoded, public); err != nil {
				return moved, err
			}
		case KindEmail:
			var config EmailConfig
			if err := json.Unmarshal(p.config, &config); err != nil {
				return moved, fmt.Errorf("channel %s: %w", p.id, err)
			}
			// A mailbox whose named secret is gone keeps sending without a login
			// failing, as it did; the reference is left empty and the log says
			// secret_unavailable.
			var secretID *string
			_ = s.pool.QueryRow(ctx, `select id from secrets where name = $1`, config.PasswordSecret).Scan(&secretID)
			if _, err := s.pool.Exec(ctx, `
				update notification_channels
				   set secret_ref = $2, secret_rotated_at = coalesce(secret_rotated_at, updated_at),
				       public_config = $3::jsonb
				 where id = $1`, p.id, secretID, publicConfigOf(p.kind, config, "")); err != nil {
				return moved, err
			}
		}
		moved++
	}
	_, err = s.pool.Exec(ctx, `
		insert into notification_backfills (name, completed_at, channels) values ($1, now(), $2)
		on conflict (name) do update set completed_at = now(), channels = notification_backfills.channels + $2`,
		SecretMigrationName, moved)
	return moved, err
}

// Enqueue writes the rows of a batch of events in one transaction: every
// channel's row for every event, pending or suppressed, all or none.
func (s *Store) Enqueue(ctx context.Context, rows []Delivery) error {
	if len(rows) == 0 {
		return nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, row := range rows {
		var eventID *int64
		if row.EventID > 0 {
			eventID = &row.EventID
		}
		if _, err := tx.Exec(ctx, `
			insert into notification_deliveries
			    (channel_id, event_id, event_type, aggregate_id, message, channel_revision, state,
			     next_attempt_at, policy_id, suppression_reason, last_error)
			values ($1, $2, $3, $4, $5::jsonb, $6, $7, now(), $8, $9, $10)
			on conflict (event_id, channel_id) do nothing`,
			row.ChannelID, eventID, row.EventType, row.aggregateID, row.message, row.channelRevision,
			row.State, nullableID(row.PolicyID), row.SuppressionReason, row.LastError); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// Claim takes up to limit due rows under a lease of the owner: the due rows in
// order, locked and skipped when another worker holds them, the attempt raised.
func (s *Store) Claim(ctx context.Context, owner string, lease time.Duration, limit int) ([]Delivery, error) {
	rows, err := s.pool.Query(ctx, `
		with picked as (
		    select id from notification_deliveries
		     where state in ('pending', 'retry_wait') and next_attempt_at <= now()
		     order by next_attempt_at, id
		       for update skip locked
		     limit $3
		)
		update notification_deliveries d
		   set state = 'leased', lease_owner = $1, lease_until = now() + make_interval(secs => $2),
		       attempt = attempt + 1, updated_at = now()
		  from picked p
		 where d.id = p.id
		returning d.id, d.channel_id, coalesce(d.event_id, 0), d.event_type, d.aggregate_id, d.message,
		          d.channel_revision, d.state, d.attempt, d.next_attempt_at, d.lease_until,
		          d.last_error_code, d.last_error, d.created_at, d.updated_at`,
		owner, lease.Seconds(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var claimed []Delivery
	for rows.Next() {
		var d Delivery
		if err := rows.Scan(&d.ID, &d.ChannelID, &d.EventID, &d.EventType, &d.aggregateID, &d.message,
			&d.channelRevision, &d.State, &d.Attempt, &d.NextAttemptAt, &d.LeaseUntil,
			&d.LastErrorCode, &d.LastError, &d.CreatedAt, &d.UpdatedAt); err != nil {
			return nil, err
		}
		d.LeaseOwner = owner
		claimed = append(claimed, d)
	}
	return claimed, rows.Err()
}

// Renew extends the lease of a row the owner holds.
func (s *Store) Renew(ctx context.Context, id, owner string, lease time.Duration) (bool, error) {
	tag, err := s.pool.Exec(ctx, `
		update notification_deliveries
		   set lease_until = now() + make_interval(secs => $3), updated_at = now()
		 where id = $1 and lease_owner = $2 and state = 'leased'`, id, owner, lease.Seconds())
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// ReclaimStale returns the rows whose lease ran out to the queue: the worker
// that held them died, or hung past its lease.
func (s *Store) ReclaimStale(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		update notification_deliveries
		   set state = 'retry_wait', lease_owner = null, lease_until = null,
		       next_attempt_at = now(), updated_at = now()
		 where state = 'leased' and lease_until < now()`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// Outcome is what the worker settles a leased row with.
type Outcome struct {
	State     string
	ErrorCode string
	Error     string
	// NextAttempt is the pause before the next attempt of a retry.
	NextAttempt time.Duration
}

// Settle writes the outcome of an attempt on a row the owner holds.
func (s *Store) Settle(ctx context.Context, id, owner string, outcome Outcome) error {
	var err error
	switch outcome.State {
	case StateDelivered:
		_, err = s.pool.Exec(ctx, `
			update notification_deliveries
			   set state = 'delivered', delivered_at = now(), lease_owner = null, lease_until = null,
			       last_error_code = '', last_error = '', updated_at = now()
			 where id = $1 and lease_owner = $2 and state = 'leased'`, id, owner)
	case StateRetryWait:
		_, err = s.pool.Exec(ctx, `
			update notification_deliveries
			   set state = 'retry_wait', next_attempt_at = now() + make_interval(secs => $3),
			       lease_owner = null, lease_until = null,
			       last_error_code = $4, last_error = $5, updated_at = now()
			 where id = $1 and lease_owner = $2 and state = 'leased'`,
			id, owner, outcome.NextAttempt.Seconds(), outcome.ErrorCode, outcome.Error)
	case StateDeadLetter:
		_, err = s.pool.Exec(ctx, `
			update notification_deliveries
			   set state = 'dead_letter', lease_owner = null, lease_until = null,
			       last_error_code = $3, last_error = $4, updated_at = now()
			 where id = $1 and lease_owner = $2 and state = 'leased'`,
			id, owner, outcome.ErrorCode, outcome.Error)
	default:
		return fmt.Errorf("a row cannot be settled as %q", outcome.State)
	}
	return err
}

// Retry returns a dead letter to the queue: an operator corrected the channel
// and wants the message sent.
func (s *Store) Retry(ctx context.Context, id string) (*Delivery, error) {
	if _, err := uuid.Parse(id); err != nil {
		return nil, ErrDeliveryNotFound
	}
	tag, err := s.pool.Exec(ctx, `
		update notification_deliveries
		   set state = 'pending', attempt = 0, next_attempt_at = now(), updated_at = now()
		 where id = $1 and state = 'dead_letter'`, id)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		delivery, err := s.Delivery(ctx, id)
		if err != nil {
			return nil, err
		}
		return nil, Error{Code: "delivery_not_dead", Message: fmt.Sprintf("the delivery is %s; only a dead letter can be retried", delivery.State)}
	}
	return s.Delivery(ctx, id)
}

// Delivery reads one row of the queue.
func (s *Store) Delivery(ctx context.Context, id string) (*Delivery, error) {
	if _, err := uuid.Parse(id); err != nil {
		return nil, ErrDeliveryNotFound
	}
	deliveries, err := s.queryDeliveries(ctx, "where d.id = $1", []any{id}, 1)
	if err != nil {
		return nil, err
	}
	if len(deliveries) == 0 {
		return nil, ErrDeliveryNotFound
	}
	return &deliveries[0], nil
}

// Record writes a settled row that names no event: the test message the
// operator pressed the button for, sent once and settled at once.
func (s *Store) Record(ctx context.Context, delivery Delivery) error {
	var delivered *time.Time
	if delivery.State == StateDelivered {
		now := time.Now().UTC()
		delivered = &now
	}
	return s.pool.QueryRow(ctx, `
		insert into notification_deliveries
		    (channel_id, event_id, event_type, message, state, attempt, last_error_code, last_error, delivered_at)
		values ($1, null, $2, $3::jsonb, $4, $5, $6, $7, $8)
		returning id, created_at, updated_at`,
		delivery.ChannelID, delivery.EventType, delivery.message, delivery.State, delivery.Attempt,
		delivery.LastErrorCode, delivery.LastError, delivered).
		Scan(&delivery.ID, &delivery.CreatedAt, &delivery.UpdatedAt)
}

// DeliveryFilter narrows the queue.
type DeliveryFilter struct {
	ChannelID string
	State     string
	// Status is the previous release's word: sent or failed.
	Status string
	Since  time.Time
	Limit  int
}

// MaxDeliveries bounds one page of the queue.
const MaxDeliveries = 500

// Deliveries reads the queue, newest first.
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
	if filter.State != "" {
		args = append(args, filter.State)
		conditions = append(conditions, fmt.Sprintf("d.state = $%d", len(args)))
	}
	switch filter.Status {
	case StatusSent:
		conditions = append(conditions, "d.state = 'delivered'")
	case StatusFailed:
		conditions = append(conditions, "d.state in ('dead_letter', 'retry_wait')")
	}
	if !filter.Since.IsZero() {
		args = append(args, filter.Since)
		conditions = append(conditions, fmt.Sprintf("d.updated_at >= $%d", len(args)))
	}
	where := ""
	if len(conditions) > 0 {
		where = "where " + strings.Join(conditions, " and ")
	}
	limit := filter.Limit
	if limit <= 0 || limit > MaxDeliveries {
		limit = 100
	}
	return s.queryDeliveries(ctx, where, args, limit)
}

func (s *Store) queryDeliveries(ctx context.Context, where string, args []any, limit int) ([]Delivery, error) {
	args = append(args, limit)
	rows, err := s.pool.Query(ctx, `
		select d.id, d.channel_id, c.name, coalesce(d.event_id, 0), d.event_type,
		       coalesce(d.message->>'title', ''), d.state, d.attempt, d.next_attempt_at,
		       coalesce(d.lease_owner::text, ''), d.lease_until, d.last_error_code, d.last_error,
		       coalesce(d.policy_id::text, ''), d.suppression_reason, d.delivered_at,
		       d.created_at, d.updated_at
		  from notification_deliveries d join notification_channels c on c.id = d.channel_id
		`+where+`
		 order by d.updated_at desc, d.id desc
		 limit $`+fmt.Sprint(len(args)), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	deliveries := []Delivery{}
	for rows.Next() {
		var d Delivery
		if err := rows.Scan(&d.ID, &d.ChannelID, &d.ChannelName, &d.EventID, &d.EventType, &d.Title,
			&d.State, &d.Attempt, &d.NextAttemptAt, &d.LeaseOwner, &d.LeaseUntil,
			&d.LastErrorCode, &d.LastError, &d.PolicyID, &d.SuppressionReason, &d.DeliveredAt,
			&d.CreatedAt, &d.UpdatedAt); err != nil {
			return nil, err
		}
		d.Status = legacyStatus(d.State)
		d.ErrorCode = d.LastErrorCode
		d.Error = d.LastError
		d.SentAt = d.UpdatedAt
		deliveries = append(deliveries, d)
	}
	return deliveries, rows.Err()
}

func (s *Store) lastDelivery(ctx context.Context, channelID string) (*DeliverySummary, error) {
	deliveries, err := s.Deliveries(ctx, DeliveryFilter{ChannelID: channelID, Limit: 1})
	if err != nil {
		return nil, err
	}
	if len(deliveries) == 0 {
		return nil, nil
	}
	return deliveries[0].Summary(), nil
}

// DeadLetterCount counts the rows that wait for an operator.
func (s *Store) DeadLetterCount(ctx context.Context) (int, error) {
	var count int
	err := s.pool.QueryRow(ctx, `select count(*) from notification_deliveries where state = 'dead_letter'`).Scan(&count)
	return count, err
}

// SweepDeliveries deletes the settled rows older than the retention.
func (s *Store) SweepDeliveries(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `
		delete from notification_deliveries
		 where state in ('delivered', 'suppressed')
		   and updated_at < now() - make_interval(secs => $1)`, DeliveryRetention.Seconds())
	if err != nil {
		return fmt.Errorf("sweeping the notification queue: %w", err)
	}
	return nil
}

// SummaryWork is one summary to send: the silence that ended and the
// rows of one channel it kept back.
type SummaryWork struct {
	SilenceID string
	Until     time.Time
	Reason    string
	ChannelID string
	// ChannelRevision is the newest revision among the kept rows.
	ChannelRevision int64
	Titles          []string
}

// EndedSilences reads the silences with send_summary that ended and have
// suppressed rows nobody summarized, with the titles those rows kept, one
// entry per silence and channel.
func (s *Store) EndedSilences(ctx context.Context) ([]SummaryWork, error) {
	rows, err := s.pool.Query(ctx, `
		select s.id, s.until, s.reason, d.channel_id, max(d.channel_revision),
		       array_agg(coalesce(d.message->>'title', d.event_type) order by d.created_at)
		  from silences s join notification_deliveries d on d.policy_id = s.id
		 where s.send_summary
		   and (s.until <= now() or s.expired_at is not null)
		   and d.state = 'suppressed' and not d.summarized
		 group by s.id, s.until, s.reason, d.channel_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var work []SummaryWork
	for rows.Next() {
		var item SummaryWork
		if err := rows.Scan(&item.SilenceID, &item.Until, &item.Reason, &item.ChannelID,
			&item.ChannelRevision, &item.Titles); err != nil {
			return nil, err
		}
		work = append(work, item)
	}
	return work, rows.Err()
}

// EnqueueSummary writes the summary row of one channel for one ended silence
// and marks the rows it names as summarized, together: the summary goes once
// or not at all.
func (s *Store) EnqueueSummary(ctx context.Context, work SummaryWork, message Message) error {
	encoded, err := json.Marshal(message)
	if err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// The rows are marked first and the summary written only for the rows this
	// transaction marked: a second worker that read the same silence marks none.
	marked, err := tx.Exec(ctx, `
		update notification_deliveries set summarized = true, updated_at = now()
		 where policy_id = $1 and channel_id = $2 and state = 'suppressed' and not summarized`,
		work.SilenceID, work.ChannelID)
	if err != nil {
		return err
	}
	if marked.RowsAffected() == 0 {
		return nil
	}
	// The silence is both what the summary is about and the policy that kept the
	// rows back, and those two columns are of different types.
	if _, err := tx.Exec(ctx, `
		insert into notification_deliveries
		    (channel_id, event_id, event_type, aggregate_id, message, channel_revision, state, policy_id)
		values ($1::uuid, null, $2, $3::text, $4::jsonb, $5, 'pending', $3::uuid)`,
		work.ChannelID, message.EventType, work.SilenceID, encoded, work.ChannelRevision); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
