-- The notification queue.
--
-- A channel is part of the security machinery: it is how the fleet says
-- that something happened when nobody is looking at the panel. Two
-- things about it were not good enough. The credential of a channel - the
-- address of an incoming webhook, the key a webhook is signed with - lay
-- in the configuration column in plain text, so a copy of the table gave
-- away a way to post into the on-call room. And the router tried a
-- receiver three times in memory and moved on, so a receiver that was
-- down for a minute turned an alert into a row that said "failed" and
-- nothing else ever sent it.
--
-- From now on the credential of a channel is a version of the secret
-- store, referenced by secret_ref, and the delivery log is a queue: one
-- row per event and channel, claimed by a worker under a lease, retried
-- with a growing pause, and parked as a dead letter when the attempts
-- run out or the receiver refuses for good - never forgotten. A restart
-- of the panel resumes from the rows.

-- The channels: the public part of the configuration, the reference to
-- the credential, a revision the reads can be compared by. The config
-- column stays for the fields that are not secret (the address of a
-- signed webhook, the mail relay, the recipients) and for the panel of
-- the previous release, which reads it; the plaintext credentials are
-- moved out of it at the first start of the new release, in Go, because
-- only the process holds the key that seals a secret version. Until that
-- start ran, a channel of the previous release still sends: the senders
-- read the reference first and the column second.
alter table notification_channels
    add column if not exists public_config     jsonb       not null default '{}'::jsonb,
    add column if not exists secret_ref        uuid        references secrets (id),
    add column if not exists secret_rotated_at timestamptz,
    add column if not exists revision          bigint      not null default 1;

comment on column notification_channels.public_config is
    'What the API shows of the address: the host of an incoming webhook, the relay of a mailbox. Never a credential.';
comment on column notification_channels.secret_ref is
    'The secret of the store that holds the credential of the channel: the incoming webhook address, the signing key, the mail password.';
comment on column notification_channels.secret_rotated_at is
    'When the credential was last set or replaced; what the API shows as secret_last_rotated_at.';
comment on column notification_channels.revision is
    'Raised on every write of the channel; a delivery names the revision it was sent under.';

create index if not exists notification_channels_secret_ref_idx
    on notification_channels (secret_ref) where secret_ref is not null;

-- The one-off move of the plaintext credentials into the secret store is
-- recorded here by name, with what it moved, so the start of the panel
-- knows it ran and an operator reading the database knows when. The
-- move is idempotent - it looks for plaintext and finds none the second
-- time - but the record says the upgrade is complete.
create table if not exists notification_backfills (
    name         text        primary key,
    completed_at timestamptz not null default now(),
    channels     integer     not null default 0
);

comment on table notification_backfills is
    'The one-off conversions of the notification tables that had to run in the panel process, by name, with when they completed.';

-- The delivery log becomes the queue. The previous table kept one row per
-- attempt; the queue keeps one row per event and channel and counts the
-- attempts on it. The old rows are carried over as their last attempt -
-- a sent one as delivered, a failed one as a dead letter with the code it
-- failed with - so the month of history the screen shows does not vanish
-- with the upgrade. A test message, which names no event, is carried
-- over the same way; the uniqueness of (event_id, channel_id) leaves the
-- rows without an event alone, as the standard says of nulls.
alter table if exists notification_deliveries rename to notification_deliveries_attempts;
alter index if exists notification_deliveries_channel_idx rename to notification_deliveries_attempts_channel_idx;
alter index if exists notification_deliveries_sent_idx rename to notification_deliveries_attempts_sent_idx;

create table if not exists notification_deliveries (
    id              uuid        primary key default gen_random_uuid(),
    channel_id      uuid        not null references notification_channels (id) on delete cascade,
    -- event_id is the row of the trail the message reports; null for a
    -- test message and for a summary after a silence.
    event_id        bigint,
    event_type      text        not null,
    -- aggregate_id is what the event is about - the alert, the campaign,
    -- the host - so the resolve of an alert can find how its fire went.
    aggregate_id    text        not null default '',
    -- message is the composed message, kept with the row: the trail is
    -- swept after its retention and a delivery that waited for a receiver
    -- longer than that still has its words; and every attempt sends the
    -- same message, not one recomposed from a changed host.
    message         jsonb       not null default '{}'::jsonb,
    -- channel_revision is the revision of the channel the row was queued
    -- under, for reading the log against the channel's history.
    channel_revision bigint     not null default 1,
    state           text        not null check (state in
                        ('pending', 'leased', 'delivered', 'retry_wait', 'dead_letter', 'suppressed')),
    attempt         integer     not null default 0 check (attempt >= 0),
    next_attempt_at timestamptz not null default now(),
    lease_owner     uuid,
    lease_until     timestamptz,
    last_error_code text        not null default '',
    -- last_error is the sentence of the last failure, for the operator;
    -- the senders keep the address out of it.
    last_error      text        not null default '',
    -- policy_id names the silence that suppressed the row; null for a
    -- maintenance window, which is a fact of the host and not a policy.
    policy_id       uuid,
    -- suppression_reason is the typed reason of a suppressed row:
    -- silence, maintenance_window, fired_suppressed.
    suppression_reason text     not null default '',
    -- summarized says a suppressed row was folded into the summary sent
    -- when its silence ended, so the summary goes once.
    summarized      boolean     not null default false,
    delivered_at    timestamptz,
    created_at      timestamptz not null default now(),
    updated_at      timestamptz not null default now(),
    unique (event_id, channel_id)
);

comment on table notification_deliveries is
    'The notification queue: one row per event and channel, claimed under a lease, retried with a growing pause, parked as a dead letter when the attempts run out. Never forgotten.';
comment on column notification_deliveries.state is
    'pending: waits for a worker; leased: a worker sends it; delivered; retry_wait: the receiver failed in a way that passes; dead_letter: given up, an operator can retry; suppressed: a silence or a maintenance window kept it.';
comment on column notification_deliveries.last_error_code is
    'The typed reason of the last failure: the transport code while it retries, the classification when it is a dead letter (channel_credentials_rejected, permanent_http_error, delivery_attempts_exhausted).';

-- The claim reads the due rows in the order they are due; the screens
-- read a channel's rows newest first and count the dead letters; the
-- sweep reads by age.
create index if not exists notification_deliveries_due_idx
    on notification_deliveries (next_attempt_at, id)
    where state in ('pending', 'retry_wait');
create index if not exists notification_deliveries_leased_idx
    on notification_deliveries (lease_until)
    where state = 'leased';
create index if not exists notification_deliveries_channel_idx
    on notification_deliveries (channel_id, created_at desc);
create index if not exists notification_deliveries_dead_idx
    on notification_deliveries (created_at desc)
    where state = 'dead_letter';
create index if not exists notification_deliveries_suppressed_idx
    on notification_deliveries (policy_id)
    where state = 'suppressed' and not summarized;
create index if not exists notification_deliveries_created_idx
    on notification_deliveries (created_at);

insert into notification_deliveries
    (channel_id, event_id, event_type, state, attempt, next_attempt_at,
     last_error_code, last_error, delivered_at, created_at, updated_at)
select distinct on (a.channel_id, a.event_id)
       a.channel_id, a.event_id, a.event_type,
       case a.status when 'sent' then 'delivered' else 'dead_letter' end,
       a.attempt, a.sent_at, a.error_code, a.error,
       case a.status when 'sent' then a.sent_at end,
       a.sent_at, a.sent_at
  from notification_deliveries_attempts a
 where a.event_id is not null
 order by a.channel_id, a.event_id, a.sent_at desc, a.id desc
on conflict (event_id, channel_id) do nothing;

insert into notification_deliveries
    (channel_id, event_id, event_type, state, attempt, next_attempt_at,
     last_error_code, last_error, delivered_at, created_at, updated_at)
select a.channel_id, null, a.event_type,
       case a.status when 'sent' then 'delivered' else 'dead_letter' end,
       a.attempt, a.sent_at, a.error_code, a.error,
       case a.status when 'sent' then a.sent_at end,
       a.sent_at, a.sent_at
  from notification_deliveries_attempts a
 where a.event_id is null;

drop table if exists notification_deliveries_attempts;

-- The silences gain two decisions of the policy. send_summary asks for one
-- message per channel when the silence ends, naming what it kept back,
-- instead of the flood of everything that happened meanwhile - which is
-- never sent. global marks a silence that may keep back the security
-- alerts of the whole installation; a silence bound to a host or a rule
-- never does, whoever wrote it, because a silence of one host is not a
-- permission to blind the installation. Writing a global silence needs
-- the global notification.manage permission.
alter table silences
    add column if not exists send_summary boolean not null default false,
    add column if not exists global       boolean not null default false;

comment on column silences.send_summary is
    'When the silence ends, one summary per channel of what it kept back is sent; the kept-back messages themselves never are.';
comment on column silences.global is
    'A silence that may keep back security alerts; needs the global notification.manage permission to write. A scoped silence never keeps them back.';

-- The evaluator keeps, on every open episode, the time of the sample that
-- last confirmed its condition. A gap in the samples longer than two
-- intervals restarts the "for" window: an alert fires only after the
-- condition held continuously, with data present, for the whole window -
-- never on the strength of a sample from before the gap. The rows from
-- before this column read as confirmed at their start.
alter table alerts
    add column if not exists confirmed_at timestamptz;

update alerts set confirmed_at = started_at where confirmed_at is null;

comment on column alerts.confirmed_at is
    'The time of the newest sample that confirmed the condition of an open episode; a gap longer than two sampling intervals restarts the for window.';
