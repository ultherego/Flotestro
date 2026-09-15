-- The delivery log of the notification channels.
--
-- One row per attempt: a channel that is down shows as a run of failed
-- rows with the receiver's answer on each, and a message that went out on
-- the third try shows the two before it. A test message from the panel is
-- a row without an event. The log is diagnostic, not evidence - the
-- audit trail keeps who changed a channel - so it is swept after a month
-- like the agent sessions.
create table if not exists notification_deliveries (
    id          bigserial   primary key,
    channel_id  uuid        not null references notification_channels (id) on delete cascade,
    -- event_id is the row of the trail the message reports; null for a
    -- test message.
    event_id    bigint,
    event_type  text        not null,
    attempt     integer     not null check (attempt > 0),
    status      text        not null check (status in ('sent', 'failed')),
    error_code  text        not null default '',
    error       text        not null default '',
    sent_at     timestamptz not null default now()
);

comment on table notification_deliveries is
    'Every attempt of every channel: what went out, what did not and why. Swept after a month.';
comment on column notification_deliveries.error_code is
    'The typed reason of a failure - connection_refused, dns_failure, receiver_status, smtp_auth_failed - empty for a sent message.';

create index if not exists notification_deliveries_channel_idx
    on notification_deliveries (channel_id, sent_at desc);
create index if not exists notification_deliveries_sent_idx
    on notification_deliveries (sent_at);
